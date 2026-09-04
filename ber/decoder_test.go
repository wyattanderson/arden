package ber_test

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

type decoderInt int64

func (v *decoderInt) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := d.Integer[decoderInt]()
	if err := d.Err(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

type decoderText string

func TestDecoderNamedOctetsSurviveInputReuse(t *testing.T) {
	encoded := ber.Sequence().Add(ber.OctetString("text"), ber.OctetString([]byte{0, 0xff})).BERPacket().Encode()
	r, err := ber.NewReader(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	d := ber.NewDecoder(r).Sequence()
	text := d.OctetString[decoderText]()
	raw := d.OctetString[decoderRaw]()
	require.NoError(t, d.End())
	clear(encoded)
	assert.Equal(t, decoderText("text"), text)
	assert.Equal(t, decoderRaw{0, 0xff}, raw)
}

func (v *decoderText) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := d.OctetString[decoderText]()
	if err := d.Err(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

type decoderRaw []byte

func (v *decoderRaw) UnmarshalBER(r *ber.Reader) error {
	e, err := r.SkipElement()
	if err != nil {
		return err
	}
	*v = decoderRaw(e.Clone())
	return nil
}

var decoderOptionalID = ber.Identifier{Class: ber.ClassContextSpecific, Number: 3}

// This external type demonstrates the public tagged and embedding contracts
// without access to any private BER implementation.
type decoderRecord struct {
	Number int64
	Flag   bool
	Tail   []decoderRaw
}

func (v *decoderRecord) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.SequenceIdentifier).UnmarshalBER(r)
}

func (v *decoderRecord) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		d := ber.NewDecoder(r).Constructed(id)
		decoded := d.Embed[decoderRecord]()
		decoded.Tail = d.Extensions[decoderRaw]()
		if err := d.End(); err != nil {
			return err
		}
		*v = decoded
		return nil
	})
}

func (v *decoderRecord) UnmarshalBERFields(d *ber.Decoder) error {
	d.Reserve(decoderOptionalID)
	decoded := decoderRecord{Number: d.Integer[int64]()}
	if d.NextIs(decoderOptionalID) {
		decoded.Flag = d.BooleanAs(decoderOptionalID)
	}
	if err := d.Err(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

func decoderFor(t *testing.T, encoded []byte) (*ber.Decoder, *ber.Reader) {
	t.Helper()
	r, err := ber.NewReader(encoded, limits())
	require.NoError(t, err)
	return ber.NewDecoder(r), r
}

func TestDecoderTypedReadsAndCollections(t *testing.T) {
	encoded := ber.Sequence().Add(ber.Integer(7), ber.Integer(-3)).BERPacket().Encode()
	d, r := decoderFor(t, ber.Integer(99).AppendTo(encoded))
	assert.Equal(t, []decoderInt{7, -3}, d.Sequence().All[decoderInt]())
	require.NoError(t, d.Err()) // Do not require EOF in the parent.
	assert.Equal(t, decoderInt(99), d.Read[decoderInt]())
	require.NoError(t, d.End())
	assert.True(t, r.Empty())
}

func TestDecoderTaggedReadsAndReceiverAtomicity(t *testing.T) {
	id := ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 5}
	encoded := ber.Constructed(id).Add(ber.Integer(42)).BERPacket().Encode()
	d, _ := decoderFor(t, encoded)
	assert.Equal(t, decoderRecord{Number: 42}, d.ReadAs[decoderRecord](id))
	require.NoError(t, d.End())

	d, _ = decoderFor(t, encoded)
	assert.Zero(t, d.Read[decoderRecord]())
	require.ErrorIs(t, d.Err(), ber.ErrUnexpectedIdentifier)

	for _, wrong := range []ber.Identifier{
		{Class: ber.ClassContextSpecific, Constructed: true, Number: 5},
		{Class: ber.ClassApplication, Number: 5},
		{Class: ber.ClassApplication, Constructed: true, Number: 6},
	} {
		d, _ = decoderFor(t, encoded)
		assert.Zero(t, d.ReadAs[decoderRecord](wrong))
		require.Error(t, d.Err())
	}

	malformed := ber.Constructed(id).Add(ber.OctetString("not an integer")).BERPacket().Encode()
	_, r := decoderFor(t, malformed)
	prior := decoderRecord{Number: 100, Flag: true}
	require.Error(t, prior.UnmarshalAs(id).UnmarshalBER(r))
	assert.Equal(t, decoderRecord{Number: 100, Flag: true}, prior)
}

func TestDecoderEmbeddingTransfersOnlyKnownFieldsAndReservations(t *testing.T) {
	unknown := ber.Primitive(ber.Identifier{Class: ber.ClassContextSpecific, Number: 8}, []byte{0xff})
	flag := ber.Primitive(decoderOptionalID, []byte{0xff})
	encoded := ber.Sequence().Add(ber.Integer(42), flag, ber.OctetString("outer"), unknown).BERPacket().Encode()
	d, _ := decoderFor(t, encoded)
	scope := d.Sequence()
	assert.Equal(t, decoderRecord{Number: 42, Flag: true}, scope.Embed[decoderRecord]())
	assert.Equal(t, decoderText("outer"), scope.Read[decoderText]())
	tail := scope.Extensions[decoderRaw]()
	require.NoError(t, d.End())
	require.Len(t, tail, 1)
	assert.Equal(t, decoderRaw(unknown.Encode()), tail[0])

	// A duplicate known field must not hide behind an unknown extension, even
	// when that optional field was absent from the embedded component.
	for _, prefix := range [][]ber.Packet{{ber.Integer(42)}, {ber.Integer(42), flag}} {
		encoded = ber.Sequence().Add(prefix...).Add(ber.OctetString("outer"), unknown, flag).BERPacket().Encode()
		d, _ = decoderFor(t, encoded)
		scope = d.Sequence()
		scope.Embed[decoderRecord]()
		scope.Read[decoderText]()
		assert.Nil(t, scope.Extensions[decoderRaw]())
		require.ErrorIs(t, d.End(), ber.ErrUnexpectedIdentifier)
	}

	// An enclosing scope's reservations must not reject a nested scope's
	// extension fields with the same identifier.
	d, _ = decoderFor(t, ber.Sequence().Add(ber.Sequence().Add(flag)).BERPacket().Encode())
	scope = d.Sequence()
	scope.Reserve(decoderOptionalID)
	assert.Len(t, scope.Sequence().Extensions[decoderRaw](), 1)
	require.NoError(t, d.End())
}

func TestDecoderFirstErrorStopsReadsAndCallbacks(t *testing.T) {
	encoded := ber.Sequence().Add(ber.Primitive(ber.BooleanIdentifier, []byte{1}), ber.Integer(7)).BERPacket().Encode()
	d, r := decoderFor(t, encoded)
	scope := d.Sequence()
	assert.False(t, scope.Boolean())
	first := scope.Err()
	require.ErrorIs(t, first, ber.ErrInvalidBoolean)
	offset := r.Offset()
	called := false
	decode := func(*ber.Reader) (int, error) {
		called = true
		return 1, nil
	}
	assert.Zero(t, scope.Using(decode))
	assert.Nil(t, scope.AllUsing(decode))
	assert.Zero(t, scope.Read[decoderInt]())
	assert.Zero(t, scope.ReadAs[decoderRecord](ber.SequenceIdentifier))
	assert.Zero(t, scope.Embed[decoderRecord]())
	assert.Nil(t, scope.Extensions[decoderRaw]())
	assert.Zero(t, scope.Sequence().Integer[int64]())
	assert.False(t, scope.More())
	assert.False(t, called)
	scope.Fail(errors.New("must not replace first error"))
	assert.Same(t, first, scope.End())
	assert.Same(t, first, d.End())
	assert.Equal(t, offset, r.Offset())
	var at *ber.DecodeError
	require.ErrorAs(t, first, &at)
	assert.Equal(t, 2, at.Offset)
}

func TestDecoderScopesRejectUnreadChildren(t *testing.T) {
	for _, finish := range []func(*ber.Decoder) error{
		(*ber.Decoder).Err,
		(*ber.Decoder).End,
		func(d *ber.Decoder) error { d.Integer[int64](); return d.Err() },
	} {
		encoded := ber.Sequence().Add(ber.Integer(1)).BERPacket().Encode()
		d, _ := decoderFor(t, ber.Integer(2).AppendTo(encoded))
		d.Sequence() // Deliberately fail to consume the child.
		require.ErrorIs(t, finish(d), ber.ErrTrailingData)
	}

	d, _ := decoderFor(t, ber.Integer(1).Encode())
	child := d.Sequence()
	require.NotNil(t, child)
	assert.Zero(t, child.Integer[int64]())
	require.Error(t, d.End())
}

type decoderNoProgress struct{}

func (*decoderNoProgress) UnmarshalBER(*ber.Reader) error { return nil }

type decoderGreedy struct{}

func (*decoderGreedy) UnmarshalBER(r *ber.Reader) error {
	if _, err := r.Integer(); err != nil {
		return err
	}
	_, err := r.Integer()
	return err
}

func TestDecoderCustomReadsAreBoundedAndMustProgress(t *testing.T) {
	encoded := ber.Integer(2).AppendTo(ber.Integer(1).Encode())
	d, _ := decoderFor(t, encoded)
	d.Read[decoderNoProgress]()
	require.ErrorIs(t, d.Err(), ber.ErrNoProgress)

	d, r := decoderFor(t, encoded)
	d.Read[decoderGreedy]()
	require.ErrorIs(t, d.Err(), ber.ErrTruncated)
	assert.Equal(t, len(ber.Integer(1).Encode()), r.Offset())

	d, _ = decoderFor(t, encoded)
	assert.Nil(t, d.AllUsing(func(*ber.Reader) (int, error) { return 0, nil }))
	require.ErrorIs(t, d.Err(), ber.ErrNoProgress)
}

func TestDecoderOptionalLookahead(t *testing.T) {
	d, _ := decoderFor(t, nil)
	assert.False(t, d.NextIs(ber.IntegerIdentifier))
	require.NoError(t, d.End())
	assert.Nil(t, d.All[decoderInt]())

	d, _ = decoderFor(t, []byte{0x1f})
	assert.False(t, d.NextIs(ber.IntegerIdentifier))
	require.ErrorIs(t, d.Err(), ber.ErrTruncated)
}

func TestDecoderNullAndImplicitPrimitives(t *testing.T) {
	d, _ := decoderFor(t, ber.Null().Encode())
	d.Null()
	require.NoError(t, d.End())

	id := ber.Identifier{Class: ber.ClassApplication, Number: 2}
	d, _ = decoderFor(t, ber.Primitive(id, nil).Encode())
	d.NullAs(id)
	require.NoError(t, d.End())

	d, _ = decoderFor(t, ber.Primitive(id, []byte{0}).Encode())
	d.NullAs(id)
	require.ErrorIs(t, d.End(), ber.ErrInvalidNull)
	var at *ber.DecodeError
	require.ErrorAs(t, d.Err(), &at)
	assert.Zero(t, at.Offset)

	d, _ = decoderFor(t, ber.Primitive(id, []byte{1}).Encode())
	assert.False(t, d.BooleanAs(id))
	require.ErrorIs(t, d.End(), ber.ErrInvalidBoolean)
	require.ErrorAs(t, d.Err(), &at)
	assert.Zero(t, at.Offset)
}

func TestDecoderUsingDiscardsValueAfterSharedFailure(t *testing.T) {
	d, _ := decoderFor(t, ber.Integer(1).Encode())
	want := errors.New("custom validation failed")
	got := d.Using(func(r *ber.Reader) (int64, error) {
		value, err := r.Integer()
		d.Fail(want)
		return value, err
	})
	assert.Zero(t, got)
	require.ErrorIs(t, d.End(), want)
}

func TestDecoderCheckedIntegerConversions(t *testing.T) {
	tests := []struct {
		name   string
		packet ber.Packet
		read   func(*ber.Decoder) any
		want   any
		bad    bool
	}{
		{"int8 min", ber.Integer(-128), func(d *ber.Decoder) any { return d.Integer[int8]() }, int8(-128), false},
		{"int8 max", ber.Integer(127), func(d *ber.Decoder) any { return d.Integer[int8]() }, int8(127), false},
		{"int8 underflow", ber.Integer(-129), func(d *ber.Decoder) any { return d.Integer[int8]() }, int8(0), true},
		{"int8 overflow", ber.Integer(128), func(d *ber.Decoder) any { return d.Integer[int8]() }, int8(0), true},
		{"unsigned negative", ber.Integer(-1), func(d *ber.Decoder) any { return d.Integer[uint64]() }, uint64(0), true},
		{"uint8 max", ber.Integer(255), func(d *ber.Decoder) any { return d.Integer[uint8]() }, uint8(255), false},
		{"uint8 overflow", ber.Integer(256), func(d *ber.Decoder) any { return d.Integer[uint8]() }, uint8(0), true},
		{"int32 min", ber.Integer(math.MinInt32), func(d *ber.Decoder) any { return d.Integer[int32]() }, int32(math.MinInt32), false},
		{"uint32 max", ber.Integer(uint32(math.MaxUint32)), func(d *ber.Decoder) any { return d.Integer[uint32]() }, uint32(math.MaxUint32), false},
		{"int64 min", ber.Integer(int64(math.MinInt64)), func(d *ber.Decoder) any { return d.Integer[int64]() }, int64(math.MinInt64), false},
		{"int64 max", ber.Integer(int64(math.MaxInt64)), func(d *ber.Decoder) any { return d.Integer[int64]() }, int64(math.MaxInt64), false},
		{"int64 overflow", ber.Integer(uint64(math.MaxInt64) + 1), func(d *ber.Decoder) any { return d.Integer[int64]() }, int64(0), true},
		{"uint64 max", ber.Integer(uint64(math.MaxUint64)), func(d *ber.Decoder) any { return d.Integer[uint64]() }, uint64(math.MaxUint64), false},
		{"named enumeration", ber.Enumerated(-7), func(d *ber.Decoder) any { return d.Enumerated[decoderInt]() }, decoderInt(-7), false},
		{"empty", ber.Primitive(ber.IntegerIdentifier, nil), func(d *ber.Decoder) any { return d.Integer[int64]() }, int64(0), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := limits()
			l.MaxIntegerBytes = 9
			r, err := ber.NewReader(tt.packet.Encode(), l)
			require.NoError(t, err)
			d := ber.NewDecoder(r)
			assert.Equal(t, tt.want, tt.read(d))
			if tt.bad {
				require.ErrorIs(t, d.End(), ber.ErrInvalidInteger)
			} else {
				require.NoError(t, d.End())
			}
		})
	}
}

func TestDecoderLimitsAndOwnedBytes(t *testing.T) {
	encoded := ber.Sequence().Add(ber.Integer(1), ber.Integer(2), ber.Integer(3)).BERPacket().Encode()
	for _, maxElements := range []int{3, 4} {
		l := limits()
		l.MaxElements = maxElements
		r, err := ber.NewReader(encoded, l)
		require.NoError(t, err)
		d := ber.NewDecoder(r)
		got := d.Sequence().All[decoderInt]()
		if maxElements == 3 {
			assert.Nil(t, got)
			var limit *ber.LimitError
			require.ErrorAs(t, d.End(), &limit)
			assert.Equal(t, "elements", limit.Limit)
		} else {
			require.NoError(t, d.End())
			assert.Equal(t, []decoderInt{1, 2, 3}, got)
		}
	}

	l := limits()
	l.MaxDepth = 1
	r, err := ber.NewReader(ber.Sequence().Add(ber.Sequence()).BERPacket().Encode(), l)
	require.NoError(t, err)
	d := ber.NewDecoder(r)
	d.Sequence().Sequence()
	var limit *ber.LimitError
	require.ErrorAs(t, d.End(), &limit)
	assert.Equal(t, "depth", limit.Limit)

	d, _ = decoderFor(t, ber.Integer(uint64(math.MaxUint64)).Encode())
	d.Integer[uint64]()
	require.ErrorAs(t, d.End(), &limit)
	assert.Equal(t, "integer bytes", limit.Limit)

	encoded = ber.OctetString([]byte{0, 0xff}).Encode()
	d, _ = decoderFor(t, encoded)
	owned := d.OctetString[[]byte]()
	require.NoError(t, d.End())
	copy(encoded, bytes.Repeat([]byte{0}, len(encoded)))
	assert.Equal(t, []byte{0, 0xff}, owned)

	d, _ = decoderFor(t, []byte{0xa0, 1, 0xff})
	assert.Nil(t, d.Extensions[decoderRaw]())
	require.ErrorIs(t, d.End(), ber.ErrTruncated)
}

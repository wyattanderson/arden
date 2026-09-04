package ber_test

import (
	"bytes"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func limits() ber.Limits { return ber.DefaultLimits() }

func TestIdentifierBoundaries(t *testing.T) {
	tests := []struct {
		name string
		id   ber.Identifier
		want []byte
	}{
		{"short universal", ber.Identifier{Class: ber.ClassUniversal, Number: 30}, []byte{0x1e}},
		{"first high tag", ber.Identifier{Class: ber.ClassApplication, Number: 31}, []byte{0x5f, 0x1f}},
		{"high tag", ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: 0x3fff}, []byte{0xbf, 0xff, 0x7f}},
		{"maximum tag", ber.Identifier{Class: ber.ClassPrivate, Number: math.MaxUint32}, []byte{0xdf, 0x8f, 0xff, 0xff, 0xff, 0x7f}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ber.WithContents(test.id, nil).Encode()
			require.Equal(t, append(test.want, 0), got)
			e, err := ber.DecodeElement(got, limits())
			require.NoError(t, err)
			assert.Equal(t, test.id, e.Identifier)
		})
	}
}

func TestLengthBoundaries(t *testing.T) {
	for _, length := range []int{0, 127, 128, 255, 256, 65535, 65536} {
		t.Run("length", func(t *testing.T) {
			value := bytes.Repeat([]byte{0x42}, length)
			encoded := ber.OctetString(value).Encode()
			r, err := ber.NewReader(encoded, limits())
			require.NoError(t, err)
			got, err := r.OctetString()
			require.NoError(t, err)
			assert.Equal(t, value, got)
			assert.Zero(t, r.Remaining())
		})
	}
}

func TestPrimitiveRoundTrips(t *testing.T) {
	for _, value := range []int64{math.MinInt64, -129, -128, -1, 0, 1, 127, 128, math.MaxInt64} {
		encoded := ber.Integer(value).Encode()
		r, err := ber.NewReader(encoded, limits())
		require.NoError(t, err)
		got, err := r.Integer()
		require.NoError(t, err)
		assert.Equal(t, value, got)
	}
	encoded := ber.Boolean(true).Encode()
	assert.Equal(t, []byte{1, 1, 0xff}, encoded)
}

func TestReaderRejectsLDAPRestrictionsAtomically(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		read func(*ber.Reader) error
		want error
	}{
		{"indefinite", []byte{0x04, 0x80}, func(r *ber.Reader) error { _, err := r.OctetString(); return err }, ber.ErrIndefiniteLength},
		{"constructed octet", []byte{0x24, 0x00}, func(r *ber.Reader) error { _, err := r.OctetString(); return err }, ber.ErrPrimitiveRequired},
		{"boolean true must be ff", []byte{0x01, 0x01, 0x01}, func(r *ber.Reader) error { _, err := r.Boolean(); return err }, ber.ErrInvalidBoolean},
		{"null contents", []byte{0x05, 0x01, 0x00}, func(r *ber.Reader) error { return r.Null() }, ber.ErrInvalidNull},
		{"nonminimal high tag", []byte{0x1f, 0x1e, 0x00}, func(r *ber.Reader) error { _, err := r.ReadElement(); return err }, ber.ErrInvalidIdentifier},
		{"nonminimal long length", []byte{0x04, 0x81, 0x7f}, func(r *ber.Reader) error { _, err := r.ReadElement(); return err }, ber.ErrInvalidLength},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, err := ber.NewReader(test.data, limits())
			require.NoError(t, err)
			err = test.read(r)
			require.ErrorIs(t, err, test.want)
			assert.Zero(t, r.Offset())
		})
	}
}

func TestReaderLimits(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		data := []byte{0x30, 0x02, 0x30, 0x00}
		l := limits()
		l.MaxDepth = 1
		r, _ := ber.NewReader(data, l)
		child, err := r.Sequence()
		require.NoError(t, err)
		_, err = child.Sequence()
		var limit *ber.LimitError
		require.ErrorAs(t, err, &limit)
		assert.Equal(t, "depth", limit.Limit)
	})
	t.Run("elements", func(t *testing.T) {
		l := limits()
		l.MaxElements = 1
		r, _ := ber.NewReader([]byte{0x05, 0x00, 0x05, 0x00}, l)
		require.NoError(t, r.Null())
		assert.Error(t, r.Null())
	})
}

func TestSkipElementValidatesNestedLimits(t *testing.T) {
	t.Run("peek does not advance", func(t *testing.T) {
		r, err := ber.NewReader([]byte{0x04, 0x00}, limits())
		require.NoError(t, err)
		id, err := r.PeekIdentifier()
		require.NoError(t, err)
		assert.Equal(t, ber.OctetStringIdentifier, id)
		assert.Zero(t, r.Offset())
	})

	t.Run("unknown extension cannot bypass depth", func(t *testing.T) {
		data := []byte{0x30, 0x02, 0x30, 0x00}
		l := limits()
		l.MaxDepth = 1
		r, err := ber.NewReader(data, l)
		require.NoError(t, err)
		_, err = r.SkipElement()
		assert.Error(t, err)
	})
}

func TestFramerEverySplit(t *testing.T) {
	frame := make([]byte, 0, 131)
	frame = append(frame, 0x30, 0x81, 0x80)
	frame = append(frame, bytes.Repeat([]byte{0}, 128)...)
	for split := 0; split <= len(frame); split++ {
		t.Run("split", func(t *testing.T) {
			reader := &splitReader{parts: [][]byte{frame[:split], frame[split:]}}
			framer, err := ber.NewFramer(reader, limits())
			require.NoError(t, err)
			got, err := framer.Next()
			require.NoError(t, err)
			require.Equal(t, frame, got)
			got[0] = 0
			assert.NotZero(t, frame[0])
		})
	}
}

func TestFramerTruncation(t *testing.T) {
	frame := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	for n := range len(frame) {
		framer, err := ber.NewFramer(bytes.NewReader(frame[:n]), limits())
		require.NoError(t, err)
		_, err = framer.Next()
		if n == 0 {
			require.ErrorIs(t, err, io.EOF)
			continue
		}
		require.ErrorIs(t, err, ber.ErrTruncated)
	}
}

func TestReaderTruncation(t *testing.T) {
	frame := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	for n := range len(frame) {
		t.Run("truncation", func(t *testing.T) {
			r, err := ber.NewReader(frame[:n], limits())
			require.NoError(t, err)
			_, err = r.ReadElement()
			require.ErrorIs(t, err, ber.ErrTruncated)
			assert.Zero(t, r.Offset())
		})
	}
}

type splitReader struct {
	parts [][]byte
}

func (r *splitReader) Read(p []byte) (int, error) {
	for len(r.parts) > 0 && len(r.parts[0]) == 0 {
		r.parts = r.parts[1:]
	}
	if len(r.parts) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.parts[0][:1])
	r.parts[0] = r.parts[0][n:]
	return n, nil
}

func FuzzDecodeElement(f *testing.F) {
	for _, seed := range [][]byte{{0x05, 0x00}, {0x30, 0x03, 0x02, 0x01, 0x01}, {0x04, 0x80}} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ber.DecodeElement(data, limits())
		r, err := ber.NewReader(data, limits())
		if err == nil {
			for !r.Empty() {
				if _, err := r.ReadElement(); err != nil {
					break
				}
			}
		}
	})
}

func FuzzPrimitiveDecoders(f *testing.F) {
	for _, seed := range [][]byte{{0x01, 0x01, 0xff}, {0x02, 0x01, 0x01}, {0x04, 0x00}, {0x05, 0x00}, {0x30, 0x00}} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		for _, read := range []func(*ber.Reader){
			func(r *ber.Reader) { _, _ = r.Boolean() },
			func(r *ber.Reader) { _, _ = r.Integer() },
			func(r *ber.Reader) { _, _ = r.Enumerated() },
			func(r *ber.Reader) { _, _ = r.OctetString() },
			func(r *ber.Reader) { _ = r.Null() },
			func(r *ber.Reader) { _, _ = r.Sequence() },
			func(r *ber.Reader) { _, _ = r.Set() },
		} {
			r, err := ber.NewReader(data, limits())
			if err == nil {
				read(r)
			}
		}
	})
}

func FuzzFramer(f *testing.F) {
	for _, seed := range [][]byte{{0x05, 0x00}, {0x30, 0x03, 0x02, 0x01, 0x01}, {0x04, 0x80}} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		framer, err := ber.NewFramer(bytes.NewReader(data), limits())
		if err == nil {
			_, _ = framer.Next()
		}
	})
}

func BenchmarkFramer(b *testing.B) {
	frame := append([]byte{0x30, 0x82, 0x10, 0x00}, bytes.Repeat([]byte{0}, 4096)...)
	b.ReportAllocs()
	for range b.N {
		framer, err := ber.NewFramer(bytes.NewReader(frame), limits())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := framer.Next(); err != nil {
			b.Fatal(err)
		}
	}
}

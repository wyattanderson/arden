package ldapmodel

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
)

func roundTrip[T any](t *testing.T, codec ValueCodec[T], value T, wire string) {
	t.Helper()
	encoded, err := codec.Encode(value)
	require.NoError(t, err)
	assert.Equal(t, wire, string(encoded))
	decoded, err := codec.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, value, decoded)
}

func TestInferredCodecs(t *testing.T) {
	roundTrip(t, BoolCodec, false, "FALSE")
	roundTrip(t, BoolCodec, true, "TRUE")
	roundTrip(t, Int64Codec, int64(math.MinInt64), "-9223372036854775808")
	roundTrip(t, Uint64Codec, uint64(math.MaxUint64), "18446744073709551615")
	roundTrip(t, DirectoryStringCodec, "Zoë", "Zoë")
	roundTrip(t, IA5StringCodec, "", "")
	roundTrip(t, NumericStringCodec, "001 02", "001 02")
	roundTrip(t, DNCodec, arden.LDAPDN("cn=Zoë,dc=test"), "cn=Zoë,dc=test")
	for _, raw := range []string{"true", "1", "", "sensitive"} {
		_, err := BoolCodec.Decode([]byte(raw))
		require.Error(t, err)
		assert.NotContains(t, err.Error(), raw+"\"")
	}
	for _, raw := range []string{"+1", "01", "-0", "1.5", "", "9223372036854775808"} {
		_, err := Int64Codec.Decode([]byte(raw))
		require.Error(t, err)
	}
	for _, raw := range []string{"-1", "18446744073709551616"} {
		_, err := Uint64Codec.Decode([]byte(raw))
		require.Error(t, err)
	}
	for _, test := range []struct {
		codec ValueCodec[string]
		raw   string
	}{
		{DirectoryStringCodec, ""}, {DirectoryStringCodec, "\xff"}, {IA5StringCodec, "é"}, {NumericStringCodec, "12a"},
	} {
		_, err := test.codec.Encode(test.raw)
		require.Error(t, err)
		_, err = test.codec.Decode([]byte(test.raw))
		require.Error(t, err)
	}
}

func TestGeneralizedTimeCodec(t *testing.T) {
	for _, test := range []struct{ wire, utc string }{
		{"20260912123456Z", "2026-09-12T12:34:56Z"},
		{"2026091212.5Z", "2026-09-12T12:30:00Z"},
		{"202609121234,5+0530", "2026-09-12T07:04:30Z"},
		{"20260912123456.123456789-07", "2026-09-12T19:34:56.123456789Z"},
		{"20260912123456.1234567890Z", "2026-09-12T12:34:56.123456789Z"},
	} {
		value, err := GeneralizedTimeCodec.Decode([]byte(test.wire))
		require.NoError(t, err)
		assert.Equal(t, test.utc, value.Format(time.RFC3339Nano))
		encoded, err := GeneralizedTimeCodec.Encode(value)
		require.NoError(t, err)
		again, err := GeneralizedTimeCodec.Decode(encoded)
		require.NoError(t, err)
		assert.True(t, value.Equal(again))
	}
	for _, raw := range []string{"20260230120000Z", "20260912123456", "20260912123460Z", "20260912123456.0000000001Z", "20260912123456+2400", "20260912123456+1260", "junk"} {
		_, err := GeneralizedTimeCodec.Decode([]byte(raw))
		require.Error(t, err, raw)
		assert.NotContains(t, err.Error(), raw)
	}
}

func TestRequiredManyAndFallibleCriterion(t *testing.T) {
	a := NewAttribute[arden.Entry]("cn", DirectoryStringCodec)
	_, err := RequiredMany(a, arden.Entry{})
	require.ErrorContains(t, err, "required attribute")
	entry := arden.NewEntry("cn=alice")
	entry.Set("cn", "Alice", "A")
	values, err := RequiredMany(a, *entry)
	require.NoError(t, err)
	assert.Equal(t, []string{"Alice", "A"}, values)
	dao := NewDAO[arden.Entry](nil, Model[arden.Entry]{})
	_, err = dao.Where(EqualCriterion(a, "")).One()
	require.ErrorContains(t, err, "encode cn assertion") // No client call (nil client).
}

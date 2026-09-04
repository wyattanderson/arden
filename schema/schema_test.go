package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestTypedAttributeRoundTripAndFilter(t *testing.T) {
	uid := NewAttribute("uid", StringCodec)
	entry := arden.NewEntry("uid=alice,dc=example")
	require.NoError(t, uid.Set(entry, "alice"))

	values, err := uid.Values(*entry)
	require.NoError(t, err)
	assert.Equal(t, []string{"alice"}, values)

	filter, err := uid.Equal("alice")
	require.NoError(t, err)
	assert.IsType(t, rfc4511.EqualityMatch{}, filter)
}

func TestBytesAttributeSharesStorage(t *testing.T) {
	photo := NewAttribute("jpegPhoto", BytesCodec)
	value := []byte{0, 0xff}
	entry := arden.NewEntry("cn=Alice")
	require.NoError(t, photo.Set(entry, value))
	filter, err := photo.Equal(value)
	require.NoError(t, err)
	values, err := photo.Values(*entry)
	require.NoError(t, err)
	require.Len(t, values, 1)
	values[0][0] = 1
	assert.Equal(t, []byte{1, 0xff}, value)
	assert.Equal(t, value, entry.RawValue("jpegPhoto"))
	assert.Equal(t, rfc4511.AssertionValue(value), filter.(rfc4511.EqualityMatch).Assertion.Value)
}

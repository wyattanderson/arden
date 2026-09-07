package schema

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestAttributePreparedKeyAndAtomicSet(t *testing.T) {
	encoded := []byte("new")
	encodeError := errors.New("cannot encode")
	attribute := NewAttribute("CN;LANG-EN;lang-de", Codec[string]{
		EncodeFunc: func(value string) ([]byte, error) {
			if value == "bad" {
				return nil, encodeError
			}
			return encoded, nil
		},
		DecodeFunc: func(raw []byte) (string, error) { return string(raw), nil },
	})
	assert.Equal(t, "CN;LANG-EN;lang-de", attribute.Name())
	assert.Equal(t, rfc4511.AttributeDescription("cn;lang-de;lang-en").Key(), attribute.Key())
	entry := arden.NewEntry("cn=Alice")
	entry.Set("cn;lang-de;lang-en", "old")
	require.ErrorIs(t, attribute.Set(entry, "ok", "bad"), encodeError)
	assert.Equal(t, "old", entry.Value("cn;lang-de;lang-en"))
	require.NoError(t, attribute.Set(entry, "ok"))
	raw, ok := entry.Attributes.LookupKey(attribute.Key())
	require.True(t, ok)
	assert.Equal(t, attribute.Name(), string(raw.Type))
	assert.Same(t, &encoded[0], &raw.Values[0][0])
	encoded[0] = 'N'
	values, err := attribute.Values(*entry)
	require.NoError(t, err)
	assert.Equal(t, []string{"New"}, values)
}

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

func TestMustEqualUsesAttributeCodec(t *testing.T) {
	uidNumber := NewAttribute("uidNumber", Uint32Codec)
	assert.Equal(t, arden.Equal("uidNumber", "4294967295"), uidNumber.MustEqual(1<<32-1))
	uid := NewAttribute("uid", StringCodec)
	assert.Equal(t, arden.Equal("uid", "alice*()\\"), uid.MustEqual("alice*()\\"))

	encodeError := errors.New("cannot encode")
	attribute := NewAttribute("custom", Codec[string]{EncodeFunc: func(string) ([]byte, error) {
		return nil, encodeError
	}})
	_, err := attribute.Equal("value")
	require.ErrorIs(t, err, encodeError)
	assert.PanicsWithError(t, err.Error(), func() { attribute.MustEqual("value") })
}

package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestLDAPOIDDecodeValidationIsAtomic(t *testing.T) {
	encoded, err := ber.AppendOctetString(nil, []byte("1..2"))
	require.NoError(t, err)
	prior := LDAPOID("9.9")
	requireDecodeError(t, encoded, &prior)
	assert.Equal(t, LDAPOID("9.9"), prior)
}

func TestLDAPTextTypesDecodeUTF8(t *testing.T) {
	encoded, err := ber.AppendOctetString(nil, []byte("Jöhn"))
	require.NoError(t, err)
	var value LDAPString
	decode(t, encoded, &value)
	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, LDAPString("Jöhn"), value)

	invalid, err := ber.AppendOctetString(nil, []byte{0xff})
	require.NoError(t, err)
	requireDecodeError(t, invalid, &value)
}

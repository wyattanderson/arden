package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestLDAPOIDDecodeValidationIsAtomic(t *testing.T) {
	encoded, err := ber.OctetString("1..2").AppendBER(nil)
	require.NoError(t, err)
	prior := LDAPOID("9.9")
	requireDecodeError(t, encoded, &prior)
	assert.Equal(t, LDAPOID("9.9"), prior)
}

func TestLDAPTextTypesDecodeUTF8(t *testing.T) {
	encoded, err := ber.OctetString("Jöhn").AppendBER(nil)
	require.NoError(t, err)
	var value LDAPString
	decode(t, encoded, &value)
	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, LDAPString("Jöhn"), value)

	invalid, err := ber.OctetString([]byte{0xff}).AppendBER(nil)
	require.NoError(t, err)
	requireDecodeError(t, invalid, &value)
}

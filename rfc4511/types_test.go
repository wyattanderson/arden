package rfc4511_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestLDAPOIDDecodeValidationIsAtomic(t *testing.T) {
	encoded, err := ber.AppendOctetString(nil, []byte("1..2"))
	require.NoError(t, err)
	prior := rfc4511.LDAPOID("9.9")
	requireDecodeError(t, encoded, &prior)
	assert.Equal(t, rfc4511.LDAPOID("9.9"), prior)
}

func TestLDAPOctetTypesCopyDecodedBytes(t *testing.T) {
	encoded, err := ber.AppendOctetString(nil, []byte{0x00, 0xff})
	require.NoError(t, err)
	var value rfc4511.LDAPString
	decode(t, encoded, &value)
	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, rfc4511.LDAPString{0x00, 0xff}, value)
}

package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/wyattanderson/arden/ber"
)

func TestLDAPOIDDecodeValidationIsAtomic(t *testing.T) {
	encoded := ber.OctetString("1..2").Encode()
	prior := LDAPOID("9.9")
	requireDecodeError(t, encoded, &prior)
	assert.Equal(t, LDAPOID("9.9"), prior)
}

func TestLDAPTextTypesDecodeUTF8(t *testing.T) {
	encoded := ber.OctetString("Jöhn").Encode()
	var value LDAPString
	decode(t, encoded, &value)
	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, LDAPString("Jöhn"), value)

	invalid := ber.OctetString([]byte{0xff}).Encode()
	requireDecodeError(t, invalid, &value)
}

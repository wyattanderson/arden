package rfc4511_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestBindRequestAuthenticationVariants(t *testing.T) {
	tests := []struct {
		name string
		auth rfc4511.AuthenticationChoice
	}{
		{"simple empty", rfc4511.SimpleAuthentication{}},
		{"simple binary", rfc4511.SimpleAuthentication{0x00, 0xff}},
		{"SASL credentials absent", rfc4511.SASLAuthentication{Mechanism: rfc4511.LDAPString("PLAIN")}},
		{"SASL credentials present empty", rfc4511.SASLAuthentication{Mechanism: rfc4511.LDAPString("PLAIN"), HasCredentials: true, Credentials: []byte{}}},
		{"SASL credentials binary", rfc4511.SASLAuthentication{Mechanism: rfc4511.LDAPString("GSSAPI"), HasCredentials: true, Credentials: []byte{0x00, 0xff}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := &rfc4511.BindRequest{Version: 3, Name: rfc4511.LDAPDN("cn=admin"), Authentication: test.auth}
			encoded, err := request.AppendBER(nil)
			require.NoError(t, err)
			var got rfc4511.BindRequest
			decode(t, encoded, &got)
			assert.Equal(t, request.Version, got.Version)
			assert.Equal(t, request.Name, got.Name)
			assert.Equal(t, request.Authentication, got.Authentication)
		})
	}
}

func TestBindRequestPreservesUnknownAuthentication(t *testing.T) {
	encoded := []byte{0x60, 0x09, 0x02, 0x01, 0x03, 0x04, 0x00, 0x85, 0x02, 0x00, 0xff}
	var request rfc4511.BindRequest
	decode(t, encoded, &request)
	unknown, ok := request.Authentication.(rfc4511.UnknownAuthentication)
	require.True(t, ok)
	assert.Equal(t, []byte{0x85, 0x02, 0x00, 0xff}, unknown.Raw())

	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, []byte{0x85, 0x02, 0x00, 0xff}, unknown.Raw())
	reencoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x60, 0x09, 0x02, 0x01, 0x03, 0x04, 0x00, 0x85, 0x02, 0x00, 0xff}, reencoded)
}

func TestBindRequestValidationBoundariesAreAtomic(t *testing.T) {
	for _, version := range []int64{1, 127} {
		_, err := (&rfc4511.BindRequest{Version: version, Authentication: rfc4511.SimpleAuthentication{}}).AppendBER(nil)
		assert.NoError(t, err)
	}
	for _, request := range []*rfc4511.BindRequest{
		nil,
		{Version: 0, Authentication: rfc4511.SimpleAuthentication{}},
		{Version: 128, Authentication: rfc4511.SimpleAuthentication{}},
		{Version: 3},
		{Version: 3, Authentication: rfc4511.SASLAuthentication{}},
	} {
		dst := []byte{0xde, 0xad}
		got, err := request.AppendBER(dst)
		assert.Error(t, err)
		assert.Equal(t, dst, got)
	}
}

func TestBindRequestRejectsDuplicateSASLCredentialsAtomically(t *testing.T) {
	// BindRequest(version=3, empty DN, SASL(PLAIN, empty credentials, duplicate credentials)).
	encoded := []byte{0x60, 0x13, 0x02, 0x01, 0x03, 0x04, 0x00, 0xa3, 0x0c, 0x04, 0x05, 'P', 'L', 'A', 'I', 'N', 0x04, 0x00, 0x04, 0x00}
	prior := rfc4511.BindRequest{Version: 9, Name: rfc4511.LDAPDN("keep"), Authentication: rfc4511.SimpleAuthentication("keep")}
	requireDecodeError(t, encoded, &prior)
	assert.Equal(t, int64(9), prior.Version)
	assert.Equal(t, "keep", string(prior.Name))
}

func TestBindAuthenticationExtensionAndIdentifierBoundaries(t *testing.T) {
	// SASL(PLAIN, trailing extension [5]).
	encoded := []byte{0x60, 0x14, 0x02, 0x01, 0x03, 0x04, 0x00, 0xa3, 0x0d, 0x04, 0x05, 'P', 'L', 'A', 'I', 'N', 0x85, 0x04, 'e', 'x', 't', 'n'}
	var request rfc4511.BindRequest
	decode(t, encoded, &request)
	sasl, ok := request.Authentication.(rfc4511.SASLAuthentication)
	require.True(t, ok)
	require.Len(t, sasl.Extensions, 1)
	reencoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, encoded, reencoded)

	for _, authentication := range []rfc4511.AuthenticationChoice{
		badAuthentication{declared: rfc4511.BindRequestIdentifier(), encoded: []byte{0x85, 0x00}},
		badAuthentication{declared: ber.Identifier{Class: ber.ClassContextSpecific, Number: 4}, encoded: []byte{0x85, 0x00}},
	} {
		dst := []byte{0xde, 0xad}
		got, err := (&rfc4511.BindRequest{Version: 3, Authentication: authentication}).AppendBER(dst)
		assert.Error(t, err)
		assert.Equal(t, dst, got)
	}
}

type badAuthentication struct {
	declared ber.Identifier
	encoded  []byte
}

func (a badAuthentication) AuthenticationIdentifier() ber.Identifier { return a.declared }
func (a badAuthentication) AppendBER(dst []byte) ([]byte, error) {
	return append(dst, a.encoded...), nil
}

func TestBindResponseServerCredentialsPresence(t *testing.T) {
	tests := []rfc4511.BindResponse{
		{Result: emptyResult(rfc4511.ResultSuccess)},
		{Result: emptyResult(rfc4511.ResultSASLBindInProgress), HasServerSASLCredentials: true, ServerSASLCredentials: []byte{}},
		{Result: emptyResult(rfc4511.ResultSuccess), HasServerSASLCredentials: true, ServerSASLCredentials: []byte{0x00, 0xff}},
	}
	for _, response := range tests {
		encoded, err := response.AppendBER(nil)
		require.NoError(t, err)
		var got rfc4511.BindResponse
		decode(t, encoded, &got)
		assert.Equal(t, response, got)
	}

	duplicate := []byte{0x61, 0x0b, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x87, 0x00, 0x87, 0x00}
	requireDecodeError(t, duplicate, &rfc4511.BindResponse{})
}

func emptyResult(code rfc4511.ResultCode) rfc4511.LDAPResult {
	return rfc4511.LDAPResult{ResultCode: code, MatchedDN: rfc4511.LDAPDN{}, DiagnosticMessage: rfc4511.LDAPString{}}
}

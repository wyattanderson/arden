package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestBindRequestAuthenticationVariants(t *testing.T) {
	tests := []struct {
		name string
		auth AuthenticationChoice
	}{
		{"simple empty", SimpleAuthentication{}},
		{"simple binary", SimpleAuthentication{0x00, 0xff}},
		{"SASL credentials absent", SASLAuthentication{Mechanism: LDAPString("PLAIN")}},
		{"SASL credentials present empty", SASLAuthentication{Mechanism: LDAPString("PLAIN"), HasCredentials: true, Credentials: []byte{}}},
		{"SASL credentials binary", SASLAuthentication{Mechanism: LDAPString("GSSAPI"), HasCredentials: true, Credentials: []byte{0x00, 0xff}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := &BindRequest{Version: 3, Name: LDAPDN("cn=admin"), Authentication: test.auth}
			encoded, err := request.AppendBER(nil)
			require.NoError(t, err)
			var got BindRequest
			decode(t, encoded, &got)
			assert.Equal(t, request.Version, got.Version)
			assert.Equal(t, request.Name, got.Name)
			assert.Equal(t, request.Authentication, got.Authentication)
		})
	}
}

func TestBindRequestPreservesUnknownAuthentication(t *testing.T) {
	encoded := []byte{0x60, 0x09, 0x02, 0x01, 0x03, 0x04, 0x00, 0x85, 0x02, 0x00, 0xff}
	var request BindRequest
	decode(t, encoded, &request)
	unknown, ok := request.Authentication.(UnknownAuthentication)
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
		_, err := (&BindRequest{Version: version, Authentication: SimpleAuthentication{}}).AppendBER(nil)
		require.NoError(t, err)
	}
	for _, request := range []*BindRequest{
		nil,
		{Version: 0, Authentication: SimpleAuthentication{}},
		{Version: 128, Authentication: SimpleAuthentication{}},
		{Version: 3},
		{Version: 3, Authentication: SASLAuthentication{}},
	} {
		dst := []byte{0xde, 0xad}
		got, err := request.AppendBER(dst)
		require.Error(t, err)
		assert.Equal(t, dst, got)
	}
}

func TestBindRequestRejectsDuplicateSASLCredentialsAtomically(t *testing.T) {
	// BindRequest(version=3, empty DN, SASL(PLAIN, empty credentials, duplicate credentials)).
	encoded := []byte{0x60, 0x13, 0x02, 0x01, 0x03, 0x04, 0x00, 0xa3, 0x0c, 0x04, 0x05, 'P', 'L', 'A', 'I', 'N', 0x04, 0x00, 0x04, 0x00}
	prior := BindRequest{Version: 9, Name: LDAPDN("keep"), Authentication: SimpleAuthentication("keep")}
	requireDecodeError(t, encoded, &prior)
	assert.Equal(t, int64(9), prior.Version)
	assert.Equal(t, "keep", string(prior.Name))
}

func TestBindAuthenticationExtensionAndIdentifierBoundaries(t *testing.T) {
	// SASL(PLAIN, trailing extension [5]).
	encoded := []byte{0x60, 0x14, 0x02, 0x01, 0x03, 0x04, 0x00, 0xa3, 0x0d, 0x04, 0x05, 'P', 'L', 'A', 'I', 'N', 0x85, 0x04, 'e', 'x', 't', 'n'}
	var request BindRequest
	decode(t, encoded, &request)
	sasl, ok := request.Authentication.(SASLAuthentication)
	require.True(t, ok)
	require.Len(t, sasl.Extensions, 1)
	reencoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, encoded, reencoded)

	for _, authentication := range []AuthenticationChoice{
		badAuthentication{declared: BindRequestIdentifier(), encoded: []byte{0x85, 0x00}},
		badAuthentication{declared: ber.Identifier{Class: ber.ClassContextSpecific, Number: 4}, encoded: []byte{0x85, 0x00}},
	} {
		dst := []byte{0xde, 0xad}
		got, err := (&BindRequest{Version: 3, Authentication: authentication}).AppendBER(dst)
		require.Error(t, err)
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
	tests := []BindResponse{
		{Result: emptyResult(ResultSuccess)},
		{Result: emptyResult(ResultSASLBindInProgress), HasServerSASLCredentials: true, ServerSASLCredentials: []byte{}},
		{Result: emptyResult(ResultSuccess), HasServerSASLCredentials: true, ServerSASLCredentials: []byte{0x00, 0xff}},
	}
	for _, response := range tests {
		encoded, err := response.AppendBER(nil)
		require.NoError(t, err)
		var got BindResponse
		decode(t, encoded, &got)
		assert.Equal(t, response, got)
	}

	duplicate := []byte{0x61, 0x0b, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x87, 0x00, 0x87, 0x00}
	requireDecodeError(t, duplicate, &BindResponse{})
}

func emptyResult(code ResultCode) LDAPResult {
	return LDAPResult{ResultCode: code}
}

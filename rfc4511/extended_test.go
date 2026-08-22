package rfc4511_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestExtendedRequestValuePresence(t *testing.T) {
	tests := []rfc4511.ExtendedRequest{
		{Name: rfc4511.LDAPOID("1.2.3")},
		{Name: rfc4511.LDAPOID("1.2.3"), HasValue: true, Value: []byte{}},
		{Name: rfc4511.LDAPOID("1.2.3"), HasValue: true, Value: []byte{0x00, 0xff}},
	}
	for _, request := range tests {
		encoded, err := request.AppendBER(nil)
		require.NoError(t, err)
		var got rfc4511.ExtendedRequest
		decode(t, encoded, &got)
		assert.Equal(t, request, got)
	}
}

func TestExtendedAndIntermediateResponseOptionalFields(t *testing.T) {
	responseTests := []rfc4511.ExtendedResponse{
		{Result: emptyResult(rfc4511.ResultSuccess)},
		{Result: emptyResult(rfc4511.ResultSuccess), HasResponseValue: true, ResponseValue: []byte{}},
		{Result: emptyResult(rfc4511.ResultSuccess), HasResponseName: true, ResponseName: rfc4511.LDAPOID("1.2.3")},
		{Result: emptyResult(rfc4511.ResultSuccess), HasResponseName: true, ResponseName: rfc4511.LDAPOID("1.2.3"), HasResponseValue: true, ResponseValue: []byte{0x00, 0xff}},
	}
	for _, response := range responseTests {
		encoded, err := response.AppendBER(nil)
		require.NoError(t, err)
		var got rfc4511.ExtendedResponse
		decode(t, encoded, &got)
		assert.Equal(t, response, got)
	}

	intermediateTests := []rfc4511.IntermediateResponse{
		{},
		{HasResponseValue: true, ResponseValue: []byte{}},
		{HasResponseName: true, ResponseName: rfc4511.LDAPOID("1.2.3")},
		{HasResponseName: true, ResponseName: rfc4511.LDAPOID("1.2.3"), HasResponseValue: true, ResponseValue: []byte{0x00, 0xff}},
	}
	for _, response := range intermediateTests {
		encoded, err := response.AppendBER(nil)
		require.NoError(t, err)
		var got rfc4511.IntermediateResponse
		decode(t, encoded, &got)
		assert.Equal(t, response, got)
	}
}

func TestExtendedTypesValidateNamesAndOrderingAtomically(t *testing.T) {
	invalidMarshalers := []ber.Marshaler{
		(*rfc4511.ExtendedRequest)(nil),
		&rfc4511.ExtendedRequest{},
		&rfc4511.ExtendedRequest{Name: rfc4511.LDAPOID("1")},
		rfc4511.ExtendedResponse{HasResponseName: true},
		rfc4511.ExtendedResponse{HasResponseName: true, ResponseName: rfc4511.LDAPOID("1..2")},
		rfc4511.IntermediateResponse{HasResponseName: true},
	}
	for _, value := range invalidMarshalers {
		dst := []byte{0xde, 0xad}
		got, err := value.AppendBER(dst)
		require.Error(t, err)
		assert.Equal(t, dst, got)
	}

	requestDuplicate := extendedRequestWire(t,
		implicit(t, 0, []byte("1.2.3")),
		implicit(t, 1, nil),
		implicit(t, 1, nil),
	)
	requireDecodeError(t, requestDuplicate, &rfc4511.ExtendedRequest{})

	responseDuplicate := extendedResponseWire(t,
		implicit(t, 10, []byte("1.2.3")),
		implicit(t, 11, nil),
		implicit(t, 11, nil),
	)
	requireDecodeError(t, responseDuplicate, &rfc4511.ExtendedResponse{})

	intermediateOutOfOrder := intermediateResponseWire(t,
		implicit(t, 1, nil),
		implicit(t, 0, []byte("1.2.3")),
	)
	requireDecodeError(t, intermediateOutOfOrder, &rfc4511.IntermediateResponse{})
}

func TestExtendedTypesPreserveTrailingExtensions(t *testing.T) {
	extension := implicit(t, 5, []byte{0x7f})
	tests := []struct {
		name    string
		encoded []byte
		decode  func([]byte) ([]byte, int)
	}{
		{"request", extendedRequestWire(t, implicit(t, 0, []byte("1.2.3")), extension), func(encoded []byte) ([]byte, int) {
			var got rfc4511.ExtendedRequest
			decode(t, encoded, &got)
			reencoded, err := got.AppendBER(nil)
			require.NoError(t, err)
			return reencoded, len(got.Extensions)
		}},
		{"response", extendedResponseWire(t, extension), func(encoded []byte) ([]byte, int) {
			var got rfc4511.ExtendedResponse
			decode(t, encoded, &got)
			reencoded, err := got.AppendBER(nil)
			require.NoError(t, err)
			return reencoded, len(got.Extensions)
		}},
		{"intermediate", intermediateResponseWire(t, extension), func(encoded []byte) ([]byte, int) {
			var got rfc4511.IntermediateResponse
			decode(t, encoded, &got)
			reencoded, err := got.AppendBER(nil)
			require.NoError(t, err)
			return reencoded, len(got.Extensions)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reencoded, extensionCount := test.decode(test.encoded)
			assert.Equal(t, 1, extensionCount)
			assert.Equal(t, test.encoded, reencoded)
		})
	}
}

func TestNoticeOfDisconnectionOID(t *testing.T) {
	assert.Equal(t, rfc4511.LDAPOID("1.3.6.1.4.1.1466.20036"), rfc4511.NoticeOfDisconnectionOID())
}

func implicit(t *testing.T, number uint32, value []byte) []byte {
	t.Helper()
	encoded, err := ber.AppendPrimitive(nil, ber.Identifier{Class: ber.ClassContextSpecific, Number: number}, value)
	require.NoError(t, err)
	return encoded
}

func extendedRequestWire(t *testing.T, fields ...[]byte) []byte {
	t.Helper()
	return constructedFields(t, rfc4511.ExtendedRequestIdentifier(), nil, fields...)
}

func extendedResponseWire(t *testing.T, fields ...[]byte) []byte {
	t.Helper()
	prefix := []byte{0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
	return constructedFields(t, rfc4511.ExtendedResponseIdentifier(), prefix, fields...)
}

func intermediateResponseWire(t *testing.T, fields ...[]byte) []byte {
	t.Helper()
	return constructedFields(t, rfc4511.IntermediateResponseIdentifier(), nil, fields...)
}

func constructedFields(t *testing.T, id ber.Identifier, prefix []byte, fields ...[]byte) []byte {
	t.Helper()
	contents := append([]byte(nil), prefix...)
	for _, field := range fields {
		contents = append(contents, field...)
	}
	encoded, err := ber.AppendConstructed(nil, id, contents)
	require.NoError(t, err)
	return encoded
}

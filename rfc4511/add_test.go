package rfc4511_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestAddRequestRoundTripsAttributesAndCopiesValues(t *testing.T) {
	request := &rfc4511.AddRequest{
		Entry: rfc4511.LDAPDN("cn=Jane,dc=example,dc=com"),
		Attributes: []rfc4511.Attribute{
			{
				Type: rfc4511.AttributeDescription("objectClass"),
				Values: []rfc4511.AttributeValue{
					rfc4511.AttributeValue("top"),
					rfc4511.AttributeValue("person"),
				},
			},
			{
				Type:   rfc4511.AttributeDescription("jpegPhoto"),
				Values: []rfc4511.AttributeValue{{0x00, 0xff, 0x80}, {}},
			},
		},
	}

	encoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	var decoded rfc4511.AddRequest
	decode(t, encoded, &decoded)
	assert.Equal(t, *request, decoded)
	element, err := ber.DecodeElement(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	assert.Equal(t, rfc4511.AddRequestIdentifier(), element.Identifier)

	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, "cn=Jane,dc=example,dc=com", string(decoded.Entry))
	assert.Equal(t, rfc4511.AttributeValue{0x00, 0xff, 0x80}, decoded.Attributes[1].Values[0])
}

func TestAddRequestRejectsInvalidAttributeAtomically(t *testing.T) {
	dst := []byte{0xde, 0xad}
	request := &rfc4511.AddRequest{
		Attributes: []rfc4511.Attribute{{Type: rfc4511.AttributeDescription("cn")}},
	}
	got, err := request.AppendBER(dst)
	require.Error(t, err)
	assert.Equal(t, dst, got)

	prior := rfc4511.AddRequest{Entry: rfc4511.LDAPDN("cn=keep")}
	malformed := []byte{0x68, 0x09, 0x04, 0x00, 0x30, 0x05, 0x30, 0x03, 0x04, 0x01, 'c'}
	r, err := ber.NewReader(malformed, ber.DefaultLimits())
	require.NoError(t, err)
	require.Error(t, prior.UnmarshalBER(r))
	assert.Equal(t, "cn=keep", string(prior.Entry))
}

func TestAddResponsePreservesUnknownResultCode(t *testing.T) {
	encoded := []byte{0x69, 0x0c, 0x0a, 0x01, 0x46, 0x04, 0x00, 0x04, 0x05, 't', 'a', 'k', 'e', 'n'}
	r, err := ber.NewReader(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	var response rfc4511.AddResponse
	require.NoError(t, response.UnmarshalBER(r))
	assert.Equal(t, rfc4511.ResultCode(70), response.Result.ResultCode)
	assert.Equal(t, "taken", string(response.Result.DiagnosticMessage))
	roundTrip, err := response.AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, encoded, roundTrip)
}

func TestAddResponseReferralValidationAndReceiverAtomicity(t *testing.T) {
	dst := []byte{0xde, 0xad}
	response := rfc4511.AddResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultReferral}}
	got, err := response.AppendBER(dst)
	require.Error(t, err)
	assert.Equal(t, dst, got)

	prior := rfc4511.AddResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}}
	malformed := []byte{0x69, 0x07, 0x0a, 0x01, 0x0a, 0x04, 0x00, 0x04, 0x00}
	r, err := ber.NewReader(malformed, ber.DefaultLimits())
	require.NoError(t, err)
	require.Error(t, prior.UnmarshalBER(r))
	assert.Equal(t, rfc4511.ResultSuccess, prior.Result.ResultCode)
}

func TestAddRequestPreservesTrailingExtension(t *testing.T) {
	encoded := []byte{
		0x68, 0x13,
		0x04, 0x00,
		0x30, 0x0c,
		0x30, 0x0a, 0x04, 0x02, 'c', 'n', 0x31, 0x04, 0x04, 0x02, 'j', 's',
		0x83, 0x01, 0x7f,
	}
	r, err := ber.NewReader(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	var request rfc4511.AddRequest
	require.NoError(t, request.UnmarshalBER(r))
	require.Len(t, request.Extensions, 1)
	assert.Equal(t, ber.Identifier{Class: ber.ClassContextSpecific, Number: 3}, request.Extensions[0].Identifier())
	assert.Equal(t, []byte{0x83, 0x01, 0x7f}, request.Extensions[0].Bytes())
	roundTrip, err := request.AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, encoded, roundTrip)
}

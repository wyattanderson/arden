package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestAddRequestRoundTripsAttributesAndCopiesValues(t *testing.T) {
	request := &AddRequest{
		Entry: LDAPDN("cn=Jane,dc=example,dc=com"),
		Attributes: []Attribute{
			{
				Type: AttributeDescription("objectClass"),
				Values: []AttributeValue{
					AttributeValue("top"),
					AttributeValue("person"),
				},
			},
			{
				Type:   AttributeDescription("jpegPhoto"),
				Values: []AttributeValue{{0x00, 0xff, 0x80}, {}},
			},
		},
	}

	encoded := request.BERPacket().Encode()
	var decoded AddRequest
	decode(t, encoded, &decoded)
	assert.Equal(t, *request, decoded)
	element, err := ber.DecodeElement(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	assert.Equal(t, AddRequestIdentifier(), element.Identifier)

	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, "cn=Jane,dc=example,dc=com", string(decoded.Entry))
	assert.Equal(t, AttributeValue{0x00, 0xff, 0x80}, decoded.Attributes[1].Values[0])
}

func TestAddRequestRejectsInvalidAttributeAtomically(t *testing.T) {
	request := &AddRequest{
		Attributes: []Attribute{
			{Type: AttributeDescription("objectClass"), Values: []AttributeValue{AttributeValue("person")}},
			{Type: AttributeDescription("cn")},
		},
	}
	prior := AddRequest{Entry: LDAPDN("cn=keep")}
	requireDecodeError(t, request.BERPacket().Encode(), &prior)
	assert.Equal(t, "cn=keep", string(prior.Entry))
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
	var response AddResponse
	require.NoError(t, response.UnmarshalBER(r))
	assert.Equal(t, ResultCode(70), response.Result.ResultCode)
	assert.Equal(t, "taken", string(response.Result.DiagnosticMessage))
	roundTrip := response.BERPacket().Encode()
	assert.Equal(t, encoded, roundTrip)
}

func TestAddResponseReferralValidationAndReceiverAtomicity(t *testing.T) {
	response := AddResponse{Result: LDAPResult{ResultCode: ResultReferral}}
	prior := AddResponse{Result: LDAPResult{ResultCode: ResultSuccess}}
	requireDecodeError(t, response.BERPacket().Encode(), &prior)
	assert.Equal(t, ResultSuccess, prior.Result.ResultCode)
	malformed := []byte{0x69, 0x07, 0x0a, 0x01, 0x0a, 0x04, 0x00, 0x04, 0x00}
	r, err := ber.NewReader(malformed, ber.DefaultLimits())
	require.NoError(t, err)
	require.Error(t, prior.UnmarshalBER(r))
	assert.Equal(t, ResultSuccess, prior.Result.ResultCode)
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
	var request AddRequest
	require.NoError(t, request.UnmarshalBER(r))
	require.Len(t, request.Extensions, 1)
	assert.Equal(t, ber.Identifier{Class: ber.ClassContextSpecific, Number: 3}, request.Extensions[0].Identifier())
	assert.Equal(t, []byte{0x83, 0x01, 0x7f}, request.Extensions[0].Bytes())
	roundTrip := request.BERPacket().Encode()
	assert.Equal(t, encoded, roundTrip)
}

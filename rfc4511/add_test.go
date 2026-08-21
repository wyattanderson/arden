package rfc4511_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestAddRequestWireRoundTrip(t *testing.T) {
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

	encoded, err := request.AppendBER([]byte{0xaa})
	require.NoError(t, err)
	want := []byte{
		0x68, 0x51,
		0x04, 0x19, 'c', 'n', '=', 'J', 'a', 'n', 'e', ',', 'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
		0x30, 0x34,
		0x30, 0x1c, 0x04, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's', 0x31, 0x0d, 0x04, 0x03, 't', 'o', 'p', 0x04, 0x06, 'p', 'e', 'r', 's', 'o', 'n',
		0x30, 0x14, 0x04, 0x09, 'j', 'p', 'e', 'g', 'P', 'h', 'o', 't', 'o', 0x31, 0x07, 0x04, 0x03, 0x00, 0xff, 0x80, 0x04, 0x00,
	}
	assert.Equal(t, append([]byte{0xaa}, want...), encoded)

	r, err := ber.NewReader(want, ber.DefaultLimits())
	require.NoError(t, err)
	var decoded rfc4511.AddRequest
	require.NoError(t, decoded.UnmarshalBER(r))
	require.NoError(t, r.RequireEmpty())
	assert.Equal(t, *request, decoded)

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
	assert.Error(t, err)
	assert.Equal(t, dst, got)

	prior := rfc4511.AddRequest{Entry: rfc4511.LDAPDN("cn=keep")}
	malformed := []byte{0x68, 0x09, 0x04, 0x00, 0x30, 0x05, 0x30, 0x03, 0x04, 0x01, 'c'}
	r, err := ber.NewReader(malformed, ber.DefaultLimits())
	require.NoError(t, err)
	assert.Error(t, prior.UnmarshalBER(r))
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
	assert.Error(t, err)
	assert.Equal(t, dst, got)

	prior := rfc4511.AddResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}}
	malformed := []byte{0x69, 0x07, 0x0a, 0x01, 0x0a, 0x04, 0x00, 0x04, 0x00}
	r, err := ber.NewReader(malformed, ber.DefaultLimits())
	require.NoError(t, err)
	assert.Error(t, prior.UnmarshalBER(r))
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

func TestNewAddOperationUsesStandardPatternAndClonesControlSlice(t *testing.T) {
	controls := []ber.Marshaler{rawControl{}}
	op, err := rfc4511.NewAddOperation(&rfc4511.AddRequest{}, controls)
	require.NoError(t, err)
	controls[0] = nil
	assert.NoError(t, op.Validate())
	assert.Equal(t, arden.CancelDrain, op.Cancellation)
	assert.Equal(t, "ldap.add", op.Metadata.Label)
	assert.Equal(t, arden.ClassificationComplete, op.Responses.Classify(rfc4511.AddResponseIdentifier()))
}

type rawControl struct{}

func (rawControl) AppendBER(dst []byte) ([]byte, error) { return append(dst, 0x30, 0x00), nil }

func TestRFCAndExtensionContractsArePublic(t *testing.T) {
	var _ arden.ProtocolOperation = (*rfc4511.AddRequest)(nil)
	var _ ber.Unmarshaler = (*rfc4511.AddResponse)(nil)
	var _ ber.Marshaler = rfc4511.Attribute{}

	_, err := rfc4511.NewAddOperation(nil, nil)
	assert.EqualError(t, err, "rfc4511: nil AddRequest")
}

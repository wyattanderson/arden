package rfc4511_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestPrimitiveOperationWireTags(t *testing.T) {
	deleteEncoded, err := (&rfc4511.DeleteRequest{Entry: rfc4511.LDAPDN("cn=Jane")}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x4a, 0x07, 'c', 'n', '=', 'J', 'a', 'n', 'e'}, deleteEncoded)
	var deleteRequest rfc4511.DeleteRequest
	decode(t, deleteEncoded, &deleteRequest)
	assert.Equal(t, "cn=Jane", string(deleteRequest.Entry))

	abandonEncoded, err := (&rfc4511.AbandonRequest{Target: 9}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x50, 0x01, 0x09}, abandonEncoded)
	var abandonRequest rfc4511.AbandonRequest
	decode(t, abandonEncoded, &abandonRequest)
	assert.Equal(t, arden.MessageID(9), abandonRequest.Target)

	unbindEncoded, err := (&rfc4511.UnbindRequest{}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x42, 0x00}, unbindEncoded)
	decode(t, unbindEncoded, &rfc4511.UnbindRequest{})
	requireDecodeError(t, []byte{0x42, 0x01, 0x00}, &rfc4511.UnbindRequest{})
}

func TestAbandonRequestTargetBoundariesAreAtomic(t *testing.T) {
	for _, target := range []arden.MessageID{1, arden.MaxMessageID} {
		_, err := (&rfc4511.AbandonRequest{Target: target}).AppendBER(nil)
		assert.NoError(t, err)
	}
	for _, target := range []arden.MessageID{0, -1} {
		dst := []byte{0xde, 0xad}
		got, err := (&rfc4511.AbandonRequest{Target: target}).AppendBER(dst)
		assert.Error(t, err)
		assert.Equal(t, dst, got)
	}

	encoded, err := ber.AppendIntegerWithIdentifier(nil, rfc4511.AbandonRequestIdentifier(), 0)
	require.NoError(t, err)
	prior := rfc4511.AbandonRequest{Target: 7}
	requireDecodeError(t, encoded, &prior)
	assert.Equal(t, arden.MessageID(7), prior.Target)
}

func TestModifyPreservesExtensibleOperationValue(t *testing.T) {
	request := &rfc4511.ModifyRequest{
		Object: rfc4511.LDAPDN("cn=Jane"),
		Changes: []rfc4511.Change{{
			Operation: rfc4511.ModifyOperation(99),
			Modification: rfc4511.PartialAttribute{
				Type:   rfc4511.AttributeDescription("description"),
				Values: []rfc4511.AttributeValue{rfc4511.AttributeValue("updated")},
			},
		}},
	}
	encoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	var got rfc4511.ModifyRequest
	decode(t, encoded, &got)
	assert.Equal(t, *request, got)
}

func TestModifyDNOptionalNewSuperiorAndDuplicateRejection(t *testing.T) {
	superior := rfc4511.LDAPDN("ou=people,dc=example")
	for _, request := range []rfc4511.ModifyDNRequest{
		{Entry: rfc4511.LDAPDN("cn=Jane"), NewRDN: rfc4511.RelativeLDAPDN("cn=Janet")},
		{Entry: rfc4511.LDAPDN("cn=Jane"), NewRDN: rfc4511.RelativeLDAPDN("cn=Janet"), DeleteOldRDN: true, NewSuperior: &superior},
	} {
		encoded, err := request.AppendBER(nil)
		require.NoError(t, err)
		var got rfc4511.ModifyDNRequest
		decode(t, encoded, &got)
		assert.Equal(t, request, got)
	}

	contents, err := ber.AppendOctetString(nil, []byte("cn=Jane"))
	require.NoError(t, err)
	contents, err = ber.AppendOctetString(contents, []byte("cn=Janet"))
	require.NoError(t, err)
	contents, err = ber.AppendBoolean(contents, true)
	require.NoError(t, err)
	newSuperiorID := ber.Identifier{Class: ber.ClassContextSpecific, Number: 0}
	contents, err = ber.AppendPrimitive(contents, newSuperiorID, []byte("ou=one"))
	require.NoError(t, err)
	contents, err = ber.AppendPrimitive(contents, newSuperiorID, []byte("ou=two"))
	require.NoError(t, err)
	encoded, err := ber.AppendConstructed(nil, rfc4511.ModifyDNRequestIdentifier(), contents)
	require.NoError(t, err)
	requireDecodeError(t, encoded, &rfc4511.ModifyDNRequest{})
}

func TestCompareRequestRejectsEmptyAssertionTypeAtomically(t *testing.T) {
	request := &rfc4511.CompareRequest{Entry: rfc4511.LDAPDN("cn=Jane"), Assertion: rfc4511.AttributeValueAssertion{Value: rfc4511.AssertionValue("Jane")}}
	dst := []byte{0xde, 0xad}
	got, err := request.AppendBER(dst)
	assert.Error(t, err)
	assert.Equal(t, dst, got)
}

func TestCommonResultResponsesPreserveUnknownCode(t *testing.T) {
	result := rfc4511.LDAPResult{ResultCode: rfc4511.ResultCode(70), DiagnosticMessage: rfc4511.LDAPString("extension-defined")}
	tests := []struct {
		name string
		in   ber.Marshaler
		out  ber.Unmarshaler
	}{
		{"search", rfc4511.SearchResultDone{Result: result}, &rfc4511.SearchResultDone{}},
		{"modify", rfc4511.ModifyResponse{Result: result}, &rfc4511.ModifyResponse{}},
		{"delete", rfc4511.DeleteResponse{Result: result}, &rfc4511.DeleteResponse{}},
		{"modify DN", rfc4511.ModifyDNResponse{Result: result}, &rfc4511.ModifyDNResponse{}},
		{"compare", rfc4511.CompareResponse{Result: result}, &rfc4511.CompareResponse{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			roundTrip(t, test.in, test.out)
			switch got := test.out.(type) {
			case *rfc4511.SearchResultDone:
				assert.Equal(t, rfc4511.ResultCode(70), got.Result.ResultCode)
			case *rfc4511.ModifyResponse:
				assert.Equal(t, rfc4511.ResultCode(70), got.Result.ResultCode)
			case *rfc4511.DeleteResponse:
				assert.Equal(t, rfc4511.ResultCode(70), got.Result.ResultCode)
			case *rfc4511.ModifyDNResponse:
				assert.Equal(t, rfc4511.ResultCode(70), got.Result.ResultCode)
			case *rfc4511.CompareResponse:
				assert.Equal(t, rfc4511.ResultCode(70), got.Result.ResultCode)
			}
		})
	}
}

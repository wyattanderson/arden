package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

func TestPrimitiveOperationWireTags(t *testing.T) {
	deleteEncoded, err := (&DeleteRequest{Entry: LDAPDN("cn=Jane")}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x4a, 0x07, 'c', 'n', '=', 'J', 'a', 'n', 'e'}, deleteEncoded)
	var deleteRequest DeleteRequest
	decode(t, deleteEncoded, &deleteRequest)
	assert.Equal(t, "cn=Jane", string(deleteRequest.Entry))

	abandonEncoded, err := (&AbandonRequest{Target: 9}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x50, 0x01, 0x09}, abandonEncoded)
	var abandonRequest AbandonRequest
	decode(t, abandonEncoded, &abandonRequest)
	assert.Equal(t, protocol.MessageID(9), abandonRequest.Target)

	unbindEncoded, err := (&UnbindRequest{}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x42, 0x00}, unbindEncoded)
	decode(t, unbindEncoded, &UnbindRequest{})
	requireDecodeError(t, []byte{0x42, 0x01, 0x00}, &UnbindRequest{})
}

func TestAbandonRequestTargetBoundariesAreAtomic(t *testing.T) {
	for _, target := range []protocol.MessageID{1, protocol.MaxMessageID} {
		_, err := (&AbandonRequest{Target: target}).AppendBER(nil)
		require.NoError(t, err)
	}
	for _, target := range []protocol.MessageID{0, -1} {
		dst := []byte{0xde, 0xad}
		got, err := (&AbandonRequest{Target: target}).AppendBER(dst)
		require.Error(t, err)
		assert.Equal(t, dst, got)
	}

	encoded, err := ber.IntegerWithIdentifier(AbandonRequestIdentifier(), 0).AppendBER(nil)
	require.NoError(t, err)
	prior := AbandonRequest{Target: 7}
	requireDecodeError(t, encoded, &prior)
	assert.Equal(t, protocol.MessageID(7), prior.Target)
}

func TestModifyPreservesExtensibleOperationValue(t *testing.T) {
	request := &ModifyRequest{
		Object: LDAPDN("cn=Jane"),
		Changes: []Change{{
			Operation: ModifyOperation(99),
			Modification: PartialAttribute{
				Type:   AttributeDescription("description"),
				Values: []AttributeValue{AttributeValue("updated")},
			},
		}},
	}
	encoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	var got ModifyRequest
	decode(t, encoded, &got)
	assert.Equal(t, *request, got)
}

func TestModifyDNOptionalNewSuperiorAndDuplicateRejection(t *testing.T) {
	superior := LDAPDN("ou=people,dc=example")
	for _, request := range []ModifyDNRequest{
		{Entry: LDAPDN("cn=Jane"), NewRDN: RelativeLDAPDN("cn=Janet")},
		{Entry: LDAPDN("cn=Jane"), NewRDN: RelativeLDAPDN("cn=Janet"), DeleteOldRDN: true, NewSuperior: &superior},
	} {
		encoded, err := request.AppendBER(nil)
		require.NoError(t, err)
		var got ModifyDNRequest
		decode(t, encoded, &got)
		assert.Equal(t, request, got)
	}

	newSuperiorID := ber.Identifier{Class: ber.ClassContextSpecific, Number: 0}
	encoded, err := ber.Constructed(ModifyDNRequestIdentifier()).
		Add(
			ber.OctetString("cn=Jane"),
			ber.OctetString("cn=Janet"),
			ber.Boolean(true),
			ber.Primitive(newSuperiorID, []byte("ou=one")),
			ber.Primitive(newSuperiorID, []byte("ou=two")),
		).
		AppendBER(nil)
	require.NoError(t, err)
	requireDecodeError(t, encoded, &ModifyDNRequest{})
}

func TestCompareRequestRejectsEmptyAssertionTypeAtomically(t *testing.T) {
	request := &CompareRequest{Entry: LDAPDN("cn=Jane"), Assertion: AttributeValueAssertion{Value: AssertionValue("Jane")}}
	dst := []byte{0xde, 0xad}
	got, err := request.AppendBER(dst)
	require.Error(t, err)
	assert.Equal(t, dst, got)
}

func TestCommonResultResponsesPreserveUnknownCode(t *testing.T) {
	result := LDAPResult{ResultCode: ResultCode(70), DiagnosticMessage: LDAPString("extension-defined")}
	tests := []struct {
		name string
		in   ber.Marshaler
		out  ber.Unmarshaler
	}{
		{"search", SearchResultDone{Result: result}, &SearchResultDone{}},
		{"modify", ModifyResponse{Result: result}, &ModifyResponse{}},
		{"delete", DeleteResponse{Result: result}, &DeleteResponse{}},
		{"modify DN", ModifyDNResponse{Result: result}, &ModifyDNResponse{}},
		{"compare", CompareResponse{Result: result}, &CompareResponse{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			roundTrip(t, test.in, test.out)
			switch got := test.out.(type) {
			case *SearchResultDone:
				assert.Equal(t, ResultCode(70), got.Result.ResultCode)
			case *ModifyResponse:
				assert.Equal(t, ResultCode(70), got.Result.ResultCode)
			case *DeleteResponse:
				assert.Equal(t, ResultCode(70), got.Result.ResultCode)
			case *ModifyDNResponse:
				assert.Equal(t, ResultCode(70), got.Result.ResultCode)
			case *CompareResponse:
				assert.Equal(t, ResultCode(70), got.Result.ResultCode)
			}
		})
	}
}

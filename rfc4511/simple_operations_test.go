package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/protocol"
)

func TestPrimitiveOperationWireTags(t *testing.T) {
	deleteEncoded := (&DeleteRequest{Entry: LDAPDN("cn=Jane")}).BERPacket().Encode()
	assert.Equal(t, []byte{0x4a, 0x07, 'c', 'n', '=', 'J', 'a', 'n', 'e'}, deleteEncoded)
	var deleteRequest DeleteRequest
	decode(t, deleteEncoded, &deleteRequest)
	assert.Equal(t, "cn=Jane", string(deleteRequest.Entry))

	abandonEncoded := (&AbandonRequest{Target: 9}).BERPacket().Encode()
	assert.Equal(t, []byte{0x50, 0x01, 0x09}, abandonEncoded)
	var abandonRequest AbandonRequest
	decode(t, abandonEncoded, &abandonRequest)
	assert.Equal(t, protocol.MessageID(9), abandonRequest.Target)

	unbindEncoded := (&UnbindRequest{}).BERPacket().Encode()
	assert.Equal(t, []byte{0x42, 0x00}, unbindEncoded)
	decode(t, unbindEncoded, &UnbindRequest{})
	requireDecodeError(t, []byte{0x42, 0x01, 0x00}, &UnbindRequest{})
}

func TestAbandonRequestTargetBoundariesAreAtomic(t *testing.T) {
	for _, target := range []protocol.MessageID{1, protocol.MaxMessageID} {
		encoded := (&AbandonRequest{Target: target}).BERPacket().Encode()
		var got AbandonRequest
		decode(t, encoded, &got)
		assert.Equal(t, target, got.Target)
	}
	for _, target := range []protocol.MessageID{0, -1} {
		encoded := (&AbandonRequest{Target: target}).BERPacket().Encode()
		prior := AbandonRequest{Target: 7}
		requireDecodeError(t, encoded, &prior)
		assert.Equal(t, protocol.MessageID(7), prior.Target)
	}

	encoded := ber.IntegerWithIdentifier(AbandonRequestIdentifier(), 0).Encode()
	prior := AbandonRequest{Target: 7}
	requireDecodeError(t, encoded, &prior)
	assert.Equal(t, protocol.MessageID(7), prior.Target)
}

func TestModifyPreservesExtensibleOperationValue(t *testing.T) {
	request := &ModifyRequest{
		Object: LDAPDN("cn=Jane"),
		Changes: []Change{{
			Operation: ModifyOperation(99),
			Modification: Attribute{
				Type:   AttributeDescription("description"),
				Values: []AttributeValue{AttributeValue("updated")},
			},
		}},
	}
	encoded := request.BERPacket().Encode()
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
		encoded := request.BERPacket().Encode()
		var got ModifyDNRequest
		decode(t, encoded, &got)
		assert.Equal(t, request, got)
	}

	newSuperiorID := ber.Identifier{Class: ber.ClassContextSpecific, Number: 0}
	encoded := ber.Constructed(ModifyDNRequestIdentifier()).
		Add(
			ber.OctetString("cn=Jane"),
			ber.OctetString("cn=Janet"),
			ber.Boolean(true),
			ber.Primitive(newSuperiorID, []byte("ou=one")),
			ber.Primitive(newSuperiorID, []byte("ou=two")),
		).
		BERPacket().Encode()
	requireDecodeError(t, encoded, &ModifyDNRequest{})
}

func TestCompareRequestRejectsEmptyAssertionTypeAtomically(t *testing.T) {
	request := &CompareRequest{Entry: LDAPDN("cn=Jane"), Assertion: AttributeValueAssertion{Value: AssertionValue("Jane")}}
	prior := CompareRequest{Entry: LDAPDN("cn=keep")}
	requireDecodeError(t, request.BERPacket().Encode(), &prior)
	assert.Equal(t, LDAPDN("cn=keep"), prior.Entry)
}

func TestCommonResultResponsesPreserveUnknownCode(t *testing.T) {
	result := LDAPResult{ResultCode: ResultCode(70), DiagnosticMessage: LDAPString("extension-defined")}
	tests := []struct {
		name string
		in   ber.Packeter
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

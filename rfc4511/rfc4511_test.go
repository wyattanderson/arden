package rfc4511_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestRFC4511CodecRoundTrips(t *testing.T) {
	newSuperior := rfc4511.LDAPDN("ou=people,dc=example,dc=com")
	matchingRule := rfc4511.MatchingRuleID("caseIgnoreMatch")
	attributeType := rfc4511.AttributeDescription("cn")
	initial := rfc4511.AssertionValue("ja")
	final := rfc4511.AssertionValue("ne")
	result := rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}
	partial := rfc4511.PartialAttribute{Type: rfc4511.AttributeDescription("description"), Values: []rfc4511.AttributeValue{nil}}

	for _, test := range []struct {
		name string
		in   ber.Marshaler
		out  ber.Unmarshaler
	}{
		{"control", rfc4511.Control{Type: rfc4511.LDAPOID("1.2.3"), Criticality: true, Value: []byte{}, HasValue: true}, &rfc4511.Control{}},
		{"assertion", rfc4511.AttributeValueAssertion{Type: rfc4511.AttributeDescription("cn"), Value: rfc4511.AssertionValue{0, 0xff}}, &rfc4511.AttributeValueAssertion{}},
		{"bind simple", &rfc4511.BindRequest{Version: 3, Name: rfc4511.LDAPDN("cn=admin"), Authentication: rfc4511.SimpleAuthentication("secret")}, &rfc4511.BindRequest{}},
		{"bind sasl", &rfc4511.BindRequest{Version: 3, Authentication: rfc4511.SASLAuthentication{Mechanism: rfc4511.LDAPString("GSSAPI"), HasCredentials: true, Credentials: []byte{0, 1}}}, &rfc4511.BindRequest{}},
		{"bind response", rfc4511.BindResponse{Result: result, ServerSASLCredentials: []byte{}, HasServerSASLCredentials: true}, &rfc4511.BindResponse{}},
		{"unbind", &rfc4511.UnbindRequest{}, &rfc4511.UnbindRequest{}},
		{"and", rfc4511.And{Filters: []rfc4511.Filter{rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}}, &rfc4511.And{}},
		{"or", rfc4511.Or{Filters: []rfc4511.Filter{rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}}, &rfc4511.Or{}},
		{"not", rfc4511.Not{Filter: rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}, &rfc4511.Not{}},
		{"equality", rfc4511.EqualityMatch{Assertion: rfc4511.AttributeValueAssertion{Type: rfc4511.AttributeDescription("cn"), Value: rfc4511.AssertionValue("Jane")}}, &rfc4511.EqualityMatch{}},
		{"greater", rfc4511.GreaterOrEqual{Assertion: rfc4511.AttributeValueAssertion{Type: rfc4511.AttributeDescription("uidNumber"), Value: rfc4511.AssertionValue("100")}}, &rfc4511.GreaterOrEqual{}},
		{"less", rfc4511.LessOrEqual{Assertion: rfc4511.AttributeValueAssertion{Type: rfc4511.AttributeDescription("uidNumber"), Value: rfc4511.AssertionValue("200")}}, &rfc4511.LessOrEqual{}},
		{"present", rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}, &rfc4511.Present{}},
		{"approximate", rfc4511.ApproximateMatch{Assertion: rfc4511.AttributeValueAssertion{Type: rfc4511.AttributeDescription("cn"), Value: rfc4511.AssertionValue("Jane")}}, &rfc4511.ApproximateMatch{}},
		{"substring", rfc4511.SubstringFilter{Type: rfc4511.AttributeDescription("cn"), Initial: &initial, Any: []rfc4511.AssertionValue{rfc4511.AssertionValue("a")}, Final: &final}, &rfc4511.SubstringFilter{}},
		{"extensible", rfc4511.ExtensibleMatch{MatchingRule: &matchingRule, Type: &attributeType, MatchValue: rfc4511.AssertionValue("Jane"), DNAttributes: true}, &rfc4511.ExtensibleMatch{}},
		{"search", &rfc4511.SearchRequest{BaseObject: rfc4511.LDAPDN("dc=example,dc=com"), Scope: rfc4511.ScopeWholeSubtree, DerefAliases: rfc4511.DerefNever, SizeLimit: 100, TimeLimitSeconds: 5, Filter: rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}, Attributes: []rfc4511.AttributeSelector{rfc4511.AttributeSelector("cn")}}, &rfc4511.SearchRequest{}},
		{"search entry", rfc4511.SearchResultEntry{ObjectName: rfc4511.LDAPDN("cn=Jane"), Attributes: []rfc4511.PartialAttribute{partial}}, &rfc4511.SearchResultEntry{}},
		{"search reference", rfc4511.SearchResultReference{URIs: []rfc4511.URI{rfc4511.URI("ldap://example/dc=example,dc=com")}}, &rfc4511.SearchResultReference{}},
		{"search done", rfc4511.SearchResultDone{Result: result}, &rfc4511.SearchResultDone{}},
		{"modify", &rfc4511.ModifyRequest{Object: rfc4511.LDAPDN("cn=Jane"), Changes: []rfc4511.Change{{Operation: rfc4511.ModifyReplace, Modification: partial}}}, &rfc4511.ModifyRequest{}},
		{"modify response", rfc4511.ModifyResponse{Result: result}, &rfc4511.ModifyResponse{}},
		{"delete", &rfc4511.DeleteRequest{Entry: rfc4511.LDAPDN("cn=Jane")}, &rfc4511.DeleteRequest{}},
		{"delete response", rfc4511.DeleteResponse{Result: result}, &rfc4511.DeleteResponse{}},
		{"modify dn", &rfc4511.ModifyDNRequest{Entry: rfc4511.LDAPDN("cn=Jane"), NewRDN: rfc4511.RelativeLDAPDN("cn=Janet"), DeleteOldRDN: true, NewSuperior: &newSuperior}, &rfc4511.ModifyDNRequest{}},
		{"modify dn response", rfc4511.ModifyDNResponse{Result: result}, &rfc4511.ModifyDNResponse{}},
		{"compare", &rfc4511.CompareRequest{Entry: rfc4511.LDAPDN("cn=Jane"), Assertion: rfc4511.AttributeValueAssertion{Type: rfc4511.AttributeDescription("cn"), Value: rfc4511.AssertionValue("Jane")}}, &rfc4511.CompareRequest{}},
		{"compare response", rfc4511.CompareResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultCompareTrue}}, &rfc4511.CompareResponse{}},
		{"abandon", &rfc4511.AbandonRequest{Target: 9}, &rfc4511.AbandonRequest{}},
		{"extended request", &rfc4511.ExtendedRequest{Name: rfc4511.LDAPOID("1.3.6.1.4.1.1466.20037"), Value: []byte{}, HasValue: true}, &rfc4511.ExtendedRequest{}},
		{"extended response", rfc4511.ExtendedResponse{Result: result, ResponseName: rfc4511.LDAPOID("1.2.3"), HasResponseName: true, ResponseValue: []byte{}, HasResponseValue: true}, &rfc4511.ExtendedResponse{}},
		{"intermediate response", rfc4511.IntermediateResponse{ResponseName: rfc4511.LDAPOID("1.2.3"), HasResponseName: true, ResponseValue: []byte{0, 0xff}, HasResponseValue: true}, &rfc4511.IntermediateResponse{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			roundTrip(t, test.in, test.out)
		})
	}

}

func TestFilterWireSpecialCasesAndExternalAlternative(t *testing.T) {
	present, err := (rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x87, 0x02, 'c', 'n'}, present)

	equality, err := (rfc4511.EqualityMatch{Assertion: rfc4511.AttributeValueAssertion{Type: rfc4511.AttributeDescription("cn")}}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa3, 0x06, 0x04, 0x02, 'c', 'n', 0x04, 0x00}, equality)

	// RFC 4511 section 4.5.1.7: NOT carries the complete child Filter under
	// context-specific constructed tag [2]. This vector covers erratum 5292's
	// disputed tagging shape without introducing a compatibility exception.
	not, err := (rfc4511.Not{Filter: rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa2, 0x04, 0x87, 0x02, 'c', 'n'}, not)

	request := &rfc4511.SearchRequest{Filter: externalFilter{}}
	encoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	r, err := ber.NewReader(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	var decoded rfc4511.SearchRequest
	require.NoError(t, decoded.UnmarshalBER(r))
	unknown, ok := decoded.Filter.(rfc4511.UnknownFilter)
	require.True(t, ok)
	assert.Equal(t, externalFilterIdentifier, unknown.FilterIdentifier())
	assert.Equal(t, []byte{0xbf, 0x2a, 0x00}, unknown.Raw())
}

func TestSearchPatternsAndOperationPolicies(t *testing.T) {
	search, err := rfc4511.NewSearchOperation(&rfc4511.SearchRequest{Filter: rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}, nil)
	require.NoError(t, err)
	assert.Equal(t, arden.CancelAbandon, search.Cancellation)
	for _, test := range []struct {
		name string
		id   ber.Identifier
		want arden.Classification
	}{
		{"entry", rfc4511.SearchResultEntryIdentifier(), arden.ClassificationContinue},
		{"reference", rfc4511.SearchResultReferenceIdentifier(), arden.ClassificationContinue},
		{"done", rfc4511.SearchResultDoneIdentifier(), arden.ClassificationComplete},
		{"unrelated", rfc4511.AddResponseIdentifier(), arden.ClassificationInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, search.Responses.Classify(test.id))
		})
	}

	extended, err := rfc4511.NewExtendedOperation(&rfc4511.ExtendedRequest{Name: rfc4511.LDAPOID("1.2.3")}, nil)
	require.NoError(t, err)
	assert.Equal(t, arden.ClassificationContinue, extended.Responses.Classify(rfc4511.IntermediateResponseIdentifier()))
	assert.Equal(t, arden.ClassificationComplete, extended.Responses.Classify(rfc4511.ExtendedResponseIdentifier()))
}

func TestRFCReceiverAtomicityAndOwnership(t *testing.T) {
	prior := rfc4511.SearchRequest{BaseObject: rfc4511.LDAPDN("dc=keep"), Filter: rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}
	r, err := ber.NewReader([]byte{0x63, 0x00}, ber.DefaultLimits())
	require.NoError(t, err)
	assert.Error(t, prior.UnmarshalBER(r))
	assert.Equal(t, "dc=keep", string(prior.BaseObject))

	encoded, err := (&rfc4511.ExtendedResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}, ResponseValue: []byte{0, 0xff}, HasResponseValue: true}).AppendBER(nil)
	require.NoError(t, err)
	r, err = ber.NewReader(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	var decoded rfc4511.ExtendedResponse
	require.NoError(t, decoded.UnmarshalBER(r))
	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, []byte{0, 0xff}, decoded.ResponseValue)
}

func TestLDAPOIDValidation(t *testing.T) {
	for _, oid := range []rfc4511.LDAPOID{[]byte(""), []byte("1"), []byte("1."), []byte(".1"), []byte("1..2"), []byte("01.2"), []byte("1.a")} {
		_, err := oid.AppendBER([]byte{0xaa})
		assert.Error(t, err, "LDAPOID %q was accepted", oid)
	}
	_, err := rfc4511.LDAPOID([]byte("1.3.6.1.4.1.1466.20037")).AppendBER(nil)
	assert.NoError(t, err)
}

func TestRFC4511StructuralRejectionsPreserveDestinations(t *testing.T) {
	for _, value := range []ber.Marshaler{
		rfc4511.And{},
		rfc4511.Or{},
		rfc4511.Not{},
		rfc4511.SubstringFilter{Type: rfc4511.AttributeDescription("cn")},
		rfc4511.ExtensibleMatch{MatchValue: rfc4511.AssertionValue("x")},
		&rfc4511.SearchRequest{DerefAliases: 99, Filter: rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}},
		&rfc4511.AbandonRequest{Target: 0},
	} {
		dst := []byte{0xde, 0xad}
		got, err := value.AppendBER(dst)
		assert.Error(t, err, "%T unexpectedly encoded", value)
		assert.Equal(t, dst, got, "%T changed destination on error", value)
	}

	r, err := ber.NewReader([]byte{0xa2, 0x08, 0x87, 0x02, 'c', 'n', 0x87, 0x02, 's', 'n'}, ber.DefaultLimits())
	require.NoError(t, err)
	var not rfc4511.Not
	assert.Error(t, not.UnmarshalBER(r))

	r, err = ber.NewReader([]byte{0xa4, 0x0c, 0x04, 0x02, 'c', 'n', 0x30, 0x06, 0x80, 0x01, 'a', 0x80, 0x01, 'b'}, ber.DefaultLimits())
	require.NoError(t, err)
	var substring rfc4511.SubstringFilter
	assert.Error(t, substring.UnmarshalBER(r))

	control, err := (rfc4511.Control{Type: rfc4511.LDAPOID("1.2.3")}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x07, 0x04, 0x05, '1', '.', '2', '.', '3'}, control)
	assert.False(t, bytes.Contains(control, []byte{0x01, 0x01, 0x00}))
}

func roundTrip(t *testing.T, input ber.Marshaler, output ber.Unmarshaler) {
	t.Helper()
	encoded, err := input.AppendBER([]byte{0xa5})
	require.NoError(t, err)
	r, err := ber.NewReader(encoded[1:], ber.DefaultLimits())
	require.NoError(t, err)
	require.NoError(t, output.UnmarshalBER(r))
	require.NoError(t, r.RequireEmpty())
	roundTripped, err := output.(ber.Marshaler).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, encoded[1:], roundTripped)
}

var externalFilterIdentifier = ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: 42}

type externalFilter struct{}

func (externalFilter) FilterIdentifier() ber.Identifier { return externalFilterIdentifier }
func (externalFilter) AppendBER(dst []byte) ([]byte, error) {
	return ber.AppendConstructed(dst, externalFilterIdentifier, nil)
}

func TestPublicContracts(t *testing.T) {
	var _ rfc4511.Filter = externalFilter{}
	var _ arden.ProtocolOperation = (*rfc4511.ExtendedRequest)(nil)
	var _ ber.Marshaler = rfc4511.Control{}
	var _ ber.Unmarshaler = (*rfc4511.Control)(nil)

	assert.Equal(t, rfc4511.LDAPOID("1.3.6.1.4.1.1466.20036"), rfc4511.NoticeOfDisconnectionOID())
}

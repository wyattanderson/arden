package rfc4511

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestRFC4511CodecRoundTrips(t *testing.T) {
	newSuperior := LDAPDN("ou=people,dc=example,dc=com")
	matchingRule := MatchingRuleID("caseIgnoreMatch")
	attributeType := AttributeDescription("cn")
	initial := AssertionValue("ja")
	final := AssertionValue("ne")
	result := LDAPResult{ResultCode: ResultSuccess}
	partial := PartialAttribute{Type: AttributeDescription("description"), Values: []AttributeValue{nil}}

	for _, test := range []struct {
		name string
		in   ber.Marshaler
		out  ber.Unmarshaler
	}{
		{"control", Control{Type: LDAPOID("1.2.3"), Criticality: true, Value: []byte{}, HasValue: true}, &Control{}},
		{"assertion", AttributeValueAssertion{Type: AttributeDescription("cn"), Value: AssertionValue{0, 0xff}}, &AttributeValueAssertion{}},
		{"bind simple", &BindRequest{Version: 3, Name: LDAPDN("cn=admin"), Authentication: SimpleAuthentication("secret")}, &BindRequest{}},
		{"bind sasl", &BindRequest{Version: 3, Authentication: SASLAuthentication{Mechanism: LDAPString("GSSAPI"), HasCredentials: true, Credentials: []byte{0, 1}}}, &BindRequest{}},
		{"bind response", BindResponse{Result: result, ServerSASLCredentials: []byte{}, HasServerSASLCredentials: true}, &BindResponse{}},
		{"unbind", &UnbindRequest{}, &UnbindRequest{}},
		{"and", And{Filters: []Filter{Present{Attribute: AttributeDescription("cn")}}}, &And{}},
		{"or", Or{Filters: []Filter{Present{Attribute: AttributeDescription("cn")}}}, &Or{}},
		{"not", Not{Filter: Present{Attribute: AttributeDescription("cn")}}, &Not{}},
		{"equality", EqualityMatch{Assertion: AttributeValueAssertion{Type: AttributeDescription("cn"), Value: AssertionValue("Jane")}}, &EqualityMatch{}},
		{"greater", GreaterOrEqual{Assertion: AttributeValueAssertion{Type: AttributeDescription("uidNumber"), Value: AssertionValue("100")}}, &GreaterOrEqual{}},
		{"less", LessOrEqual{Assertion: AttributeValueAssertion{Type: AttributeDescription("uidNumber"), Value: AssertionValue("200")}}, &LessOrEqual{}},
		{"present", Present{Attribute: AttributeDescription("cn")}, &Present{}},
		{"approximate", ApproximateMatch{Assertion: AttributeValueAssertion{Type: AttributeDescription("cn"), Value: AssertionValue("Jane")}}, &ApproximateMatch{}},
		{"substring", SubstringFilter{Type: AttributeDescription("cn"), Initial: &initial, Any: []AssertionValue{AssertionValue("a")}, Final: &final}, &SubstringFilter{}},
		{"extensible", ExtensibleMatch{MatchingRule: &matchingRule, Type: &attributeType, MatchValue: AssertionValue("Jane"), DNAttributes: true}, &ExtensibleMatch{}},
		{"search", &SearchRequest{BaseObject: LDAPDN("dc=example,dc=com"), Scope: ScopeWholeSubtree, DerefAliases: DerefNever, SizeLimit: 100, TimeLimit: 5 * time.Second, Filter: Present{Attribute: AttributeDescription("cn")}, Attributes: []AttributeSelector{AttributeSelector("cn")}}, &SearchRequest{}},
		{"search entry", SearchResultEntry{ObjectName: LDAPDN("cn=Jane"), Attributes: []PartialAttribute{partial}}, &SearchResultEntry{}},
		{"search reference", SearchResultReference{URIs: []URI{URI("ldap://example/dc=example,dc=com")}}, &SearchResultReference{}},
		{"search done", SearchResultDone{Result: result}, &SearchResultDone{}},
		{"modify", &ModifyRequest{Object: LDAPDN("cn=Jane"), Changes: []Change{{Operation: ModifyReplace, Modification: partial}}}, &ModifyRequest{}},
		{"modify response", ModifyResponse{Result: result}, &ModifyResponse{}},
		{"delete", &DeleteRequest{Entry: LDAPDN("cn=Jane")}, &DeleteRequest{}},
		{"delete response", DeleteResponse{Result: result}, &DeleteResponse{}},
		{"modify dn", &ModifyDNRequest{Entry: LDAPDN("cn=Jane"), NewRDN: RelativeLDAPDN("cn=Janet"), DeleteOldRDN: true, NewSuperior: &newSuperior}, &ModifyDNRequest{}},
		{"modify dn response", ModifyDNResponse{Result: result}, &ModifyDNResponse{}},
		{"compare", &CompareRequest{Entry: LDAPDN("cn=Jane"), Assertion: AttributeValueAssertion{Type: AttributeDescription("cn"), Value: AssertionValue("Jane")}}, &CompareRequest{}},
		{"compare response", CompareResponse{Result: LDAPResult{ResultCode: ResultCompareTrue}}, &CompareResponse{}},
		{"abandon", &AbandonRequest{Target: 9}, &AbandonRequest{}},
		{"extended request", &ExtendedRequest{Name: LDAPOID("1.3.6.1.4.1.1466.20037"), Value: []byte{}, HasValue: true}, &ExtendedRequest{}},
		{"extended response", ExtendedResponse{Result: result, ResponseName: LDAPOID("1.2.3"), HasResponseName: true, ResponseValue: []byte{}, HasResponseValue: true}, &ExtendedResponse{}},
		{"intermediate response", IntermediateResponse{ResponseName: LDAPOID("1.2.3"), HasResponseName: true, ResponseValue: []byte{0, 0xff}, HasResponseValue: true}, &IntermediateResponse{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			roundTrip(t, test.in, test.out)
		})
	}

}

func TestFilterWireSpecialCasesAndExternalAlternative(t *testing.T) {
	present, err := (Present{Attribute: AttributeDescription("cn")}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x87, 0x02, 'c', 'n'}, present)

	equality, err := (EqualityMatch{Assertion: AttributeValueAssertion{Type: AttributeDescription("cn")}}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa3, 0x06, 0x04, 0x02, 'c', 'n', 0x04, 0x00}, equality)

	// RFC 4511 section 4.5.1.7: NOT carries the complete child Filter under
	// context-specific constructed tag [2]. This vector covers erratum 5292's
	// disputed tagging shape without introducing a compatibility exception.
	not, err := (Not{Filter: Present{Attribute: AttributeDescription("cn")}}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa2, 0x04, 0x87, 0x02, 'c', 'n'}, not)

	request := &SearchRequest{Filter: externalFilter{}}
	encoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	r, err := ber.NewReader(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	var decoded SearchRequest
	require.NoError(t, decoded.UnmarshalBER(r))
	unknown, ok := decoded.Filter.(UnknownFilter)
	require.True(t, ok)
	assert.Equal(t, externalFilterIdentifier, unknown.FilterIdentifier())
	assert.Equal(t, []byte{0xbf, 0x2a, 0x00}, unknown.Raw())
}

func TestRFCReceiverAtomicityAndOwnership(t *testing.T) {
	prior := SearchRequest{BaseObject: LDAPDN("dc=keep"), Filter: Present{Attribute: AttributeDescription("cn")}}
	r, err := ber.NewReader([]byte{0x63, 0x00}, ber.DefaultLimits())
	require.NoError(t, err)
	require.Error(t, prior.UnmarshalBER(r))
	assert.Equal(t, "dc=keep", string(prior.BaseObject))

	encoded, err := (&ExtendedResponse{Result: LDAPResult{ResultCode: ResultSuccess}, ResponseValue: []byte{0, 0xff}, HasResponseValue: true}).AppendBER(nil)
	require.NoError(t, err)
	r, err = ber.NewReader(encoded, ber.DefaultLimits())
	require.NoError(t, err)
	var decoded ExtendedResponse
	require.NoError(t, decoded.UnmarshalBER(r))
	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, []byte{0, 0xff}, decoded.ResponseValue)
}

func TestLDAPOIDValidation(t *testing.T) {
	for _, oid := range []LDAPOID{"", "1", "1.", ".1", "1..2", "01.2", "1.a"} {
		_, err := oid.AppendBER([]byte{0xaa})
		require.Error(t, err, "LDAPOID %q was accepted", oid)
	}
	_, err := LDAPOID("1.3.6.1.4.1.1466.20037").AppendBER(nil)
	require.NoError(t, err)
}

func TestRFC4511StructuralRejectionsPreserveDestinations(t *testing.T) {
	for _, value := range []ber.Marshaler{
		And{},
		Or{},
		Not{},
		SubstringFilter{Type: AttributeDescription("cn")},
		ExtensibleMatch{MatchValue: AssertionValue("x")},
		&SearchRequest{DerefAliases: 99, Filter: Present{Attribute: AttributeDescription("cn")}},
		&AbandonRequest{Target: 0},
	} {
		dst := []byte{0xde, 0xad}
		got, err := value.AppendBER(dst)
		require.Error(t, err, "%T unexpectedly encoded", value)
		assert.Equal(t, dst, got, "%T changed destination on error", value)
	}

	r, err := ber.NewReader([]byte{0xa2, 0x08, 0x87, 0x02, 'c', 'n', 0x87, 0x02, 's', 'n'}, ber.DefaultLimits())
	require.NoError(t, err)
	var not Not
	require.Error(t, not.UnmarshalBER(r))

	r, err = ber.NewReader([]byte{0xa4, 0x0c, 0x04, 0x02, 'c', 'n', 0x30, 0x06, 0x80, 0x01, 'a', 0x80, 0x01, 'b'}, ber.DefaultLimits())
	require.NoError(t, err)
	var substring SubstringFilter
	require.Error(t, substring.UnmarshalBER(r))

	control, err := (Control{Type: LDAPOID("1.2.3")}).AppendBER(nil)
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
func (externalFilter) BERPacket() ber.Packet {
	return ber.Constructed(externalFilterIdentifier).BERPacket()
}
func (externalFilter) AppendBER(dst []byte) ([]byte, error) {
	return (externalFilter{}).BERPacket().AppendBER(dst)
}

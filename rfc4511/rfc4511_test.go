package rfc4511_test

import (
	"bytes"
	"reflect"
	"testing"

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
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x87, 0x02, 'c', 'n'}; !bytes.Equal(present, want) {
		t.Fatalf("Present = %x, want %x", present, want)
	}

	equality, err := (rfc4511.EqualityMatch{Assertion: rfc4511.AttributeValueAssertion{Type: rfc4511.AttributeDescription("cn")}}).AppendBER(nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xa3, 0x06, 0x04, 0x02, 'c', 'n', 0x04, 0x00}; !bytes.Equal(equality, want) {
		t.Fatalf("EqualityMatch = %x, want %x", equality, want)
	}

	// RFC 4511 section 4.5.1.7: NOT carries the complete child Filter under
	// context-specific constructed tag [2]. This vector covers erratum 5292's
	// disputed tagging shape without introducing a compatibility exception.
	not, err := (rfc4511.Not{Filter: rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}).AppendBER(nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xa2, 0x04, 0x87, 0x02, 'c', 'n'}; !bytes.Equal(not, want) {
		t.Fatalf("Not = %x, want %x", not, want)
	}

	request := &rfc4511.SearchRequest{Filter: externalFilter{}}
	encoded, err := request.AppendBER(nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ber.NewReader(encoded, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var decoded rfc4511.SearchRequest
	if err := decoded.UnmarshalBER(r); err != nil {
		t.Fatal(err)
	}
	unknown, ok := decoded.Filter.(rfc4511.UnknownFilter)
	if !ok || unknown.FilterIdentifier() != externalFilterIdentifier {
		t.Fatalf("decoded external filter = %#v", decoded.Filter)
	}
	if !bytes.Equal(unknown.Raw(), []byte{0xbf, 0x2a, 0x00}) {
		t.Fatalf("unknown external filter raw = %x", unknown.Raw())
	}
}

func TestSearchPatternsAndOperationPolicies(t *testing.T) {
	search, err := rfc4511.NewSearchOperation(&rfc4511.SearchRequest{Filter: rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if search.Cancellation != arden.CancelAbandon {
		t.Fatalf("Search cancellation = %v", search.Cancellation)
	}
	for id, want := range map[ber.Identifier]arden.Classification{
		rfc4511.SearchResultEntryIdentifier():     arden.ClassificationContinue,
		rfc4511.SearchResultReferenceIdentifier(): arden.ClassificationContinue,
		rfc4511.SearchResultDoneIdentifier():      arden.ClassificationComplete,
		rfc4511.AddResponseIdentifier():           arden.ClassificationInvalid,
	} {
		if got := search.Responses.Classify(id); got != want {
			t.Fatalf("Search pattern %s = %v, want %v", id, got, want)
		}
	}

	extended, err := rfc4511.NewExtendedOperation(&rfc4511.ExtendedRequest{Name: rfc4511.LDAPOID("1.2.3")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if extended.Responses.Classify(rfc4511.IntermediateResponseIdentifier()) != arden.ClassificationContinue ||
		extended.Responses.Classify(rfc4511.ExtendedResponseIdentifier()) != arden.ClassificationComplete {
		t.Fatal("extended response pattern is not streaming then terminal")
	}
}

func TestRFCReceiverAtomicityAndOwnership(t *testing.T) {
	prior := rfc4511.SearchRequest{BaseObject: rfc4511.LDAPDN("dc=keep"), Filter: rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}
	r, err := ber.NewReader([]byte{0x63, 0x00}, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := prior.UnmarshalBER(r); err == nil {
		t.Fatal("malformed search was accepted")
	}
	if string(prior.BaseObject) != "dc=keep" {
		t.Fatalf("failed unmarshal changed receiver: %#v", prior)
	}

	encoded, err := (&rfc4511.ExtendedResponse{Result: rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess}, ResponseValue: []byte{0, 0xff}, HasResponseValue: true}).AppendBER(nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err = ber.NewReader(encoded, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var decoded rfc4511.ExtendedResponse
	if err := decoded.UnmarshalBER(r); err != nil {
		t.Fatal(err)
	}
	for i := range encoded {
		encoded[i] = 0
	}
	if !bytes.Equal(decoded.ResponseValue, []byte{0, 0xff}) {
		t.Fatalf("decoded response value aliases source: %x", decoded.ResponseValue)
	}
}

func TestLDAPOIDValidation(t *testing.T) {
	for _, oid := range []rfc4511.LDAPOID{[]byte(""), []byte("1"), []byte("1."), []byte(".1"), []byte("1..2"), []byte("01.2"), []byte("1.a")} {
		if _, err := oid.AppendBER([]byte{0xaa}); err == nil {
			t.Fatalf("LDAPOID %q was accepted", oid)
		}
	}
	if _, err := rfc4511.LDAPOID([]byte("1.3.6.1.4.1.1466.20037")).AppendBER(nil); err != nil {
		t.Fatalf("valid LDAPOID rejected: %v", err)
	}
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
		if err == nil {
			t.Fatalf("%T unexpectedly encoded", value)
		}
		if !bytes.Equal(got, dst) {
			t.Fatalf("%T changed destination on error: %x", value, got)
		}
	}

	r, err := ber.NewReader([]byte{0xa2, 0x08, 0x87, 0x02, 'c', 'n', 0x87, 0x02, 's', 'n'}, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var not rfc4511.Not
	if err := not.UnmarshalBER(r); err == nil {
		t.Fatal("NOT filter accepted two child filters")
	}

	r, err = ber.NewReader([]byte{0xa4, 0x0c, 0x04, 0x02, 'c', 'n', 0x30, 0x06, 0x80, 0x01, 'a', 0x80, 0x01, 'b'}, ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var substring rfc4511.SubstringFilter
	if err := substring.UnmarshalBER(r); err == nil {
		t.Fatal("substring filter accepted out-of-order duplicate initial parts")
	}

	control, err := (rfc4511.Control{Type: rfc4511.LDAPOID("1.2.3")}).AppendBER(nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x30, 0x07, 0x04, 0x05, '1', '.', '2', '.', '3'}; !bytes.Equal(control, want) {
		t.Fatalf("control encoding = %x, want %x", control, want)
	}
	if bytes.Contains(control, []byte{0x01, 0x01, 0x00}) {
		t.Fatal("default false control criticality was encoded")
	}
}

func roundTrip(t *testing.T, input ber.Marshaler, output ber.Unmarshaler) {
	t.Helper()
	encoded, err := input.AppendBER([]byte{0xa5})
	if err != nil {
		t.Fatal(err)
	}
	r, err := ber.NewReader(encoded[1:], ber.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := output.UnmarshalBER(r); err != nil {
		t.Fatal(err)
	}
	if err := r.RequireEmpty(); err != nil {
		t.Fatal(err)
	}
	roundTripped, err := output.(ber.Marshaler).AppendBER(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTripped, encoded[1:]) {
		t.Fatalf("round trip = %x, want %x\ndecoded = %#v", roundTripped, encoded[1:], output)
	}
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

	if !reflect.DeepEqual(rfc4511.NoticeOfDisconnectionOID(), rfc4511.LDAPOID("1.3.6.1.4.1.1466.20036")) {
		t.Fatal("notice OID changed")
	}
}

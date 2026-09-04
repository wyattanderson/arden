package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestFilterAlternativesDispatchToConcreteTypes(t *testing.T) {
	initial := AssertionValue("Ja")
	final := AssertionValue("ne")
	rule := MatchingRuleID("caseIgnoreMatch")
	typeValue := AttributeDescription("cn")
	assertion := AttributeValueAssertion{Type: AttributeDescription("cn"), Value: AssertionValue("Jane")}
	tests := []struct {
		name string
		in   Filter
		out  Filter
	}{
		{"and", And{Filters: []Filter{Present{Attribute: AttributeDescription("cn")}}}, And{}},
		{"or", Or{Filters: []Filter{Present{Attribute: AttributeDescription("cn")}}}, Or{}},
		{"not", Not{Filter: Present{Attribute: AttributeDescription("cn")}}, Not{}},
		{"equality", EqualityMatch{Assertion: assertion}, EqualityMatch{}},
		{"substrings", SubstringFilter{Type: typeValue, Initial: &initial, Any: []AssertionValue{AssertionValue("a")}, Final: &final}, SubstringFilter{}},
		{"greater or equal", GreaterOrEqual{Assertion: assertion}, GreaterOrEqual{}},
		{"less or equal", LessOrEqual{Assertion: assertion}, LessOrEqual{}},
		{"present", Present{Attribute: typeValue}, Present{}},
		{"approximate", ApproximateMatch{Assertion: assertion}, ApproximateMatch{}},
		{"extensible", ExtensibleMatch{MatchingRule: &rule, Type: &typeValue, MatchValue: AssertionValue("Jane"), DNAttributes: true}, ExtensibleMatch{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := &SearchRequest{Filter: test.in}
			encoded, err := request.AppendBER(nil)
			require.NoError(t, err)
			var got SearchRequest
			decode(t, encoded, &got)
			assert.IsType(t, test.out, got.Filter)
			reencoded, err := got.AppendBER(nil)
			require.NoError(t, err)
			assert.Equal(t, encoded, reencoded)
		})
	}
}

func TestFilterExtensionBoundary(t *testing.T) {
	unknownWire := []byte{0xbf, 0x2a, 0x00}
	requestWire := searchRequestWithFilter(t, unknownWire)
	var request SearchRequest
	decode(t, requestWire, &request)
	unknown, ok := request.Filter.(UnknownFilter)
	require.True(t, ok)
	assert.Equal(t, ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: 42}, unknown.FilterIdentifier())
	assert.Equal(t, unknownWire, unknown.Raw())
	reencoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, requestWire, reencoded)
}

func TestSubstringFilterOrderingRejections(t *testing.T) {
	context := func(number uint32, value string) ber.Packet {
		return ber.Primitive(ber.Identifier{Class: ber.ClassContextSpecific, Number: number}, []byte(value))
	}
	tests := [][]ber.Packet{
		{},
		{context(0, "a"), context(0, "b")},
		{context(2, "z"), context(1, "a")},
		{context(2, "z"), context(2, "x")},
	}
	for _, parts := range tests {
		encoded, err := ber.Constructed(ber.Identifier{Class: ber.ClassContextSpecific, Number: 4}).
			Add(ber.OctetString("cn")).
			Add(ber.Sequence().Add(parts...)).
			AppendBER(nil)
		require.NoError(t, err)
		requireDecodeError(t, encoded, &SubstringFilter{})
	}
}

func searchRequestWithFilter(t *testing.T, filter []byte) []byte {
	t.Helper()
	encoded, err := ber.Constructed(SearchRequestIdentifier()).
		Add(
			ber.OctetString([]byte(nil)),
			ber.Enumerated(0),
			ber.Enumerated(0),
			ber.Integer(0),
			ber.Integer(0),
			ber.Boolean(false),
		).
		Add(ber.Encoded(filter)).
		Add(ber.Sequence()).
		AppendBER(nil)
	require.NoError(t, err)
	return encoded
}

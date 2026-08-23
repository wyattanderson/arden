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

func TestFilterExtensionBoundaryAndDeclaredIdentifierValidation(t *testing.T) {
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

	for _, filter := range []Filter{
		badFilter{declared: ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 42}, encoded: unknownWire},
		badFilter{declared: ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: 41}, encoded: unknownWire},
	} {
		dst := []byte{0xde, 0xad}
		got, err := (&SearchRequest{Filter: filter}).AppendBER(dst)
		require.Error(t, err)
		assert.Equal(t, dst, got)
	}
}

func TestSubstringFilterOrderingRejections(t *testing.T) {
	typePrefix, err := ber.AppendOctetString(nil, []byte("cn"))
	require.NoError(t, err)
	context := func(number uint32, value string) []byte {
		encoded, appendErr := ber.AppendPrimitive(nil, ber.Identifier{Class: ber.ClassContextSpecific, Number: number}, []byte(value))
		require.NoError(t, appendErr)
		return encoded
	}
	tests := [][]byte{
		{},
		append(context(0, "a"), context(0, "b")...),
		append(context(2, "z"), context(1, "a")...),
		append(context(2, "z"), context(2, "x")...),
	}
	for _, parts := range tests {
		sequence, err := ber.AppendSequence(typePrefix, parts)
		require.NoError(t, err)
		encoded, err := ber.AppendConstructed(nil, ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: 4}, sequence)
		require.NoError(t, err)
		requireDecodeError(t, encoded, &SubstringFilter{})
	}
}

type badFilter struct {
	declared ber.Identifier
	encoded  []byte
}

func (f badFilter) FilterIdentifier() ber.Identifier     { return f.declared }
func (f badFilter) AppendBER(dst []byte) ([]byte, error) { return append(dst, f.encoded...), nil }

func searchRequestWithFilter(t *testing.T, filter []byte) []byte {
	t.Helper()
	contents, err := ber.AppendOctetString(nil, nil)
	require.NoError(t, err)
	contents, err = ber.AppendEnumerated(contents, 0)
	require.NoError(t, err)
	contents, err = ber.AppendEnumerated(contents, 0)
	require.NoError(t, err)
	contents, err = ber.AppendInteger(contents, 0)
	require.NoError(t, err)
	contents, err = ber.AppendInteger(contents, 0)
	require.NoError(t, err)
	contents, err = ber.AppendBoolean(contents, false)
	require.NoError(t, err)
	contents = append(contents, filter...)
	contents, err = ber.AppendSequence(contents, nil)
	require.NoError(t, err)
	encoded, err := ber.AppendConstructed(nil, SearchRequestIdentifier(), contents)
	require.NoError(t, err)
	return encoded
}

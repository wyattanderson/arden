package rfc4511_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestFilterAlternativesDispatchToConcreteTypes(t *testing.T) {
	initial := rfc4511.AssertionValue("Ja")
	final := rfc4511.AssertionValue("ne")
	rule := rfc4511.MatchingRuleID("caseIgnoreMatch")
	typeValue := rfc4511.AttributeDescription("cn")
	assertion := rfc4511.AttributeValueAssertion{Type: rfc4511.AttributeDescription("cn"), Value: rfc4511.AssertionValue("Jane")}
	tests := []struct {
		name string
		in   rfc4511.Filter
		out  rfc4511.Filter
	}{
		{"and", rfc4511.And{Filters: []rfc4511.Filter{rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}}, rfc4511.And{}},
		{"or", rfc4511.Or{Filters: []rfc4511.Filter{rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}}, rfc4511.Or{}},
		{"not", rfc4511.Not{Filter: rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}}, rfc4511.Not{}},
		{"equality", rfc4511.EqualityMatch{Assertion: assertion}, rfc4511.EqualityMatch{}},
		{"substrings", rfc4511.SubstringFilter{Type: typeValue, Initial: &initial, Any: []rfc4511.AssertionValue{rfc4511.AssertionValue("a")}, Final: &final}, rfc4511.SubstringFilter{}},
		{"greater or equal", rfc4511.GreaterOrEqual{Assertion: assertion}, rfc4511.GreaterOrEqual{}},
		{"less or equal", rfc4511.LessOrEqual{Assertion: assertion}, rfc4511.LessOrEqual{}},
		{"present", rfc4511.Present{Attribute: typeValue}, rfc4511.Present{}},
		{"approximate", rfc4511.ApproximateMatch{Assertion: assertion}, rfc4511.ApproximateMatch{}},
		{"extensible", rfc4511.ExtensibleMatch{MatchingRule: &rule, Type: &typeValue, MatchValue: rfc4511.AssertionValue("Jane"), DNAttributes: true}, rfc4511.ExtensibleMatch{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := &rfc4511.SearchRequest{Filter: test.in}
			encoded, err := request.AppendBER(nil)
			require.NoError(t, err)
			var got rfc4511.SearchRequest
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
	var request rfc4511.SearchRequest
	decode(t, requestWire, &request)
	unknown, ok := request.Filter.(rfc4511.UnknownFilter)
	require.True(t, ok)
	assert.Equal(t, ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: 42}, unknown.FilterIdentifier())
	assert.Equal(t, unknownWire, unknown.Raw())
	reencoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, requestWire, reencoded)

	for _, filter := range []rfc4511.Filter{
		badFilter{declared: ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 42}, encoded: unknownWire},
		badFilter{declared: ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: 41}, encoded: unknownWire},
	} {
		dst := []byte{0xde, 0xad}
		got, err := (&rfc4511.SearchRequest{Filter: filter}).AppendBER(dst)
		assert.Error(t, err)
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
		requireDecodeError(t, encoded, &rfc4511.SubstringFilter{})
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
	encoded, err := ber.AppendConstructed(nil, rfc4511.SearchRequestIdentifier(), contents)
	require.NoError(t, err)
	return encoded
}

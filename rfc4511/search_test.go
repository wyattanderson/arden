package rfc4511

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestSearchRequestRoundTripsBoundariesAndExtensibleScope(t *testing.T) {
	request := &SearchRequest{
		BaseObject:       LDAPDN("dc=example,dc=com"),
		Scope:            SearchScope(99),
		DerefAliases:     DerefAlways,
		SizeLimit:        math.MaxInt32,
		TimeLimitSeconds: math.MaxInt32,
		TypesOnly:        true,
		Filter:           Present{Attribute: AttributeDescription("objectClass")},
		Attributes:       []AttributeSelector{AttributeSelector("cn"), AttributeSelector("+")},
	}
	encoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	var got SearchRequest
	decode(t, encoded, &got)
	assert.Equal(t, *request, got)
}

func TestSearchRequestRejectsClosedEnumAndLimitOverflowAtomically(t *testing.T) {
	validFilter := Present{Attribute: AttributeDescription("cn")}
	for _, request := range []*SearchRequest{
		nil,
		{DerefAliases: DerefAliases(-1), Filter: validFilter},
		{DerefAliases: DerefAliases(4), Filter: validFilter},
		{SizeLimit: math.MaxInt32 + 1, Filter: validFilter},
		{TimeLimitSeconds: math.MaxInt32 + 1, Filter: validFilter},
		{},
	} {
		dst := []byte{0xde, 0xad}
		got, err := request.AppendBER(dst)
		require.Error(t, err)
		assert.Equal(t, dst, got)
	}

	for _, encoded := range [][]byte{
		searchRequestEncoding(t, 0, 4, 0, 0),
		searchRequestEncoding(t, 0, 0, -1, 0),
		searchRequestEncoding(t, 0, 0, 0, math.MaxInt32+1),
	} {
		prior := SearchRequest{BaseObject: LDAPDN("dc=keep"), Filter: validFilter}
		requireDecodeError(t, encoded, &prior)
		assert.Equal(t, "dc=keep", string(prior.BaseObject))
	}
}

func TestSearchResultReferenceRequiresURIAndPreservesExtensions(t *testing.T) {
	dst := []byte{0xde, 0xad}
	got, err := (SearchResultReference{}).AppendBER(dst)
	require.Error(t, err)
	assert.Equal(t, dst, got)

	empty, err := ber.AppendConstructed(nil, SearchResultReferenceIdentifier(), nil)
	require.NoError(t, err)
	requireDecodeError(t, empty, &SearchResultReference{})

	contents, err := ber.AppendOctetString(nil, []byte("ldap://example"))
	require.NoError(t, err)
	contents, err = ber.AppendPrimitive(contents, ber.Identifier{Class: ber.ClassContextSpecific, Number: 5}, []byte{0x7f})
	require.NoError(t, err)
	encoded, err := ber.AppendConstructed(nil, SearchResultReferenceIdentifier(), contents)
	require.NoError(t, err)
	var reference SearchResultReference
	decode(t, encoded, &reference)
	assert.Equal(t, []URI{URI("ldap://example")}, reference.URIs)
	require.Len(t, reference.Extensions, 1)
	reencoded, err := reference.AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, encoded, reencoded)
}

func TestSearchResultChoiceDecodesAndExposesValue(t *testing.T) {
	tests := []struct {
		name  string
		value ber.Marshaler
		check func(*testing.T, SearchResultValue)
	}{
		{"entry", SearchResultEntry{ObjectName: "uid=alice,dc=example"}, func(t *testing.T, value SearchResultValue) {
			entry, ok := value.(SearchResultEntry)
			require.True(t, ok)
			assert.Equal(t, LDAPDN("uid=alice,dc=example"), entry.ObjectName)
		}},
		{"reference", SearchResultReference{URIs: []URI{"ldap://example"}}, func(t *testing.T, value SearchResultValue) {
			reference, ok := value.(SearchResultReference)
			require.True(t, ok)
			assert.Equal(t, []URI{"ldap://example"}, reference.URIs)
		}},
		{"done", SearchResultDone{Result: emptyResult(ResultSuccess)}, func(t *testing.T, value SearchResultValue) {
			done, ok := value.(SearchResultDone)
			require.True(t, ok)
			assert.Equal(t, ResultSuccess, done.Result.ResultCode)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := test.value.AppendBER(nil)
			require.NoError(t, err)
			var result SearchResult
			decode(t, encoded, &result)
			test.check(t, result.Value())
		})
	}
	assert.Nil(t, (SearchResult{}).Value())
}

func TestSearchResultChoiceRejectsUnknownIdentifierAtomically(t *testing.T) {
	encoded, err := (SearchResultEntry{ObjectName: "dc=keep"}).AppendBER(nil)
	require.NoError(t, err)
	var result SearchResult
	decode(t, encoded, &result)

	unknown, err := ber.AppendConstructed(nil, applicationConstructed(30), nil)
	require.NoError(t, err)
	requireDecodeError(t, unknown, &result)
	entry, ok := result.Value().(SearchResultEntry)
	require.True(t, ok)
	assert.Equal(t, LDAPDN("dc=keep"), entry.ObjectName)
}

func searchRequestEncoding(t *testing.T, scope, deref, size, timeLimit int64) []byte {
	t.Helper()
	contents, err := ber.AppendOctetString(nil, nil)
	require.NoError(t, err)
	contents, err = ber.AppendEnumerated(contents, scope)
	require.NoError(t, err)
	contents, err = ber.AppendEnumerated(contents, deref)
	require.NoError(t, err)
	contents, err = ber.AppendInteger(contents, size)
	require.NoError(t, err)
	contents, err = ber.AppendInteger(contents, timeLimit)
	require.NoError(t, err)
	contents, err = ber.AppendBoolean(contents, false)
	require.NoError(t, err)
	contents, err = (Present{Attribute: AttributeDescription("cn")}).AppendBER(contents)
	require.NoError(t, err)
	contents, err = ber.AppendSequence(contents, nil)
	require.NoError(t, err)
	encoded, err := ber.AppendConstructed(nil, SearchRequestIdentifier(), contents)
	require.NoError(t, err)
	return encoded
}

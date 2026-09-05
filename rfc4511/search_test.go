package rfc4511

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestSearchRequestRoundTripsBoundariesAndExtensibleScope(t *testing.T) {
	request := &SearchRequest{
		BaseObject:   LDAPDN("dc=example,dc=com"),
		Scope:        SearchScope(99),
		DerefAliases: DerefAlways,
		SizeLimit:    math.MaxInt32,
		TimeLimit:    math.MaxInt32 * time.Second,
		TypesOnly:    true,
		Filter:       Present{Attribute: AttributeDescription("objectClass")},
		Attributes:   NewAttributeSelectors([]AttributeSelector{AttributeSelector("cn"), AttributeSelector("+")}),
	}
	encoded := request.BERPacket().Encode()
	var got SearchRequest
	decode(t, encoded, &got)
	assert.Equal(t, *request, got)
}

func TestSearchRequestRejectsClosedEnumAndLimitOverflowAtomically(t *testing.T) {
	validFilter := Present{Attribute: AttributeDescription("cn")}
	for _, request := range []*SearchRequest{
		{DerefAliases: DerefAliases(-1), Filter: validFilter},
		{DerefAliases: DerefAliases(4), Filter: validFilter},
		{SizeLimit: math.MaxInt32 + 1, Filter: validFilter},
		{TimeLimit: (math.MaxInt32 + 1) * time.Second, Filter: validFilter},
	} {
		prior := SearchRequest{BaseObject: LDAPDN("dc=keep"), Filter: validFilter}
		requireDecodeError(t, request.BERPacket().Encode(), &prior)
		assert.Equal(t, "dc=keep", string(prior.BaseObject))
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

func TestSearchRequestTimeLimitUsesWholeSecondsWithoutSignValidation(t *testing.T) {
	validFilter := Present{Attribute: AttributeDescription("cn")}
	for _, test := range []struct {
		input time.Duration
		want  time.Duration
	}{
		{input: 1500 * time.Millisecond, want: time.Second},
		{input: -1500 * time.Millisecond, want: -time.Second},
		{input: math.MaxInt32*time.Second + 500*time.Millisecond, want: math.MaxInt32 * time.Second},
	} {
		request := &SearchRequest{TimeLimit: test.input, Filter: validFilter}
		encoded := request.BERPacket().Encode()
		var got SearchRequest
		decode(t, encoded, &got)
		assert.Equal(t, test.want, got.TimeLimit)
	}
}

func TestSearchResultReferenceRequiresURIAndPreservesExtensions(t *testing.T) {
	empty := (SearchResultReference{}).BERPacket().Encode()
	requireDecodeError(t, empty, &SearchResultReference{})

	encoded := ber.Constructed(SearchResultReferenceIdentifier()).
		Add(
			ber.OctetString("ldap://example"),
			ber.Primitive(ber.Identifier{Class: ber.ClassContextSpecific, Number: 5}, []byte{0x7f}),
		).
		BERPacket().Encode()
	var reference SearchResultReference
	decode(t, encoded, &reference)
	assert.Equal(t, []URI{URI("ldap://example")}, reference.URIs)
	require.Len(t, reference.Extensions, 1)
	reencoded := reference.BERPacket().Encode()
	assert.Equal(t, encoded, reencoded)
}

func TestSearchResultChoiceDecodesAndExposesValue(t *testing.T) {
	tests := []struct {
		name  string
		value ber.Packeter
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
			encoded := test.value.BERPacket().Encode()
			var result SearchResult
			decode(t, encoded, &result)
			test.check(t, result.Value())
		})
	}
	assert.Nil(t, (SearchResult{}).Value())
}

func TestSearchResultChoiceRejectsUnknownIdentifierAtomically(t *testing.T) {
	encoded := (SearchResultEntry{ObjectName: "dc=keep"}).BERPacket().Encode()
	var result SearchResult
	decode(t, encoded, &result)

	unknown := ber.Constructed(applicationConstructed(30)).BERPacket().Encode()
	requireDecodeError(t, unknown, &result)
	entry, ok := result.Value().(SearchResultEntry)
	require.True(t, ok)
	assert.Equal(t, LDAPDN("dc=keep"), entry.ObjectName)
}

func searchRequestEncoding(t *testing.T, scope, deref, size, timeLimit int64) []byte {
	t.Helper()
	encoded := ber.Constructed(SearchRequestIdentifier()).
		Add(
			ber.OctetString([]byte(nil)),
			ber.Enumerated(scope),
			ber.Enumerated(deref),
			ber.Integer(size),
			ber.Integer(timeLimit),
			ber.Boolean(false),
		).
		Add(Present{Attribute: AttributeDescription("cn")}).
		Add(ber.Sequence()).
		BERPacket().Encode()
	return encoded
}

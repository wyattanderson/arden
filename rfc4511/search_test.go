package rfc4511_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestSearchRequestRoundTripsBoundariesAndExtensibleScope(t *testing.T) {
	request := &rfc4511.SearchRequest{
		BaseObject:       rfc4511.LDAPDN("dc=example,dc=com"),
		Scope:            rfc4511.SearchScope(99),
		DerefAliases:     rfc4511.DerefAlways,
		SizeLimit:        math.MaxInt32,
		TimeLimitSeconds: math.MaxInt32,
		TypesOnly:        true,
		Filter:           rfc4511.Present{Attribute: rfc4511.AttributeDescription("objectClass")},
		Attributes:       []rfc4511.AttributeSelector{rfc4511.AttributeSelector("cn"), rfc4511.AttributeSelector("+")},
	}
	encoded, err := request.AppendBER(nil)
	require.NoError(t, err)
	var got rfc4511.SearchRequest
	decode(t, encoded, &got)
	assert.Equal(t, *request, got)
}

func TestSearchRequestRejectsClosedEnumAndLimitOverflowAtomically(t *testing.T) {
	validFilter := rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}
	for _, request := range []*rfc4511.SearchRequest{
		nil,
		{DerefAliases: rfc4511.DerefAliases(-1), Filter: validFilter},
		{DerefAliases: rfc4511.DerefAliases(4), Filter: validFilter},
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
		prior := rfc4511.SearchRequest{BaseObject: rfc4511.LDAPDN("dc=keep"), Filter: validFilter}
		requireDecodeError(t, encoded, &prior)
		assert.Equal(t, "dc=keep", string(prior.BaseObject))
	}
}

func TestSearchResultReferenceRequiresURIAndPreservesExtensions(t *testing.T) {
	dst := []byte{0xde, 0xad}
	got, err := (rfc4511.SearchResultReference{}).AppendBER(dst)
	require.Error(t, err)
	assert.Equal(t, dst, got)

	empty, err := ber.AppendConstructed(nil, rfc4511.SearchResultReferenceIdentifier(), nil)
	require.NoError(t, err)
	requireDecodeError(t, empty, &rfc4511.SearchResultReference{})

	contents, err := ber.AppendOctetString(nil, []byte("ldap://example"))
	require.NoError(t, err)
	contents, err = ber.AppendPrimitive(contents, ber.Identifier{Class: ber.ClassContextSpecific, Number: 5}, []byte{0x7f})
	require.NoError(t, err)
	encoded, err := ber.AppendConstructed(nil, rfc4511.SearchResultReferenceIdentifier(), contents)
	require.NoError(t, err)
	var reference rfc4511.SearchResultReference
	decode(t, encoded, &reference)
	assert.Equal(t, []rfc4511.URI{rfc4511.URI("ldap://example")}, reference.URIs)
	require.Len(t, reference.Extensions, 1)
	reencoded, err := reference.AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, encoded, reencoded)
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
	contents, err = (rfc4511.Present{Attribute: rfc4511.AttributeDescription("cn")}).AppendBER(contents)
	require.NoError(t, err)
	contents, err = ber.AppendSequence(contents, nil)
	require.NoError(t, err)
	encoded, err := ber.AppendConstructed(nil, rfc4511.SearchRequestIdentifier(), contents)
	require.NoError(t, err)
	return encoded
}

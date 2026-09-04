package rfc4511

import (
	"bytes"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestLDAPResultDefaultTaggedAndEmbeddedDecoding(t *testing.T) {
	result := LDAPResult{
		ResultCode:        ResultReferral,
		MatchedDN:         "dc=example",
		DiagnosticMessage: "follow referral",
		Referrals:         []URI{"ldap://example/dc=example"},
	}
	var standalone LDAPResult
	decode(t, result.BERPacket().Encode(), &standalone)
	assert.Equal(t, result, standalone)

	for _, id := range []ber.Identifier{
		searchDoneIdentifier, addResponseIdentifier, modifyResponseIdentifier,
		modifyDNResponseIdentifier, compareResponseIdentifier, deleteResponseIdentifier,
	} {
		t.Run(id.String(), func(t *testing.T) {
			encoded := resultResponsePacket(id, result).Encode()
			r, err := ber.NewReader(encoded, ber.DefaultLimits())
			require.NoError(t, err)
			d := ber.NewDecoder(r)
			got := d.ReadAs[LDAPResult](id)
			require.NoError(t, d.End())
			assert.Equal(t, result, got)
		})
	}

	unknown := ber.Primitive(contextPrimitive(20), []byte{0, 0xff})
	bindPacket := ber.Constructed(bindResponseIdentifier)
	result.addPrefix(bindPacket)
	bindPacket.Add(ber.Primitive(serverSASLCredentialsIdentifier, []byte{0, 0xfe}), unknown)
	encoded := bindPacket.BERPacket().Encode()
	var bind BindResponse
	decode(t, encoded, &bind)
	assert.Equal(t, result, bind.Result)
	assert.Empty(t, bind.Result.Extensions)
	assert.True(t, bind.HasServerSASLCredentials)
	assert.Equal(t, []byte{0, 0xfe}, bind.ServerSASLCredentials)
	require.Len(t, bind.Extensions, 1)
	assert.Equal(t, unknown.Encode(), bind.Extensions[0].Bytes())
	assert.Equal(t, encoded, bind.BERPacket().Encode())
	clear(encoded)
	assert.Equal(t, []byte{0, 0xfe}, bind.ServerSASLCredentials)
	assert.Equal(t, unknown.Encode(), bind.Extensions[0].Bytes())

	extendedPacket := ber.Constructed(extendedResponseIdentifier)
	result.addPrefix(extendedPacket)
	extendedPacket.Add(
		ber.Primitive(extendedResponseNameIdentifier, []byte("1.2.3")),
		ber.Primitive(extendedResponseValueIdentifier, []byte{0, 0xfd}),
		unknown,
	)
	encoded = extendedPacket.BERPacket().Encode()
	var extended ExtendedResponse
	decode(t, encoded, &extended)
	assert.Equal(t, result, extended.Result)
	assert.Empty(t, extended.Result.Extensions)
	assert.True(t, extended.HasResponseName)
	assert.True(t, extended.HasResponseValue)
	assert.Equal(t, LDAPOID("1.2.3"), extended.ResponseName)
	assert.Equal(t, []byte{0, 0xfd}, extended.ResponseValue)
	require.Len(t, extended.Extensions, 1)
	assert.Equal(t, encoded, extended.BERPacket().Encode())
	clear(encoded)
	assert.Equal(t, []byte{0, 0xfd}, extended.ResponseValue)
	assert.Equal(t, unknown.Encode(), extended.Extensions[0].Bytes())
}

func TestEmbeddedResultRejectsReferralsAfterOuterFieldsOrExtensions(t *testing.T) {
	referral := ber.Constructed(referralIdentifier).Add(URI("ldap://example")).BERPacket()
	unknown := ber.Primitive(contextPrimitive(20), nil)
	for _, code := range []ResultCode{ResultSuccess, ResultReferral} {
		result := LDAPResult{ResultCode: code}
		if code == ResultReferral {
			result.Referrals = []URI{"ldap://example"}
		}
		for _, delayed := range []bool{false, true} {
			bind := ber.Constructed(bindResponseIdentifier)
			result.addPrefix(bind)
			bind.Add(ber.Primitive(serverSASLCredentialsIdentifier, nil))
			if delayed {
				bind.Add(unknown)
			}
			bind.Add(referral)
			priorBind := BindResponse{Result: LDAPResult{MatchedDN: "keep"}, ServerSASLCredentials: []byte("keep")}
			requireDecodeError(t, bind.BERPacket().Encode(), &priorBind)
			assert.Equal(t, LDAPDN("keep"), priorBind.Result.MatchedDN)
			assert.Equal(t, []byte("keep"), priorBind.ServerSASLCredentials)

			extended := ber.Constructed(extendedResponseIdentifier)
			result.addPrefix(extended)
			extended.Add(ber.Primitive(extendedResponseNameIdentifier, []byte("1.2.3")))
			if delayed {
				extended.Add(unknown)
			}
			extended.Add(referral)
			priorExtended := ExtendedResponse{Result: LDAPResult{MatchedDN: "keep"}, ResponseValue: []byte("keep")}
			requireDecodeError(t, extended.BERPacket().Encode(), &priorExtended)
			assert.Equal(t, LDAPDN("keep"), priorExtended.Result.MatchedDN)
			assert.Equal(t, []byte("keep"), priorExtended.ResponseValue)
		}
	}
}

func TestTaggedResultLateFailureIsAtomic(t *testing.T) {
	prior := LDAPResult{ResultCode: ResultOther, MatchedDN: "keep", Referrals: []URI{"keep"}}
	packet := ber.Constructed(searchDoneIdentifier)
	(LDAPResult{ResultCode: ResultSuccess}).addPrefix(packet)
	// Unknown constructed extensions must be validated, not merely copied.
	packet.Add(ber.WithContents(contextConstructed(20), []byte{0xff}))
	r, err := ber.NewReader(packet.BERPacket().Encode(), ber.DefaultLimits())
	require.NoError(t, err)
	require.Error(t, prior.UnmarshalAs(searchDoneIdentifier).UnmarshalBER(r))
	assert.Equal(t, LDAPResult{ResultCode: ResultOther, MatchedDN: "keep", Referrals: []URI{"keep"}}, prior)
}

func TestSearchDecoderRejectsTruncationsAtomically(t *testing.T) {
	request := SearchRequest{
		BaseObject: "dc=example", Scope: ScopeSubtree, DerefAliases: DerefAlways,
		SizeLimit: 10, TimeLimit: time.Second, Filter: All(Has("cn"), Equal("sn", "Smith")),
		Attributes: []AttributeSelector{"cn", "sn"},
	}
	encoded := request.BERPacket().Encode()
	for length := range len(encoded) {
		prior := SearchRequest{BaseObject: "keep", Attributes: []AttributeSelector{"keep"}}
		requireDecodeError(t, encoded[:length], &prior)
		assert.Equal(t, SearchRequest{BaseObject: "keep", Attributes: []AttributeSelector{"keep"}}, prior)
	}

	entry := SearchResultEntry{
		ObjectName: "cn=Smith,dc=example",
		Attributes: []PartialAttribute{{Type: "cn", Values: []AttributeValue{[]byte("Smith"), {0, 0xff}}}},
	}
	encoded = entry.BERPacket().Encode()
	for length := range len(encoded) {
		prior := SearchResultEntry{ObjectName: "keep", Attributes: []PartialAttribute{{Type: "keep"}}}
		requireDecodeError(t, encoded[:length], &prior)
		assert.Equal(t, SearchResultEntry{ObjectName: "keep", Attributes: []PartialAttribute{{Type: "keep"}}}, prior)
	}
	var decoded SearchResultEntry
	decode(t, encoded, &decoded)
	clear(encoded)
	assert.Equal(t, entry, decoded)
}

func TestSearchTimeConversionRejectsOverflowButRetainsSignedPolicy(t *testing.T) {
	for _, seconds := range []int64{math.MinInt64, math.MinInt64/int64(time.Second) - 1, math.MaxInt64} {
		prior := SearchRequest{BaseObject: "keep"}
		requireDecodeError(t, searchRequestEncoding(t, 0, 0, 0, seconds), &prior)
		assert.Equal(t, LDAPDN("keep"), prior.BaseObject)
	}
	for _, seconds := range []int64{math.MinInt64 / int64(time.Second), -1, 0, math.MaxInt32} {
		var decoded SearchRequest
		decode(t, searchRequestEncoding(t, 0, 0, 0, seconds), &decoded)
		assert.Equal(t, time.Duration(seconds)*time.Second, decoded.TimeLimit)
	}
}

func TestCompositeDecodersUseNamedTextValidation(t *testing.T) {
	badText := string([]byte{0xff})
	requireDecodeError(t, (&SearchRequest{BaseObject: LDAPDN(badText), Filter: Has("cn")}).BERPacket().Encode(), &SearchRequest{})
	requireDecodeError(t, (&SearchRequest{Filter: Has("cn"), Attributes: []AttributeSelector{AttributeSelector(badText)}}).BERPacket().Encode(), &SearchRequest{})
	requireDecodeError(t, (SearchResultEntry{ObjectName: LDAPDN(badText)}).BERPacket().Encode(), &SearchResultEntry{})
	requireDecodeError(t, (SearchResultDone{Result: LDAPResult{DiagnosticMessage: LDAPString(badText)}}).BERPacket().Encode(), &SearchResultDone{})
	requireDecodeError(t, (&DeleteRequest{Entry: LDAPDN(badText)}).BERPacket().Encode(), &DeleteRequest{})

	// Binary assertion and attribute values remain unrestricted octets.
	value := bytes.Repeat([]byte{0xff}, 5)
	input := EqualityMatch{Assertion: AttributeValueAssertion{Type: "cn", Value: AssertionValue(value)}}
	var output EqualityMatch
	decode(t, input.BERPacket().Encode(), &output)
	assert.Equal(t, input, output)
}

package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

var (
	_ ResultResponse = AddResponse{}
	_ ResultResponse = BindResponse{}
	_ ResultResponse = CompareResponse{}
	_ ResultResponse = DeleteResponse{}
	_ ResultResponse = ExtendedResponse{}
	_ ResultResponse = ModifyResponse{}
	_ ResultResponse = ModifyDNResponse{}
	_ ResultResponse = SearchResultDone{}
)

func TestLDAPResultRoundTripsSemanticVariants(t *testing.T) {
	tests := []struct {
		name string
		in   LDAPResult
	}{
		{"success", LDAPResult{ResultCode: ResultSuccess}},
		{"ordinary error", LDAPResult{ResultCode: ResultNoSuchObject, MatchedDN: LDAPDN("dc=example"), DiagnosticMessage: LDAPString("missing")}},
		{"unknown result code", LDAPResult{ResultCode: ResultCode(70), DiagnosticMessage: LDAPString("extension-defined")}},
		{"referral", LDAPResult{ResultCode: ResultReferral, Referrals: []URI{URI("ldap://one"), URI("ldap://two")}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded := test.in.BERPacket().Encode()
			var got LDAPResult
			decode(t, encoded, &got)
			assert.Equal(t, test.in, got)
			reencoded := got.BERPacket().Encode()
			assert.Equal(t, encoded, reencoded)
		})
	}
}

func TestLDAPResultReferralRulesAreAtomic(t *testing.T) {
	for _, result := range []LDAPResult{
		{ResultCode: ResultReferral},
		{ResultCode: ResultSuccess, Referrals: []URI{URI("ldap://unexpected")}},
	} {
		prior := LDAPResult{ResultCode: ResultBusy}
		requireDecodeError(t, result.BERPacket().Encode(), &prior)
		assert.Equal(t, ResultBusy, prior.ResultCode)
	}

	prior := LDAPResult{ResultCode: ResultBusy, DiagnosticMessage: LDAPString("keep")}
	// A referral result without the required referral field.
	requireDecodeError(t, []byte{0x30, 0x07, 0x0a, 0x01, 0x0a, 0x04, 0x00, 0x04, 0x00}, &prior)
	assert.Equal(t, ResultBusy, prior.ResultCode)
	assert.Equal(t, "keep", string(prior.DiagnosticMessage))

	// A non-referral result carrying referral URIs.
	requireDecodeError(t, []byte{0x30, 0x0f, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0xa3, 0x06, 0x04, 0x04, 'l', 'd', 'a', 'p'}, &prior)
	assert.Equal(t, ResultBusy, prior.ResultCode)
}

func TestLDAPResultPreservesTrailingExtensionsAndOwnership(t *testing.T) {
	encoded := []byte{0x30, 0x0a, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x83, 0x01, 0x7f}
	var result LDAPResult
	decode(t, encoded, &result)
	require.Len(t, result.Extensions, 1)
	assert.Equal(t, ber.Identifier{Class: ber.ClassContextSpecific, Number: 3}, result.Extensions[0].Identifier())
	assert.Equal(t, []byte{0x83, 0x01, 0x7f}, result.Extensions[0].Bytes())

	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, []byte{0x83, 0x01, 0x7f}, result.Extensions[0].Bytes())
	reencoded := result.BERPacket().Encode()
	assert.Equal(t, []byte{0x30, 0x0a, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x83, 0x01, 0x7f}, reencoded)
}

func TestLDAPResultRejectsDuplicateReferral(t *testing.T) {
	encoded := []byte{
		0x30, 0x13,
		0x0a, 0x01, 0x0a, 0x04, 0x00, 0x04, 0x00,
		0xa3, 0x04, 0x04, 0x02, 'o', 'k',
		0xa3, 0x04, 0x04, 0x02, 'n', 'o',
	}
	requireDecodeError(t, encoded, &LDAPResult{})
}

package rfc4511_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestLDAPResultRoundTripsSemanticVariants(t *testing.T) {
	tests := []struct {
		name string
		in   rfc4511.LDAPResult
	}{
		{"success", rfc4511.LDAPResult{ResultCode: rfc4511.ResultSuccess, MatchedDN: rfc4511.LDAPDN{}, DiagnosticMessage: rfc4511.LDAPString{}}},
		{"ordinary error", rfc4511.LDAPResult{ResultCode: rfc4511.ResultNoSuchObject, MatchedDN: rfc4511.LDAPDN("dc=example"), DiagnosticMessage: rfc4511.LDAPString("missing")}},
		{"unknown result code", rfc4511.LDAPResult{ResultCode: rfc4511.ResultCode(70), MatchedDN: rfc4511.LDAPDN{}, DiagnosticMessage: rfc4511.LDAPString("extension-defined")}},
		{"referral", rfc4511.LDAPResult{ResultCode: rfc4511.ResultReferral, MatchedDN: rfc4511.LDAPDN{}, DiagnosticMessage: rfc4511.LDAPString{}, Referrals: []rfc4511.URI{rfc4511.URI("ldap://one"), rfc4511.URI("ldap://two")}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := test.in.AppendBER(nil)
			require.NoError(t, err)
			var got rfc4511.LDAPResult
			decode(t, encoded, &got)
			assert.Equal(t, test.in, got)
			reencoded, err := got.AppendBER(nil)
			require.NoError(t, err)
			assert.Equal(t, encoded, reencoded)
		})
	}
}

func TestLDAPResultReferralRulesAreAtomic(t *testing.T) {
	for _, result := range []rfc4511.LDAPResult{
		{ResultCode: rfc4511.ResultReferral},
		{ResultCode: rfc4511.ResultSuccess, Referrals: []rfc4511.URI{rfc4511.URI("ldap://unexpected")}},
	} {
		dst := []byte{0xde, 0xad}
		got, err := result.AppendBER(dst)
		assert.Error(t, err)
		assert.Equal(t, dst, got)
	}

	prior := rfc4511.LDAPResult{ResultCode: rfc4511.ResultBusy, DiagnosticMessage: rfc4511.LDAPString("keep")}
	// A referral result without the required referral field.
	requireDecodeError(t, []byte{0x30, 0x07, 0x0a, 0x01, 0x0a, 0x04, 0x00, 0x04, 0x00}, &prior)
	assert.Equal(t, rfc4511.ResultBusy, prior.ResultCode)
	assert.Equal(t, "keep", string(prior.DiagnosticMessage))

	// A non-referral result carrying referral URIs.
	requireDecodeError(t, []byte{0x30, 0x0f, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0xa3, 0x06, 0x04, 0x04, 'l', 'd', 'a', 'p'}, &prior)
	assert.Equal(t, rfc4511.ResultBusy, prior.ResultCode)
}

func TestLDAPResultPreservesTrailingExtensionsAndOwnership(t *testing.T) {
	encoded := []byte{0x30, 0x0a, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x83, 0x01, 0x7f}
	var result rfc4511.LDAPResult
	decode(t, encoded, &result)
	require.Len(t, result.Extensions, 1)
	assert.Equal(t, ber.Identifier{Class: ber.ClassContextSpecific, Number: 3}, result.Extensions[0].Identifier())
	assert.Equal(t, []byte{0x83, 0x01, 0x7f}, result.Extensions[0].Bytes())

	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, []byte{0x83, 0x01, 0x7f}, result.Extensions[0].Bytes())
	reencoded, err := result.AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x0a, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x83, 0x01, 0x7f}, reencoded)
}

func TestLDAPResultRejectsDuplicateReferral(t *testing.T) {
	encoded := []byte{
		0x30, 0x13,
		0x0a, 0x01, 0x0a, 0x04, 0x00, 0x04, 0x00,
		0xa3, 0x04, 0x04, 0x02, 'o', 'k',
		0xa3, 0x04, 0x04, 0x02, 'n', 'o',
	}
	requireDecodeError(t, encoded, &rfc4511.LDAPResult{})
}

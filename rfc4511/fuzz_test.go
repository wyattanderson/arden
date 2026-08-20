package rfc4511_test

import (
	"testing"

	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

func FuzzRFC4511Unmarshalers(f *testing.F) {
	for _, seed := range [][]byte{
		{0x04, 0x00},
		{0x30, 0x00},
		{0x63, 0x1b, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x02, 'c', 'n', 0x30, 0x00},
		{0x69, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, decoder := range []ber.Unmarshaler{
			new(rfc4511.LDAPString), new(rfc4511.LDAPOID), new(rfc4511.LDAPDN), new(rfc4511.RelativeLDAPDN), new(rfc4511.URI),
			new(rfc4511.AttributeDescription), new(rfc4511.AttributeSelector), new(rfc4511.MatchingRuleID), new(rfc4511.AttributeValue), new(rfc4511.AssertionValue),
			new(rfc4511.PartialAttribute), new(rfc4511.Attribute), new(rfc4511.AttributeValueAssertion), new(rfc4511.LDAPResult), new(rfc4511.Control),
			new(rfc4511.SimpleAuthentication), new(rfc4511.SASLAuthentication), new(rfc4511.BindRequest), new(rfc4511.BindResponse), new(rfc4511.UnbindRequest),
			new(rfc4511.And), new(rfc4511.Or), new(rfc4511.Not), new(rfc4511.EqualityMatch), new(rfc4511.GreaterOrEqual), new(rfc4511.LessOrEqual), new(rfc4511.Present), new(rfc4511.ApproximateMatch), new(rfc4511.SubstringFilter), new(rfc4511.ExtensibleMatch),
			new(rfc4511.SearchRequest), new(rfc4511.SearchResultEntry), new(rfc4511.SearchResultReference), new(rfc4511.SearchResultDone),
			new(rfc4511.Change), new(rfc4511.ModifyRequest), new(rfc4511.ModifyResponse), new(rfc4511.DeleteRequest), new(rfc4511.DeleteResponse), new(rfc4511.ModifyDNRequest), new(rfc4511.ModifyDNResponse), new(rfc4511.CompareRequest), new(rfc4511.CompareResponse), new(rfc4511.AbandonRequest), new(rfc4511.ExtendedRequest), new(rfc4511.ExtendedResponse), new(rfc4511.IntermediateResponse),
		} {
			r, err := ber.NewReader(data, ber.DefaultLimits())
			if err == nil {
				_ = decoder.UnmarshalBER(r)
			}
		}
	})
}

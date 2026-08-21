package rfc4511_test

import (
	"bytes"
	"reflect"
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
		{0x60, 0x09, 0x02, 0x01, 0x03, 0x04, 0x00, 0x85, 0x02, 0x00, 0xff},
		{0x78, 0x09, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x8b, 0x00},
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
				if decoder.UnmarshalBER(r) == nil && r.RequireEmpty() == nil {
					marshaler, ok := decoder.(ber.Marshaler)
					if !ok {
						t.Fatalf("successful decoder %T does not implement ber.Marshaler", decoder)
					}
					canonical, err := marshaler.AppendBER(nil)
					if err != nil {
						t.Fatalf("%T accepted input but could not re-encode it: %v", decoder, err)
					}
					roundTripped := reflect.New(reflect.TypeOf(decoder).Elem()).Interface().(ber.Unmarshaler)
					roundTripReader, err := ber.NewReader(canonical, ber.DefaultLimits())
					if err != nil || roundTripped.UnmarshalBER(roundTripReader) != nil || roundTripReader.RequireEmpty() != nil {
						t.Fatalf("%T produced an encoding it could not decode", decoder)
					}
					reencoded, err := roundTripped.(ber.Marshaler).AppendBER(nil)
					if err != nil || !bytes.Equal(canonical, reencoded) {
						t.Fatalf("%T encoding did not stabilize after a valid round trip", decoder)
					}
				}
			}
		}
	})
}

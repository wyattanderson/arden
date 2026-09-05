package rfc4511

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
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
			new(LDAPString), new(LDAPOID), new(LDAPDN), new(RelativeLDAPDN), new(URI),
			new(AttributeDescription), new(AttributeSelector), new(AttributeSelectors), new(MatchingRuleID), new(AttributeValue), new(AssertionValue),
			new(PartialAttribute), new(Attribute), new(AttributeValueAssertion), new(LDAPResult), new(Control),
			new(SimpleAuthentication), new(SASLAuthentication), new(BindRequest), new(BindResponse), new(UnbindRequest),
			new(And), new(Or), new(Not), new(EqualityMatch), new(GreaterOrEqual), new(LessOrEqual), new(Present), new(ApproximateMatch), new(SubstringFilter), new(ExtensibleMatch),
			new(SearchRequest), new(SearchResultEntry), new(SearchResultReference), new(SearchResultDone),
			new(Change), new(ModifyRequest), new(ModifyResponse), new(DeleteRequest), new(DeleteResponse), new(ModifyDNRequest), new(ModifyDNResponse), new(CompareRequest), new(CompareResponse), new(AbandonRequest), new(ExtendedRequest), new(ExtendedResponse), new(IntermediateResponse),
		} {
			r, err := ber.NewReader(data, ber.DefaultLimits())
			if err == nil {
				if decoder.UnmarshalBER(r) == nil && r.RequireEmpty() == nil {
					packet, ok := decoder.(ber.Packeter)
					require.True(t, ok)
					canonical := packet.BERPacket().Encode()
					roundTripped := reflect.New(reflect.TypeOf(decoder).Elem()).Interface().(ber.Unmarshaler)
					roundTripReader, err := ber.NewReader(canonical, ber.DefaultLimits())
					require.NoError(t, err)
					require.NoError(t, roundTripped.UnmarshalBER(roundTripReader))
					require.NoError(t, roundTripReader.RequireEmpty())
					reencoded := roundTripped.(ber.Packeter).BERPacket().Encode()
					require.Equal(t, canonical, reencoded)
				}
			}
		}
	})
}

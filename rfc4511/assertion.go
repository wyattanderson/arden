package rfc4511

import (
	"github.com/wyattanderson/arden/ber"
)

// AttributeValueAssertion pairs an attribute description with a raw assertion
// value. RFC 4511 section 4.1.6.
type AttributeValueAssertion struct {
	Type       AttributeDescription
	Value      AssertionValue
	Extensions []UnknownField
}

// BERPacket returns the attribute-value assertion packet.
func (v AttributeValueAssertion) BERPacket() ber.Packet {
	return ber.Sequence().
		Add(ber.OctetString(v.Type), ber.OctetString(v.Value)).
		Add(v.Extensions...).
		BERPacket()
}

//revive:disable-next-line:exported
func (v *AttributeValueAssertion) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.SequenceIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the assertion decoder to an alternate identifier.
func (v *AttributeValueAssertion) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		d := ber.NewDecoder(r).Constructed(id)
		decoded := AttributeValueAssertion{
			Type:       d.Read[AttributeDescription](),
			Value:      d.Read[AssertionValue](),
			Extensions: d.Extensions[UnknownField](),
		}
		if err := d.End(); err != nil {
			return err
		}
		if err := requireNonEmpty("attribute description", decoded.Type); err != nil {
			return err
		}
		*v = decoded
		return nil
	})
}

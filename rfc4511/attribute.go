package rfc4511

import "github.com/wyattanderson/arden/ber"

// Attribute is an RFC 4511 attribute whose value set may be empty, as allowed
// in search results and modifications. AddRequest.UnmarshalBER requires at
// least one value per attribute.
// Extensions preserves any allowed unknown trailing SEQUENCE components in
// their original order.
//
// RFC 4511 section 4.1.7.
type Attribute struct {
	Type       AttributeDescription
	Values     []AttributeValue
	Extensions []UnknownField
}

// BERPacket returns the attribute packet.
func (a Attribute) BERPacket() ber.Packet {
	return ber.Sequence().
		Add(ber.OctetString(a.Type)).
		Add(ber.Set().Add(a.Values...)).
		Add(a.Extensions...).
		BERPacket()
}

//revive:disable-next-line:exported
func (a *Attribute) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Sequence()
	decoded := Attribute{
		Type:       d.Read[AttributeDescription](),
		Values:     d.Set().All[AttributeValue](),
		Extensions: d.Extensions[UnknownField](),
	}
	if err := d.End(); err != nil {
		return err
	}
	if err := requireNonEmpty("attribute type", decoded.Type); err != nil {
		return err
	}
	*a = decoded
	return nil
}

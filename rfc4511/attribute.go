package rfc4511

import (
	"errors"

	"github.com/wyattanderson/arden/ber"
)

// PartialAttribute is an RFC 4511 attribute whose value set may be empty.
// Extensions preserves any allowed unknown trailing SEQUENCE components in
// their original order.
//
// RFC 4511 section 4.1.7.
type PartialAttribute struct {
	Type       AttributeDescription
	Values     []AttributeValue
	Extensions []UnknownField
}

// Attribute is an RFC 4511 attribute whose value set must contain at least
// one value. It is distinct from PartialAttribute because the wire layer can
// enforce that cardinality without knowing schema semantics.
//
// RFC 4511 section 4.1.7.
type Attribute struct {
	Type       AttributeDescription
	Values     []AttributeValue
	Extensions []UnknownField
}

// BERPacket returns the partial-attribute packet.
func (a PartialAttribute) BERPacket() ber.Packet {
	return attributePacket(a.Type, a.Values, a.Extensions)
}

//revive:disable-next-line:exported
func (a *PartialAttribute) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Sequence()
	decoded := PartialAttribute{
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

// BERPacket returns the attribute packet.
func (a Attribute) BERPacket() ber.Packet {
	return attributePacket(a.Type, a.Values, a.Extensions)
}

//revive:disable-next-line:exported
func (a *Attribute) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := d.Read[PartialAttribute]()
	if err := d.Err(); err != nil {
		return err
	}
	if len(decoded.Values) == 0 {
		return errors.New("arden: Attribute requires at least one value")
	}
	*a = Attribute(decoded)
	return nil
}

func attributePacket(
	typeValue AttributeDescription,
	values []AttributeValue,
	extensions []UnknownField,
) ber.Packet {
	return ber.Sequence().
		Add(ber.OctetString(typeValue)).
		Add(ber.Set().Add(values...)).
		Add(extensions...).
		BERPacket()
}

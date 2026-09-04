package rfc4511

import (
	"bytes"
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
	typeValue, values, extensions, err := decodeAttribute(r, false)
	if err != nil {
		return err
	}
	*a = PartialAttribute{Type: typeValue, Values: values, Extensions: extensions}
	return nil
}

// BERPacket returns the attribute packet.
func (a Attribute) BERPacket() ber.Packet {
	return attributePacket(a.Type, a.Values, a.Extensions)
}

//revive:disable-next-line:exported
func (a *Attribute) UnmarshalBER(r *ber.Reader) error {
	typeValue, values, extensions, err := decodeAttribute(r, true)
	if err != nil {
		return err
	}
	*a = Attribute{Type: typeValue, Values: values, Extensions: extensions}
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

func decodeAttribute(r *ber.Reader, requireValue bool) (
	AttributeDescription,
	[]AttributeValue,
	[]UnknownField,
	error,
) {
	contents, err := r.Sequence()
	if err != nil {
		return "", nil, nil, err
	}
	typeValue, err := contents.OctetString()
	if err != nil {
		return "", nil, nil, err
	}
	if len(typeValue) == 0 {
		return "", nil, nil, errors.New("arden: attribute type is empty")
	}
	valueSet, err := contents.Set()
	if err != nil {
		return "", nil, nil, err
	}
	var values []AttributeValue
	for !valueSet.Empty() {
		value, err := valueSet.OctetString()
		if err != nil {
			return "", nil, nil, err
		}
		values = append(values, AttributeValue(bytes.Clone(value)))
	}
	if requireValue && len(values) == 0 {
		return "", nil, nil, errors.New("arden: Attribute requires at least one value")
	}
	extensions, err := decodeUnknownFields(contents)
	if err != nil {
		return "", nil, nil, err
	}
	return AttributeDescription(string(typeValue)), values, extensions, nil
}

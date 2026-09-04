package rfc4511

import (
	"bytes"

	"github.com/wyattanderson/arden/ber"
)

// AttributeValueAssertion pairs an attribute description with a raw assertion
// value. RFC 4511 section 4.1.6.
type AttributeValueAssertion struct {
	Type       AttributeDescription
	Value      AssertionValue
	Extensions []UnknownField
}

//revive:disable-next-line:exported
func (v AttributeValueAssertion) AppendBER(dst []byte) ([]byte, error) {
	if err := requireNonEmpty("attribute description", v.Type); err != nil {
		return dst, err
	}
	return v.BERPacket().AppendBER(dst)
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
	contents, err := r.Sequence()
	if err != nil {
		return err
	}
	decoded, err := decodeAssertionContents(contents)
	if err != nil {
		return err
	}
	*v = decoded
	return nil
}

func decodeAssertionContents(r *ber.Reader) (AttributeValueAssertion, error) {
	typeValue, err := r.OctetString()
	if err != nil {
		return AttributeValueAssertion{}, err
	}
	if err := requireNonEmpty("attribute description", typeValue); err != nil {
		return AttributeValueAssertion{}, err
	}
	value, err := r.OctetString()
	if err != nil {
		return AttributeValueAssertion{}, err
	}
	extensions, err := decodeUnknownFields(r)
	if err != nil {
		return AttributeValueAssertion{}, err
	}
	return AttributeValueAssertion{
		Type:       AttributeDescription(string(typeValue)),
		Value:      AssertionValue(bytes.Clone(value)),
		Extensions: extensions,
	}, nil
}

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
	start := len(dst)
	contents, err := v.appendContents(nil)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendSequence(dst, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (v *AttributeValueAssertion) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("AttributeValueAssertion")
	}
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

func (v AttributeValueAssertion) appendContents(dst []byte) ([]byte, error) {
	start := len(dst)
	if err := requireNonEmpty("attribute description", v.Type); err != nil {
		return dst, err
	}
	var err error
	if dst, err = ber.AppendOctetString(dst, v.Type); err != nil {
		return dst[:start], err
	}
	if dst, err = ber.AppendOctetString(dst, v.Value); err != nil {
		return dst[:start], err
	}
	if dst, err = appendUnknownFields(dst, v.Extensions); err != nil {
		return dst[:start], err
	}
	return dst, nil
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
		Type:       AttributeDescription(bytes.Clone(typeValue)),
		Value:      AssertionValue(bytes.Clone(value)),
		Extensions: extensions,
	}, nil
}

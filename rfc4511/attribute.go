package rfc4511

import (
	"bytes"
	"errors"
	"fmt"

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

//revive:disable-next-line:exported
func (a PartialAttribute) AppendBER(dst []byte) ([]byte, error) {
	return appendAttribute(dst, a.Type, a.Values, a.Extensions, false)
}

//revive:disable-next-line:exported
func (a *PartialAttribute) UnmarshalBER(r *ber.Reader) error {
	if a == nil {
		return errors.New("rfc4511: nil PartialAttribute receiver")
	}
	typeValue, values, extensions, err := decodeAttribute(r, false)
	if err != nil {
		return err
	}
	*a = PartialAttribute{Type: typeValue, Values: values, Extensions: extensions}
	return nil
}

//revive:disable-next-line:exported
func (a Attribute) AppendBER(dst []byte) ([]byte, error) {
	return appendAttribute(dst, a.Type, a.Values, a.Extensions, true)
}

//revive:disable-next-line:exported
func (a *Attribute) UnmarshalBER(r *ber.Reader) error {
	if a == nil {
		return errors.New("rfc4511: nil Attribute receiver")
	}
	typeValue, values, extensions, err := decodeAttribute(r, true)
	if err != nil {
		return err
	}
	*a = Attribute{Type: typeValue, Values: values, Extensions: extensions}
	return nil
}

func appendAttribute(
	dst []byte,
	typeValue AttributeDescription,
	values []AttributeValue,
	extensions []UnknownField,
	requireValue bool,
) ([]byte, error) {
	start := len(dst)
	if len(typeValue) == 0 {
		return dst, errors.New("rfc4511: attribute type is empty")
	}
	if requireValue && len(values) == 0 {
		return dst, errors.New("rfc4511: Attribute requires at least one value")
	}

	contents, err := ber.AppendOctetString(nil, typeValue)
	if err != nil {
		return dst[:start], err
	}
	setContents := make([]byte, 0)
	for i, value := range values {
		setContents, err = ber.AppendOctetString(setContents, value)
		if err != nil {
			return dst[:start], fmt.Errorf("rfc4511: attribute value %d: %w", i, err)
		}
	}
	contents, err = ber.AppendSet(contents, setContents)
	if err != nil {
		return dst[:start], err
	}
	contents, err = appendUnknownFields(contents, extensions)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendSequence(dst, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

func decodeAttribute(r *ber.Reader, requireValue bool) (
	AttributeDescription,
	[]AttributeValue,
	[]UnknownField,
	error,
) {
	contents, err := r.Sequence()
	if err != nil {
		return nil, nil, nil, err
	}
	typeValue, err := contents.OctetString()
	if err != nil {
		return nil, nil, nil, err
	}
	if len(typeValue) == 0 {
		return nil, nil, nil, errors.New("rfc4511: attribute type is empty")
	}
	valueSet, err := contents.Set()
	if err != nil {
		return nil, nil, nil, err
	}
	var values []AttributeValue
	for !valueSet.Empty() {
		value, err := valueSet.OctetString()
		if err != nil {
			return nil, nil, nil, err
		}
		values = append(values, AttributeValue(bytes.Clone(value)))
	}
	if requireValue && len(values) == 0 {
		return nil, nil, nil, errors.New("rfc4511: Attribute requires at least one value")
	}
	extensions, err := decodeUnknownFields(contents)
	if err != nil {
		return nil, nil, nil, err
	}
	return AttributeDescription(bytes.Clone(typeValue)), values, extensions, nil
}

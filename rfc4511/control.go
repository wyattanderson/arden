package rfc4511

import (
	"bytes"
	"fmt"

	"github.com/wyattanderson/arden/ber"
)

// Control is the RFC 4511 wire representation of an LDAP control. HasValue
// distinguishes an absent controlValue from a present, empty value.
// Extensions preserves allowed unknown trailing fields in source order.
//
// RFC 4511 section 4.1.11.
type Control struct {
	Type        LDAPOID
	Criticality bool
	Value       []byte
	HasValue    bool
	Extensions  []UnknownField
}

func (v Control) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if err := requireNonEmpty("control type", v.Type); err != nil {
		return dst, err
	}
	if err := validateLDAPOID(v.Type); err != nil {
		return dst, err
	}
	contents, err := ber.AppendOctetString(nil, v.Type)
	if err != nil {
		return dst[:start], err
	}
	if v.Criticality {
		contents, err = ber.AppendBoolean(contents, true)
		if err != nil {
			return dst[:start], err
		}
	}
	if v.HasValue {
		contents, err = ber.AppendOctetString(contents, v.Value)
		if err != nil {
			return dst[:start], err
		}
	}
	contents, err = appendUnknownFields(contents, v.Extensions)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendSequence(dst, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

func (v *Control) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return nilReceiver("Control")
	}
	contents, err := r.Sequence()
	if err != nil {
		return err
	}
	typeValue, err := contents.OctetString()
	if err != nil {
		return err
	}
	if err := requireNonEmpty("control type", typeValue); err != nil {
		return err
	}
	if err := validateLDAPOID(typeValue); err != nil {
		return err
	}
	decoded := Control{Type: LDAPOID(bytes.Clone(typeValue))}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == ber.BooleanIdentifier {
			decoded.Criticality, err = contents.Boolean()
			if err != nil {
				return err
			}
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == ber.OctetStringIdentifier {
			value, err := contents.OctetString()
			if err != nil {
				return err
			}
			decoded.Value, decoded.HasValue = bytes.Clone(value), true
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == ber.BooleanIdentifier || id == ber.OctetStringIdentifier {
			return fmt.Errorf("rfc4511: duplicate or out-of-order Control field %s", id)
		}
		decoded.Extensions, err = decodeUnknownFields(contents)
		if err != nil {
			return err
		}
	}
	*v = decoded
	return nil
}

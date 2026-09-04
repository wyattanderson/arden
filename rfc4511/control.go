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

// BERPacket returns the control packet.
func (v Control) BERPacket() ber.Packet {
	control := ber.Sequence().Add(ber.OctetString(v.Type))
	if v.Criticality {
		control.Add(ber.Boolean(true))
	}
	if v.HasValue {
		control.Add(ber.OctetString(v.Value))
	}
	return control.Add(v.Extensions...).BERPacket()
}

//revive:disable-next-line:exported
func (v *Control) UnmarshalBER(r *ber.Reader) error {
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
	decoded := Control{Type: LDAPOID(string(typeValue))}
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
			return fmt.Errorf("arden: duplicate or out-of-order Control field %s", id)
		}
		decoded.Extensions, err = decodeUnknownFields(contents)
		if err != nil {
			return err
		}
	}
	*v = decoded
	return nil
}

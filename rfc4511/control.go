package rfc4511

import (
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
	d := ber.NewDecoder(r).Sequence()
	decoded := Control{Type: d.Read[LDAPOID]()}
	if d.NextIs(ber.BooleanIdentifier) {
		decoded.Criticality = d.Boolean()
	}
	if d.NextIs(ber.OctetStringIdentifier) {
		decoded.Value = d.OctetString[[]byte]()
		decoded.HasValue = true
	}
	decoded.Extensions = d.Extensions[UnknownField](ber.BooleanIdentifier, ber.OctetStringIdentifier)
	if err := d.End(); err != nil {
		return err
	}
	*v = decoded
	return nil
}

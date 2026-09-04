package rfc4511

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/wyattanderson/arden/ber"
)

// LDAPString is UTF-8 LDAP text with an OCTET STRING wire encoding.
type LDAPString string

// LDAPOID is a textual LDAP object identifier.
type LDAPOID string

// LDAPDN is a textual LDAP distinguished name.
type LDAPDN string

// RelativeLDAPDN is a textual LDAP relative distinguished name.
type RelativeLDAPDN string

// URI is a textual LDAP uniform resource identifier.
type URI string

// AttributeDescription is a textual LDAP attribute description.
type AttributeDescription string

// AttributeSelector is a textual LDAP search attribute selector.
type AttributeSelector string

// MatchingRuleID is a textual LDAP matching rule identifier.
type MatchingRuleID string

// AttributeValue is a byte-oriented LDAP attribute value.
type AttributeValue []byte

// AssertionValue is a byte-oriented LDAP assertion value.
type AssertionValue []byte

type ldapText interface {
	LDAPString | LDAPOID | LDAPDN | RelativeLDAPDN | URI | AttributeDescription | AttributeSelector | MatchingRuleID
}

type ldapBytes interface {
	AttributeValue | AssertionValue
}

func unmarshalLDAPText[T ldapText](dst *T, r *ber.Reader, id ber.Identifier) error {
	if dst == nil {
		return errors.New("arden: nil OCTET STRING receiver")
	}
	value, err := r.Primitive(id)
	if err != nil {
		return err
	}
	if !utf8.Valid(value) {
		return errors.New("arden: LDAP text is not valid UTF-8")
	}
	// Conversion gives the text its own storage without an intermediate clone.
	*dst = T(value)
	return nil
}

func unmarshalLDAPBytes[T ldapBytes](dst *T, r *ber.Reader, id ber.Identifier) error {
	if dst == nil {
		return errors.New("arden: nil LDAP byte value receiver")
	}
	d := ber.NewDecoder(r)
	value := d.Primitive[T](id)
	if err := d.Err(); err != nil {
		return err
	}
	*dst = value
	return nil
}

// BERPacket returns v as an OCTET STRING packet.
func (v LDAPString) BERPacket() ber.Packet { return ber.OctetString(v) }

//revive:disable-next-line:exported
func (v *LDAPString) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.OctetStringIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the LDAPString decoder to an implicit identifier.
func (v *LDAPString) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		return unmarshalLDAPText(v, r, id)
	})
}

// BERPacket returns v as an OCTET STRING packet.
func (v LDAPOID) BERPacket() ber.Packet { return ber.OctetString(v) }

//revive:disable-next-line:exported
func (v *LDAPOID) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.OctetStringIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the LDAP OID decoder to an implicit identifier.
func (v *LDAPOID) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		var decoded LDAPOID
		if err := unmarshalLDAPText(&decoded, r, id); err != nil {
			return err
		}
		if err := validateLDAPOID(decoded); err != nil {
			return err
		}
		*v = decoded
		return nil
	})
}

// BERPacket returns v as an OCTET STRING packet.
func (v LDAPDN) BERPacket() ber.Packet { return ber.OctetString(v) }

//revive:disable-next-line:exported
func (v *LDAPDN) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.OctetStringIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the LDAPDN decoder to an implicit identifier.
func (v *LDAPDN) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		return unmarshalLDAPText(v, r, id)
	})
}

// BERPacket returns v as an OCTET STRING packet.
func (v RelativeLDAPDN) BERPacket() ber.Packet { return ber.OctetString(v) }

//revive:disable-next-line:exported
func (v *RelativeLDAPDN) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.OctetStringIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the RelativeLDAPDN decoder to an implicit identifier.
func (v *RelativeLDAPDN) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		return unmarshalLDAPText(v, r, id)
	})
}

// BERPacket returns v as an OCTET STRING packet.
func (v URI) BERPacket() ber.Packet { return ber.OctetString(v) }

//revive:disable-next-line:exported
func (v *URI) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.OctetStringIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the URI decoder to an implicit identifier.
func (v *URI) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		return unmarshalLDAPText(v, r, id)
	})
}

// BERPacket returns v as an OCTET STRING packet.
func (v AttributeDescription) BERPacket() ber.Packet { return ber.OctetString(v) }

//revive:disable-next-line:exported
func (v *AttributeDescription) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.OctetStringIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the AttributeDescription decoder to an implicit identifier.
func (v *AttributeDescription) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		return unmarshalLDAPText(v, r, id)
	})
}

// BERPacket returns v as an OCTET STRING packet.
func (v AttributeSelector) BERPacket() ber.Packet { return ber.OctetString(v) }

//revive:disable-next-line:exported
func (v *AttributeSelector) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.OctetStringIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the AttributeSelector decoder to an implicit identifier.
func (v *AttributeSelector) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		return unmarshalLDAPText(v, r, id)
	})
}

// BERPacket returns v as an OCTET STRING packet.
func (v MatchingRuleID) BERPacket() ber.Packet { return ber.OctetString(v) }

//revive:disable-next-line:exported
func (v *MatchingRuleID) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.OctetStringIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the MatchingRuleID decoder to an implicit identifier.
func (v *MatchingRuleID) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		return unmarshalLDAPText(v, r, id)
	})
}

// BERPacket returns v as an OCTET STRING packet.
func (v AttributeValue) BERPacket() ber.Packet { return ber.OctetString(v) }

//revive:disable-next-line:exported
func (v *AttributeValue) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.OctetStringIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the AttributeValue decoder to an implicit identifier.
func (v *AttributeValue) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		return unmarshalLDAPBytes(v, r, id)
	})
}

// BERPacket returns v as an OCTET STRING packet.
func (v AssertionValue) BERPacket() ber.Packet { return ber.OctetString(v) }

//revive:disable-next-line:exported
func (v *AssertionValue) UnmarshalBER(r *ber.Reader) error {
	return v.UnmarshalAs(ber.OctetStringIdentifier).UnmarshalBER(r)
}

// UnmarshalAs binds the AssertionValue decoder to an implicit identifier.
func (v *AssertionValue) UnmarshalAs(id ber.Identifier) ber.Unmarshaler {
	return ber.UnmarshalFunc(func(r *ber.Reader) error {
		return unmarshalLDAPBytes(v, r, id)
	})
}

// UnknownField preserves one complete, allowed trailing BER field from an
// extensible RFC 4511 SEQUENCE. Its bytes are copied while decoding and cannot
// be supplied or mutated by callers. Bytes returns a further copy.
type UnknownField struct {
	identifier ber.Identifier
	raw        []byte
}

// Identifier returns the preserved field's BER identifier.
func (f UnknownField) Identifier() ber.Identifier { return f.identifier }

// Bytes returns the complete preserved BER encoding in an independent slice.
func (f UnknownField) Bytes() []byte { return bytes.Clone(f.raw) }

// BERPacket returns the preserved complete BER packet.
func (f UnknownField) BERPacket() ber.Packet { return ber.Encoded(f.raw) }

func unknownField(e ber.Element) UnknownField {
	return UnknownField{identifier: e.Identifier, raw: bytes.Clone(e.Raw)}
}

// UnmarshalBER preserves a complete unknown field, validating its nested BER
// contents and copying all retained bytes.
func (f *UnknownField) UnmarshalBER(r *ber.Reader) error {
	e, err := r.SkipElement()
	if err != nil {
		return err
	}
	*f = unknownField(e)
	return nil
}

// validateLDAPOID implements RFC 4512 section 1.4's numericoid grammar. It
// is intentionally byte-oriented and does not parse DNs, schema values, or
// filter strings.
func validateLDAPOID[T ~string | ~[]byte](value T) error {
	parts := 0
	digits := 0
	leadingZero := false
	for _, b := range []byte(value) {
		switch {
		case b >= '0' && b <= '9':
			if digits == 0 {
				leadingZero = b == '0'
			} else if leadingZero {
				return errors.New("arden: LDAPOID has a leading zero")
			}
			digits++
		case b == '.':
			if digits == 0 {
				return errors.New("arden: LDAPOID has an empty arc")
			}
			parts++
			digits, leadingZero = 0, false
		default:
			return fmt.Errorf("arden: LDAPOID contains non-numeric byte %q", b)
		}
	}
	if digits == 0 {
		return errors.New("arden: LDAPOID has an empty arc")
	}
	if parts == 0 {
		return errors.New("arden: LDAPOID requires at least two arcs")
	}
	return nil
}

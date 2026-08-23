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

func appendLDAPText[T ldapText](dst []byte, value T) ([]byte, error) {
	if !utf8.ValidString(string(value)) {
		return dst, errors.New("arden: LDAP text is not valid UTF-8")
	}
	return ber.AppendOctetString(dst, []byte(value))
}

func unmarshalLDAPText[T ldapText](dst *T, r *ber.Reader) error {
	if dst == nil {
		return errors.New("arden: nil OCTET STRING receiver")
	}
	value, err := r.OctetString()
	if err != nil {
		return err
	}
	if !utf8.Valid(value) {
		return errors.New("arden: LDAP text is not valid UTF-8")
	}
	*dst = T(string(value))
	return nil
}

func appendLDAPBytes[T ldapBytes](dst []byte, value T) ([]byte, error) {
	return ber.AppendOctetString(dst, []byte(value))
}

func unmarshalLDAPBytes[T ldapBytes](dst *T, r *ber.Reader) error {
	if dst == nil {
		return errors.New("arden: nil LDAP byte value receiver")
	}
	value, err := r.OctetString()
	if err != nil {
		return err
	}
	*dst = T(bytes.Clone(value))
	return nil
}

//revive:disable-next-line:exported
func (v LDAPString) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPText(dst, v)
}

//revive:disable-next-line:exported
func (v *LDAPString) UnmarshalBER(r *ber.Reader) error { return unmarshalLDAPText(v, r) }

//revive:disable-next-line:exported
func (v LDAPOID) AppendBER(dst []byte) ([]byte, error) {
	if err := validateLDAPOID(v); err != nil {
		return dst, err
	}
	return appendLDAPText(dst, v)
}

//revive:disable-next-line:exported
func (v *LDAPOID) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return errors.New("arden: nil LDAPOID receiver")
	}
	value, err := r.OctetString()
	if err != nil {
		return err
	}
	if !utf8.Valid(value) {
		return errors.New("arden: LDAP OID is not valid UTF-8")
	}
	if err := validateLDAPOID(string(value)); err != nil {
		return err
	}
	*v = LDAPOID(string(value))
	return nil
}

//revive:disable-next-line:exported
func (v LDAPDN) AppendBER(dst []byte) ([]byte, error) { return appendLDAPText(dst, v) }

//revive:disable-next-line:exported
func (v *LDAPDN) UnmarshalBER(r *ber.Reader) error { return unmarshalLDAPText(v, r) }

//revive:disable-next-line:exported
func (v RelativeLDAPDN) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPText(dst, v)
}

//revive:disable-next-line:exported
func (v *RelativeLDAPDN) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPText(v, r)
}

//revive:disable-next-line:exported
func (v URI) AppendBER(dst []byte) ([]byte, error) { return appendLDAPText(dst, v) }

//revive:disable-next-line:exported
func (v *URI) UnmarshalBER(r *ber.Reader) error { return unmarshalLDAPText(v, r) }

//revive:disable-next-line:exported
func (v AttributeDescription) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPText(dst, v)
}

//revive:disable-next-line:exported
func (v *AttributeDescription) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPText(v, r)
}

//revive:disable-next-line:exported
func (v AttributeSelector) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPText(dst, v)
}

//revive:disable-next-line:exported
func (v *AttributeSelector) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPText(v, r)
}

//revive:disable-next-line:exported
func (v MatchingRuleID) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPText(dst, v)
}

//revive:disable-next-line:exported
func (v *MatchingRuleID) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPText(v, r)
}

//revive:disable-next-line:exported
func (v AttributeValue) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPBytes(dst, v)
}

//revive:disable-next-line:exported
func (v *AttributeValue) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPBytes(v, r)
}

//revive:disable-next-line:exported
func (v AssertionValue) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPBytes(dst, v)
}

//revive:disable-next-line:exported
func (v *AssertionValue) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPBytes(v, r)
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

func unknownField(e ber.Element) UnknownField {
	return UnknownField{identifier: e.Identifier, raw: bytes.Clone(e.Raw)}
}

func appendUnknownFields(dst []byte, fields []UnknownField) ([]byte, error) {
	start := len(dst)
	for i, field := range fields {
		if len(field.raw) == 0 {
			return dst[:start], fmt.Errorf("arden: unknown field %d was not decoded", i)
		}
		dst = append(dst, field.raw...)
	}
	return dst, nil
}

func decodeUnknownFields(r *ber.Reader) ([]UnknownField, error) {
	var fields []UnknownField
	for !r.Empty() {
		e, err := r.SkipElement()
		if err != nil {
			return nil, err
		}
		fields = append(fields, unknownField(e))
	}
	return fields, nil
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

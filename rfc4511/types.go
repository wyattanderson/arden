package rfc4511

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/wyattanderson/arden/ber"
)

// These distinct byte-oriented types share an OCTET STRING wire encoding but
// carry different LDAP meanings. RFC 4511 sections 4.1.2 through 4.1.6 define
// their wire forms. They deliberately do not normalize DNs, interpret schema,
// or convert attribute values through Go strings.
type (
	LDAPString           []byte
	LDAPOID              []byte
	LDAPDN               []byte
	RelativeLDAPDN       []byte
	URI                  []byte
	AttributeDescription []byte
	AttributeSelector    []byte
	MatchingRuleID       []byte
	AttributeValue       []byte
	AssertionValue       []byte
)

type ldapOctets interface {
	LDAPString | LDAPOID | LDAPDN | RelativeLDAPDN | URI | AttributeDescription | AttributeSelector | MatchingRuleID | AttributeValue | AssertionValue
}

func appendLDAPOctets[T ldapOctets](dst []byte, value T) ([]byte, error) {
	return ber.AppendOctetString(dst, []byte(value))
}

func unmarshalLDAPOctets[T ldapOctets](dst *T, r *ber.Reader) error {
	if dst == nil {
		return errors.New("rfc4511: nil OCTET STRING receiver")
	}
	value, err := r.OctetString()
	if err != nil {
		return err
	}
	*dst = T(bytes.Clone(value))
	return nil
}

func (v LDAPString) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPOctets(dst, v)
}
func (v *LDAPString) UnmarshalBER(r *ber.Reader) error { return unmarshalLDAPOctets(v, r) }

func (v LDAPOID) AppendBER(dst []byte) ([]byte, error) {
	if err := validateLDAPOID(v); err != nil {
		return dst, err
	}
	return appendLDAPOctets(dst, v)
}
func (v *LDAPOID) UnmarshalBER(r *ber.Reader) error {
	if v == nil {
		return errors.New("rfc4511: nil LDAPOID receiver")
	}
	value, err := r.OctetString()
	if err != nil {
		return err
	}
	if err := validateLDAPOID(value); err != nil {
		return err
	}
	*v = LDAPOID(bytes.Clone(value))
	return nil
}

func (v LDAPDN) AppendBER(dst []byte) ([]byte, error) { return appendLDAPOctets(dst, v) }
func (v *LDAPDN) UnmarshalBER(r *ber.Reader) error    { return unmarshalLDAPOctets(v, r) }

func (v RelativeLDAPDN) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPOctets(dst, v)
}
func (v *RelativeLDAPDN) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPOctets(v, r)
}

func (v URI) AppendBER(dst []byte) ([]byte, error) { return appendLDAPOctets(dst, v) }
func (v *URI) UnmarshalBER(r *ber.Reader) error    { return unmarshalLDAPOctets(v, r) }

func (v AttributeDescription) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPOctets(dst, v)
}
func (v *AttributeDescription) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPOctets(v, r)
}

func (v AttributeSelector) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPOctets(dst, v)
}
func (v *AttributeSelector) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPOctets(v, r)
}

func (v MatchingRuleID) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPOctets(dst, v)
}
func (v *MatchingRuleID) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPOctets(v, r)
}

func (v AttributeValue) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPOctets(dst, v)
}
func (v *AttributeValue) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPOctets(v, r)
}

func (v AssertionValue) AppendBER(dst []byte) ([]byte, error) {
	return appendLDAPOctets(dst, v)
}
func (v *AssertionValue) UnmarshalBER(r *ber.Reader) error {
	return unmarshalLDAPOctets(v, r)
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
			return dst[:start], fmt.Errorf("rfc4511: unknown field %d was not decoded", i)
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
func validateLDAPOID(value []byte) error {
	parts := 0
	digits := 0
	leadingZero := false
	for _, b := range value {
		switch {
		case b >= '0' && b <= '9':
			if digits == 0 {
				leadingZero = b == '0'
			} else if leadingZero {
				return errors.New("rfc4511: LDAPOID has a leading zero")
			}
			digits++
		case b == '.':
			if digits == 0 {
				return errors.New("rfc4511: LDAPOID has an empty arc")
			}
			parts++
			digits, leadingZero = 0, false
		default:
			return fmt.Errorf("rfc4511: LDAPOID contains non-numeric byte %q", b)
		}
	}
	if digits == 0 {
		return errors.New("rfc4511: LDAPOID has an empty arc")
	}
	if parts == 0 {
		return errors.New("rfc4511: LDAPOID requires at least two arcs")
	}
	return nil
}

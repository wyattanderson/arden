package arden

import (
	"bytes"
	"strings"

	"github.com/wyattanderson/arden/rfc4511"
)

// Entry is a schema-neutral LDAP entry. Text helpers are the ordinary API;
// raw byte helpers preserve binary attribute syntaxes without conversion.
type Entry struct {
	DN         LDAPDN
	Attributes []Attribute
}

// NewEntry constructs an entry suitable for Add.
func NewEntry(dn LDAPDN) *Entry { return &Entry{DN: dn} }

// Set replaces name with text values.
func (e *Entry) Set(name string, values ...string) {
	raw := make([][]byte, len(values))
	for i, value := range values {
		raw[i] = []byte(value)
	}
	e.setRaw(name, raw)
}

// SetBytes replaces name with independently owned raw values.
func (e *Entry) SetBytes(name string, values ...[]byte) { e.setRaw(name, values) }

func (e *Entry) setRaw(name string, values [][]byte) {
	attribute := Attribute{Type: rfc4511.AttributeDescription(name), Values: cloneAttributeValues(values)}
	for i := range e.Attributes {
		if strings.EqualFold(string(e.Attributes[i].Type), name) {
			e.Attributes[i] = attribute
			return
		}
	}
	e.Attributes = append(e.Attributes, attribute)
}

// Value returns the first value as a string, or an empty string when absent.
// Go strings preserve arbitrary bytes; use RawValue when the syntax is binary.
func (e Entry) Value(name string) string {
	value := e.RawValue(name)
	return string(value)
}

// Values returns all values converted to strings.
func (e Entry) Values(name string) []string {
	raw := e.RawValues(name)
	values := make([]string, len(raw))
	for i := range raw {
		values[i] = string(raw[i])
	}
	return values
}

// RawValue returns an independent copy of the first value, or nil when absent.
func (e Entry) RawValue(name string) []byte {
	values := e.RawValues(name)
	if len(values) == 0 {
		return nil
	}
	return values[0]
}

// RawValues returns independent copies of all values for name.
func (e Entry) RawValues(name string) [][]byte {
	for _, attribute := range e.Attributes {
		if strings.EqualFold(string(attribute.Type), name) {
			values := make([][]byte, len(attribute.Values))
			for i := range attribute.Values {
				values[i] = bytes.Clone(attribute.Values[i])
			}
			return values
		}
	}
	return nil
}

// Contains reports whether name has the exact text value.
func (e Entry) Contains(name, value string) bool {
	for _, candidate := range e.RawValues(name) {
		if bytes.Equal(candidate, []byte(value)) {
			return true
		}
	}
	return false
}

func cloneAttributeValues[T ~[]byte](values []T) []rfc4511.AttributeValue {
	cloned := make([]rfc4511.AttributeValue, len(values))
	for i := range values {
		cloned[i] = bytes.Clone(values[i])
	}
	return cloned
}

func entryFromSearchResult(wire rfc4511.SearchResultEntry) Entry {
	attributes := make([]Attribute, len(wire.Attributes))
	for i, attribute := range wire.Attributes {
		attributes[i] = Attribute(attribute)
	}
	return Entry{DN: wire.ObjectName, Attributes: attributes}
}

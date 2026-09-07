package arden

import (
	"bytes"

	"github.com/wyattanderson/arden/rfc4511"
)

// Entry is a schema-neutral LDAP entry. Text helpers are the ordinary API;
// Attributes provides direct access to shared raw values. Copies of an entry
// share its initialized attribute collection; use Attributes.Clone to detach.
type Entry struct {
	DN         LDAPDN
	Attributes Attributes
}

// NewEntry constructs an entry suitable for Add.
func NewEntry(dn LDAPDN) *Entry { return &Entry{DN: dn} }

// Set replaces name with text values, allocating only the final value slice
// and the bytes for each string.
func (e *Entry) Set(name string, values ...string) {
	raw := make([]rfc4511.AttributeValue, len(values))
	for i, value := range values {
		raw[i] = []byte(value)
	}
	e.Attributes.Set(Attribute{Type: rfc4511.AttributeDescription(name), Values: raw})
}

// SetBytes replaces name with raw values. It copies the outer value slice to
// the wire value type but shares the supplied bytes. Callers with an existing
// []rfc4511.AttributeValue can use Attributes.Set to share that slice too.
func (e *Entry) SetBytes(name string, values ...[]byte) {
	raw := make([]rfc4511.AttributeValue, len(values))
	for i, value := range values {
		raw[i] = value
	}
	e.Attributes.Set(Attribute{Type: rfc4511.AttributeDescription(name), Values: raw})
}

// Value returns the first value as a string, or an empty string when absent.
// Go strings preserve arbitrary bytes; use RawValue when the syntax is binary.
func (e Entry) Value(name string) string { return string(e.RawValue(name)) }

// Values returns all values converted to independent strings.
func (e Entry) Values(name string) []string {
	attribute, _ := e.Attributes.Lookup(rfc4511.AttributeDescription(name))
	values := make([]string, len(attribute.Values))
	for i, value := range attribute.Values {
		values[i] = string(value)
	}
	return values
}

// RawValue returns the first value's bytes, or nil when absent. Mutating the
// returned bytes changes the entry. Use Attributes.Lookup for all raw values.
func (e Entry) RawValue(name string) []byte {
	attribute, _ := e.Attributes.Lookup(rfc4511.AttributeDescription(name))
	if len(attribute.Values) == 0 {
		return nil
	}
	return attribute.Values[0]
}

// Contains reports whether name has the exact text value.
func (e Entry) Contains(name, value string) bool {
	attribute, _ := e.Attributes.Lookup(rfc4511.AttributeDescription(name))
	for _, candidate := range attribute.Values {
		if bytes.Equal(candidate, []byte(value)) {
			return true
		}
	}
	return false
}

func entryFromSearchResult(wire rfc4511.SearchResultEntry) Entry {
	return Entry{DN: wire.ObjectName, Attributes: wire.Attributes}
}

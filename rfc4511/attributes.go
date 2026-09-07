package rfc4511

import (
	"bytes"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/wyattanderson/arden/ber"
)

// AttributeKey is an opaque, comparable attribute-description lookup key.
// Equivalent descriptions have equal keys. Keys do not resolve schema aliases
// or attribute subtypes. The zero key denotes an empty (invalid) description.
type AttributeKey struct{ normalized string }

// Key lowercases the description and sorts and deduplicates attribute options.
// Like packet constructors, it assumes a syntactically valid description.
// Prepare keys once for repeated lookups; already canonical names without
// options require no allocation.
func (d AttributeDescription) Key() AttributeKey {
	name := strings.ToLower(string(d))
	base, options, found := strings.Cut(name, ";")
	if !found {
		return AttributeKey{normalized: name}
	}
	// Canonically ordered options need no split, sort, or allocation either.
	previous, rest, more := strings.Cut(options, ";")
	canonical := true
	for more {
		var next string
		next, rest, more = strings.Cut(rest, ";")
		if previous >= next {
			canonical = false
			break
		}
		previous = next
	}
	if canonical {
		return AttributeKey{normalized: name}
	}
	parts := strings.Split(options, ";")
	slices.Sort(parts)
	return AttributeKey{normalized: base + ";" + strings.Join(slices.Compact(parts), ";")}
}

// Attributes is an ordered collection indexed by normalized descriptions.
// Its zero value is empty and ready for use. Copies of an initialized collection
// share all mutations; use Clone for independent mutable storage. Concurrent
// reads are safe only while the collection and its shared values are unchanged.
type Attributes struct{ store *attributeStore }

// Keep the slice and index together when Attributes (and Entry) are copied.
// Index eagerly for predictable model lookup costs. If profiles later show many
// entries are never inspected, indexing could become lazy behind the same API;
// that would also require preserving the concurrent-read contract.
type attributeStore struct {
	ordered []Attribute
	index   map[AttributeKey]int
}

// NewAttributes constructs a collection in insertion order. Equivalent
// descriptions replace earlier attributes in place. Values and extensions are
// shared, but the caller's outer attribute slice is not retained.
func NewAttributes(attributes ...Attribute) Attributes {
	var result Attributes
	if len(attributes) == 0 {
		return result
	}
	result.store = &attributeStore{
		ordered: make([]Attribute, 0, len(attributes)),
		index:   make(map[AttributeKey]int, len(attributes)),
	}
	for _, attribute := range attributes {
		result.Set(attribute)
	}
	return result
}

// Len returns the number of distinct attribute descriptions.
func (a Attributes) Len() int {
	if a.store == nil {
		return 0
	}
	return len(a.store.ordered)
}

// Lookup returns an attribute by its complete description, ignoring ASCII case
// and option order. The boolean distinguishes absence from a present attribute
// with no values. Values and extensions share storage with the collection.
// Changing the returned Type does not rename the stored attribute. Renaming
// requires deleting the old description and setting the new one.
func (a Attributes) Lookup(name AttributeDescription) (Attribute, bool) {
	return a.LookupKey(name.Key())
}

// LookupKey looks up a prepared key without normalizing or allocating.
func (a Attributes) LookupKey(key AttributeKey) (Attribute, bool) {
	if a.store == nil {
		return Attribute{}, false
	}
	i, ok := a.store.index[key]
	if !ok {
		return Attribute{}, false
	}
	return a.store.ordered[i], true
}

// Set replaces an equivalent description in place or appends a new attribute.
// It retains the supplied spelling, values, and extensions without copying their
// backing storage. Construction assumes valid attribute descriptions.
func (a *Attributes) Set(attribute Attribute) {
	a.set(attribute.Type.Key(), attribute)
}

// set reports whether it replaced an existing description. Decoding can use
// this result to reject duplicates in its private temporary collection without
// performing a second map lookup for every incoming attribute.
func (a *Attributes) set(key AttributeKey, attribute Attribute) bool {
	if a.store == nil {
		a.store = &attributeStore{index: make(map[AttributeKey]int)}
	}
	if i, ok := a.store.index[key]; ok {
		a.store.ordered[i] = attribute
		return true
	}
	a.store.index[key] = len(a.store.ordered)
	a.store.ordered = append(a.store.ordered, attribute)
	return false
}

// Delete removes a description, preserving the relative order of the others.
// It reports whether an attribute was removed.
func (a *Attributes) Delete(name AttributeDescription) bool {
	if a.store == nil {
		return false
	}
	key := name.Key()
	i, ok := a.store.index[key]
	if !ok {
		return false
	}
	delete(a.store.index, key)
	a.store.ordered = slices.Delete(a.store.ordered, i, i+1)
	for existing, position := range a.store.index {
		if position > i {
			a.store.index[existing] = position - 1
		}
	}
	return true
}

// All visits attributes in insertion/wire order. Returned attributes share
// value and extension storage. Do not structurally mutate the collection during
// iteration. Iteration stops when the caller breaks.
func (a Attributes) All() iter.Seq[Attribute] {
	return func(yield func(Attribute) bool) {
		if a.store == nil {
			return
		}
		for _, attribute := range a.store.ordered {
			if !yield(attribute) {
				return
			}
		}
	}
}

// Clone copies the collection and all mutable backing storage. Immutable
// UnknownField payloads may be shared; their public byte accessors copy.
func (a Attributes) Clone() Attributes {
	if a.Len() == 0 {
		return Attributes{}
	}
	result := NewAttributes(a.store.ordered...)
	for i := range result.store.ordered {
		attribute := &result.store.ordered[i]
		attribute.Values = slices.Clone(attribute.Values)
		for j, value := range attribute.Values {
			attribute.Values[j] = bytes.Clone(value)
		}
		attribute.Extensions = slices.Clone(attribute.Extensions)
	}
	return result
}

// BERPacket constructs the attribute SEQUENCE directly from stored attributes.
// It retains value bytes until encoding finishes and does not cache encoding:
// callers may mutate shared values between encodings.
func (a Attributes) BERPacket() ber.Packet {
	if a.store == nil {
		return ber.Sequence().BERPacket()
	}
	return ber.Sequence().Add(a.store.ordered...).BERPacket()
}

// UnmarshalBER decodes an attribute SEQUENCE, building its index as attributes
// arrive. Duplicate normalized descriptions are rejected. Retained bytes are
// owned by the decoded attributes; the receiver is unchanged on failure.
func (a *Attributes) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Sequence()
	var decoded Attributes
	for d.More() {
		attribute := d.Read[Attribute]()
		if d.Err() != nil {
			break
		}
		key := attribute.Type.Key()
		if decoded.set(key, attribute) {
			d.Fail(fmt.Errorf("arden: duplicate attribute description %q", attribute.Type))
			break
		}
	}
	if err := d.End(); err != nil {
		return err
	}
	*a = decoded
	return nil
}

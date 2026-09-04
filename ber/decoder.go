package ber

import (
	"bytes"
	"fmt"
)

// UnmarshalFunc adapts a decoding function to Unmarshaler.
type UnmarshalFunc func(*Reader) error

// UnmarshalBER invokes f.
func (f UnmarshalFunc) UnmarshalBER(r *Reader) error { return f(r) }

// TaggedUnmarshaler binds a value's decoder to an alternate complete BER
// identifier. The adapter must validate that identifier, decode exactly one
// value, and leave its receiver unchanged on failure.
type TaggedUnmarshaler interface {
	UnmarshalAs(Identifier) Unmarshaler
}

// FieldsUnmarshaler decodes a type's known components in an enclosing scope.
// It must not enter an envelope, consume trailing extensions, or call End.
// The enclosing type owns those operations. Reserve transfers any identifiers
// that must not reappear as extensions to that enclosing scope.
// Implementations must leave their receiver unchanged on failure.
type FieldsUnmarshaler interface {
	UnmarshalBERFields(*Decoder) error
}

type decoderState struct{ err error }

// Decoder is a scoped, first-error decoder over a bounded Reader. Child scopes
// share the first failure; subsequent operations return zero values without
// reading input or invoking custom decoders. Decode into temporary values and
// check End (for a complete scope) or Err before publishing them.
//
// Decoder never relaxes Reader's limits. It is not safe for concurrent use.
type Decoder struct {
	reader   *Reader
	state    *decoderState
	child    *Decoder
	reserved map[Identifier]struct{}
}

// NewDecoder wraps r without consuming input. r must be non-nil. A decoder and
// its child scopes exclusively own the reader until decoding is complete.
func NewDecoder(r *Reader) *Decoder {
	return &Decoder{reader: r, state: new(decoderState)}
}

// Fail records the first non-nil error, with its current input offset.
func (d *Decoder) Fail(err error) {
	if err != nil && d.state.err == nil {
		d.state.err = decodeError(d.reader.Offset(), err)
	}
}

// Err returns the first failure. Any outstanding child scope is finished, but
// this scope may still contain unread siblings.
func (d *Decoder) Err() error {
	d.ready()
	return d.state.err
}

// End finishes this scope, rejecting unread contents rather than skipping
// them. Unknown trailing fields must be consumed explicitly with Extensions.
func (d *Decoder) End() error {
	if d.ready() {
		d.Fail(d.reader.RequireEmpty())
	}
	return d.state.err
}

func (d *Decoder) ready() bool {
	if d.state.err != nil {
		return false
	}
	if d.child != nil {
		child := d.child
		d.child = nil
		d.Fail(child.End())
	}
	return d.state.err == nil
}

// More reports whether this scope has unread contents and has not failed.
func (d *Decoder) More() bool { return d.ready() && !d.reader.Empty() }

// PeekIdentifier inspects the next required value without consuming it.
func (d *Decoder) PeekIdentifier() Identifier { return d.Using((*Reader).PeekIdentifier) }

// NextIs reports whether the next optional value has id. An empty scope is
// absence, while a malformed identifier records a decoding failure.
func (d *Decoder) NextIs(id Identifier) bool {
	return d.More() && d.PeekIdentifier() == id && d.state.err == nil
}

// Constructed enters the value with id. The returned scope is never nil, even
// on failure. It must be consumed before the parent reads another field;
// parent operations automatically finish an outstanding child scope.
func (d *Decoder) Constructed(id Identifier) *Decoder {
	child := &Decoder{reader: d.reader, state: d.state}
	if !d.ready() {
		return child
	}
	r, err := d.reader.Constructed(id)
	d.Fail(err)
	if err == nil {
		child.reader = r
		d.child = child
	}
	return child
}

// Sequence enters a universal SEQUENCE.
func (d *Decoder) Sequence() *Decoder { return d.Constructed(SequenceIdentifier) }

// Set enters a universal SET.
func (d *Decoder) Set() *Decoder { return d.Constructed(SetIdentifier) }

// Using invokes a reader-based decoding function and records its error.
// Unlike Read, the function may intentionally consume zero or multiple values.
func (d *Decoder) Using[T any](decode func(*Reader) (T, error)) T {
	var zero T
	if !d.ready() {
		return zero
	}
	offset := d.reader.Offset()
	value, err := decode(d.reader)
	if err != nil {
		d.Fail(decodeError(offset, err))
		return zero
	}
	if d.state.err != nil {
		return zero
	}
	return value
}

// Read decodes exactly one complete value through *T's UnmarshalBER method.
// The pointer type parameter is inferred from T.
func (d *Decoder) Read[T any, P interface {
	*T
	Unmarshaler
}]() T {
	return d.one(func(r *Reader) (T, error) {
		var value T
		err := P(&value).UnmarshalBER(r)
		return value, err
	})
}

// ReadAs decodes exactly one complete value using an alternate identifier.
// It delegates identifier checking and field decoding to T's bound decoder.
func (d *Decoder) ReadAs[T any, P interface {
	*T
	TaggedUnmarshaler
}](id Identifier) T {
	return d.one(func(r *Reader) (T, error) {
		var value T
		err := P(&value).UnmarshalAs(id).UnmarshalBER(r)
		return value, err
	})
}

// one bounds a custom decoder to one TLV without charging the probe against
// the shared element budget. The real decoder charges every element it reads.
func (d *Decoder) one[T any](decode func(*Reader) (T, error)) T {
	var zero T
	if !d.ready() {
		return zero
	}
	probe := *d.reader
	state := *probe.state
	probe.state = &state
	if _, err := probe.ReadElement(); err != nil {
		d.Fail(err)
		return zero
	}
	bounded := *d.reader
	bounded.data = bounded.data[:probe.pos]
	start := bounded.pos
	value, err := decode(&bounded)
	d.reader.pos = bounded.pos
	if err == nil && bounded.pos == start {
		err = ErrNoProgress
	}
	if err == nil {
		err = bounded.RequireEmpty()
	}
	if err != nil {
		d.Fail(decodeError(bounded.base+start, err))
		return zero
	}
	if d.state.err != nil {
		return zero
	}
	return value
}

// Embed decodes T's known fields directly in this scope. It neither consumes
// an envelope nor finishes the scope. Reservations made by the embedded type
// remain active for the enclosing type's Extensions call.
func (d *Decoder) Embed[T any, P interface {
	*T
	FieldsUnmarshaler
}]() T {
	var value T
	if !d.ready() {
		return value
	}
	d.Fail(P(&value).UnmarshalBERFields(d))
	if d.Err() != nil {
		var zero T
		return zero
	}
	return value
}

// All decodes every remaining value in this scope. Failure discards the
// partial collection. Empty collections are nil, and successful collection
// decoding always consumes the scope completely.
func (d *Decoder) All[T any, P interface {
	*T
	Unmarshaler
}]() []T {
	return d.AllUsing(func(r *Reader) (T, error) {
		var value T
		err := P(&value).UnmarshalBER(r)
		return value, err
	})
}

// AllUsing decodes a collection with a custom decoder for each complete child.
// Each invocation is bounded to one TLV and must make progress.
func (d *Decoder) AllUsing[T any](decode func(*Reader) (T, error)) []T {
	var values []T
	for d.More() {
		value := d.one(decode)
		if d.state.err != nil {
			return nil
		}
		values = append(values, value)
	}
	if d.End() != nil {
		return nil
	}
	return values
}

// Reserve marks known field identifiers that may not occur in the trailing
// extension region. Reservations belong to this scope, not its nested values.
// Embedded types use this to enforce their field ownership without exposing
// their schema to the enclosing type.
func (d *Decoder) Reserve(ids ...Identifier) {
	if !d.ready() {
		return
	}
	if d.reserved == nil && len(ids) > 0 {
		d.reserved = make(map[Identifier]struct{}, len(ids))
	}
	for _, id := range ids {
		d.reserved[id] = struct{}{}
	}
}

// Extensions decodes all trailing unknown fields, rejecting any reserved
// identifier anywhere in the extension region. ids adds the enclosing type's
// exclusions to those declared by embedded components. T owns preservation
// and validation of each unknown value (including any nested contents).
func (d *Decoder) Extensions[T any, P interface {
	*T
	Unmarshaler
}](ids ...Identifier) []T {
	d.Reserve(ids...)
	var values []T
	for d.More() {
		id := d.PeekIdentifier()
		if _, known := d.reserved[id]; known {
			d.Fail(fmt.Errorf("%w: duplicate or out-of-order field %s", ErrUnexpectedIdentifier, id))
		}
		value := d.Read[T, P]()
		if d.state.err != nil {
			return nil
		}
		values = append(values, value)
	}
	if d.End() != nil {
		return nil
	}
	return values
}

// Primitive reads an implicitly tagged octet value. Returned byte slices are
// owned copies, unlike Reader's borrowed primitive views.
func (d *Decoder) Primitive[T octets](id Identifier) T {
	return d.Using(func(r *Reader) (T, error) {
		value, err := r.Primitive(id)
		// Byte values must survive reuse or clearing of the input buffer.
		return T(bytes.Clone(value)), err
	})
}

// OctetString reads a universal OCTET STRING into a string or byte-slice type.
func (d *Decoder) OctetString[T octets]() T { return d.Primitive[T](OctetStringIdentifier) }

// Boolean reads an LDAP BOOLEAN.
func (d *Decoder) Boolean() bool { return d.Using((*Reader).Boolean) }

// BooleanAs reads an implicitly tagged LDAP BOOLEAN.
func (d *Decoder) BooleanAs(id Identifier) bool {
	return d.Using(func(r *Reader) (bool, error) {
		value, err := r.Primitive(id)
		if err != nil {
			return false, err
		}
		if len(value) != 1 || (value[0] != 0 && value[0] != 0xff) {
			return false, ErrInvalidBoolean
		}
		return value[0] != 0, nil
	})
}

// Integer reads an INTEGER and checks that it is representable by T.
func (d *Decoder) Integer[T integer]() T { return d.IntegerAs[T](IntegerIdentifier) }

// Enumerated reads an ENUMERATED and checks that it is representable by T.
// Closed-enumeration membership remains the responsibility of the RFC type.
func (d *Decoder) Enumerated[T integer]() T { return d.IntegerAs[T](EnumeratedIdentifier) }

// IntegerAs reads an implicitly tagged integer with checked conversion to T.
// Values above MaxInt64 require an unsigned destination and a MaxIntegerBytes
// limit of at least nine to accommodate BER's leading positive sign octet.
func (d *Decoder) IntegerAs[T integer](id Identifier) T {
	return d.Using(func(r *Reader) (T, error) {
		return r.integer[T](id)
	})
}

// Null reads a universal NULL.
func (d *Decoder) Null() { d.NullAs(NullIdentifier) }

// NullAs reads an implicitly tagged NULL with empty contents.
func (d *Decoder) NullAs(id Identifier) {
	d.Using(func(r *Reader) (struct{}, error) {
		value, err := r.Primitive(id)
		if err != nil {
			return struct{}{}, err
		}
		if len(value) != 0 {
			return struct{}{}, ErrInvalidNull
		}
		return struct{}{}, nil
	})
}

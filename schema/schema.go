// Package schema provides small, reflection-free contracts for generated LDAP
// models. It does not perform network operations or maintain object state.
package schema

import (
	"errors"
	"fmt"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/rfc4511"
)

// ValueCodec converts one schema value to and from its LDAP wire bytes.
type ValueCodec[T any] interface {
	Encode(T) ([]byte, error)
	Decode([]byte) (T, error)
}

// Codec defines a ValueCodec with functions.
type Codec[T any] struct {
	EncodeFunc func(T) ([]byte, error)
	DecodeFunc func([]byte) (T, error)
}

// Encode converts value to LDAP wire bytes. The codec determines whether the
// result shares storage with value.
func (c Codec[T]) Encode(value T) ([]byte, error) {
	if c.EncodeFunc == nil {
		return nil, errors.New("schema: codec has no encoder")
	}
	return c.EncodeFunc(value)
}

// Decode converts LDAP wire bytes to the schema value.
func (c Codec[T]) Decode(value []byte) (T, error) {
	if c.DecodeFunc == nil {
		var zero T
		return zero, errors.New("schema: codec has no decoder")
	}
	return c.DecodeFunc(value)
}

// Attribute is a generated or handwritten typed attribute descriptor. Its name
// and normalized key are prepared together by NewAttribute and cannot diverge.
type Attribute[T any] struct {
	name  string
	key   rfc4511.AttributeKey
	Codec ValueCodec[T]
}

// NewAttribute constructs a typed attribute descriptor.
func NewAttribute[T any](name string, codec ValueCodec[T]) Attribute[T] {
	return Attribute[T]{name: name, key: rfc4511.AttributeDescription(name).Key(), Codec: codec}
}

// Name returns the original, immutable attribute description.
func (a Attribute[T]) Name() string { return a.name }

// Key returns the prepared lookup key, shared by every use of this descriptor.
func (a Attribute[T]) Key() rfc4511.AttributeKey { return a.key }

// Decode decodes one raw value without constructing a temporary value slice.
func (a Attribute[T]) Decode(raw []byte) (T, error) { return a.decodeAt(raw, 0) }

func (a Attribute[T]) decodeAt(raw []byte, index int) (T, error) {
	var zero T
	if a.Codec == nil {
		return zero, fmt.Errorf("schema: attribute %q has no codec", a.name)
	}
	value, err := a.Codec.Decode(raw)
	if err != nil {
		return zero, fmt.Errorf("schema: decode %s value %d: %w", a.name, index, err)
	}
	return value, nil
}

// Values decodes every value present on entry.
func (a Attribute[T]) Values(entry arden.Entry) ([]T, error) {
	if a.Codec == nil {
		return nil, fmt.Errorf("schema: attribute %q has no codec", a.name)
	}
	attribute, _ := entry.Attributes.LookupKey(a.key)
	raw := attribute.Values
	values := make([]T, len(raw))
	for i := range raw {
		value, err := a.decodeAt(raw[i], i)
		if err != nil {
			return nil, err
		}
		values[i] = value
	}
	return values, nil
}

// Equal constructs a typed equality filter.
func (a Attribute[T]) Equal(value T) (arden.Filter, error) {
	if a.Codec == nil {
		return nil, fmt.Errorf("schema: attribute %q has no codec", a.name)
	}
	encoded, err := a.Codec.Encode(value)
	if err != nil {
		return nil, fmt.Errorf("schema: encode %s assertion: %w", a.name, err)
	}
	return arden.EqualBytes(a.name, encoded), nil
}

// MustEqual constructs a typed equality filter and panics if encoding fails.
// Model predicates may use it when their codec encodes every value of T, such
// as StringCodec or Uint32Codec. Use Equal for codecs that can reject input.
func (a Attribute[T]) MustEqual(value T) arden.Filter {
	filter, err := a.Equal(value)
	if err != nil {
		panic(err)
	}
	return filter
}

// Set encodes values directly into the entry's final wire-value slice. Bytes
// returned by the codec are retained without copying. A failed encoding leaves
// the entry unchanged.
func (a Attribute[T]) Set(entry *arden.Entry, values ...T) error {
	if entry == nil {
		return errors.New("schema: nil entry")
	}
	if a.Codec == nil {
		return fmt.Errorf("schema: attribute %q has no codec", a.name)
	}
	raw := make([]rfc4511.AttributeValue, len(values))
	for i, value := range values {
		encoded, err := a.Codec.Encode(value)
		if err != nil {
			return fmt.Errorf("schema: encode %s value %d: %w", a.name, i, err)
		}
		raw[i] = encoded
	}
	entry.Attributes.Set(arden.Attribute{Type: rfc4511.AttributeDescription(a.name), Values: raw})
	return nil
}

// StringCodec preserves a Go string's bytes.
var StringCodec ValueCodec[string] = Codec[string]{
	EncodeFunc: func(value string) ([]byte, error) { return []byte(value), nil },
	DecodeFunc: func(value []byte) (string, error) { return string(value), nil },
}

// BytesCodec passes arbitrary bytes through without copying. Encoded and
// decoded values share storage with the input.
var BytesCodec ValueCodec[[]byte] = Codec[[]byte]{
	EncodeFunc: func(value []byte) ([]byte, error) { return value, nil },
	DecodeFunc: func(value []byte) ([]byte, error) { return value, nil },
}

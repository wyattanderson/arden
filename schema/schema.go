// Package schema provides small, reflection-free contracts for generated LDAP
// models. It does not perform network operations or maintain object state.
package schema

import (
	"errors"
	"fmt"

	"github.com/wyattanderson/arden"
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

// Attribute is a generated or handwritten typed attribute descriptor.
type Attribute[T any] struct {
	Name  string
	Codec ValueCodec[T]
}

// NewAttribute constructs a typed attribute descriptor.
func NewAttribute[T any](name string, codec ValueCodec[T]) Attribute[T] {
	return Attribute[T]{Name: name, Codec: codec}
}

// Values decodes every value present on entry.
func (a Attribute[T]) Values(entry arden.Entry) ([]T, error) {
	if a.Codec == nil {
		return nil, fmt.Errorf("schema: attribute %q has no codec", a.Name)
	}
	raw := entry.RawValues(a.Name)
	values := make([]T, len(raw))
	for i := range raw {
		value, err := a.Codec.Decode(raw[i])
		if err != nil {
			return nil, fmt.Errorf("schema: decode %s value %d: %w", a.Name, i, err)
		}
		values[i] = value
	}
	return values, nil
}

// Equal constructs a typed equality filter.
func (a Attribute[T]) Equal(value T) (arden.Filter, error) {
	if a.Codec == nil {
		return nil, fmt.Errorf("schema: attribute %q has no codec", a.Name)
	}
	encoded, err := a.Codec.Encode(value)
	if err != nil {
		return nil, fmt.Errorf("schema: encode %s assertion: %w", a.Name, err)
	}
	return arden.EqualBytes(a.Name, encoded), nil
}

// Set encodes values onto entry.
func (a Attribute[T]) Set(entry *arden.Entry, values ...T) error {
	if entry == nil {
		return errors.New("schema: nil entry")
	}
	if a.Codec == nil {
		return fmt.Errorf("schema: attribute %q has no codec", a.Name)
	}
	raw := make([][]byte, len(values))
	for i, value := range values {
		encoded, err := a.Codec.Encode(value)
		if err != nil {
			return fmt.Errorf("schema: encode %s value %d: %w", a.Name, i, err)
		}
		raw[i] = encoded
	}
	entry.SetBytes(a.Name, raw...)
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

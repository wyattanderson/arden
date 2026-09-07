package ldapmodel

import (
	"fmt"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/schema"
)

// RequiredOne decodes an attribute that must have exactly one value. It checks
// cardinality before invoking the codec and allocates no temporary value slice.
func RequiredOne[T any](attribute schema.Attribute[T], entry arden.Entry) (T, error) {
	raw, _ := entry.Attributes.LookupKey(attribute.Key())
	values := raw.Values
	if len(values) != 1 {
		var zero T
		return zero, fmt.Errorf(
			"ldapmodel: required attribute %q has %d values",
			attribute.Name(),
			len(values),
		)
	}
	return attribute.Decode(values[0])
}

// OptionalOne decodes an attribute that may have zero or one value. Absence is
// represented by nil. Cardinality is checked before decoding, without a
// temporary value slice.
func OptionalOne[T any](attribute schema.Attribute[T], entry arden.Entry) (*T, error) {
	raw, _ := entry.Attributes.LookupKey(attribute.Key())
	values := raw.Values
	if len(values) > 1 {
		return nil, fmt.Errorf(
			"ldapmodel: single-valued attribute %q has %d values",
			attribute.Name(),
			len(values),
		)
	}
	if len(values) == 0 {
		return nil, nil
	}
	value, err := attribute.Decode(values[0])
	if err != nil {
		return nil, err
	}
	return &value, nil
}

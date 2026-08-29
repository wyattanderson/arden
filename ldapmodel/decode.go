package ldapmodel

import (
	"fmt"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/schema"
)

// RequiredOne decodes an attribute that must have exactly one value.
func RequiredOne[T any](attribute schema.Attribute[T], entry arden.Entry) (T, error) {
	values, err := attribute.Values(entry)
	if err != nil {
		var zero T
		return zero, err
	}
	if len(values) != 1 {
		var zero T
		return zero, fmt.Errorf(
			"ldapmodel: required attribute %q has %d values",
			attribute.Name,
			len(values),
		)
	}
	return values[0], nil
}

// OptionalOne decodes an attribute that may have zero or one value. Absence is
// represented by nil.
func OptionalOne[T any](attribute schema.Attribute[T], entry arden.Entry) (*T, error) {
	values, err := attribute.Values(entry)
	if err != nil {
		return nil, err
	}
	if len(values) > 1 {
		return nil, fmt.Errorf(
			"ldapmodel: single-valued attribute %q has %d values",
			attribute.Name,
			len(values),
		)
	}
	if len(values) == 0 {
		return nil, nil
	}
	return &values[0], nil
}

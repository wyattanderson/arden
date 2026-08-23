package arden

import "github.com/wyattanderson/arden/rfc4511"

// Equal constructs a text equality filter without filter-string interpolation.
func Equal(attribute, value string) Filter { return rfc4511.Equal(attribute, value) }

// EqualBytes constructs an equality filter for a binary assertion value.
func EqualBytes(attribute string, value []byte) Filter {
	return rfc4511.EqualBytes(attribute, value)
}

// Has constructs a presence filter.
func Has(attribute string) Filter { return rfc4511.Has(attribute) }

// All constructs an AND filter.
func All(filters ...Filter) Filter { return rfc4511.All(filters...) }

// Any constructs an OR filter.
func Any(filters ...Filter) Filter { return rfc4511.Any(filters...) }

// Negate constructs a NOT filter.
func Negate(filter Filter) Filter { return rfc4511.Negate(filter) }

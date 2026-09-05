package ldapmodel

import "github.com/wyattanderson/arden"

const defaultPageSize uint32 = 100

// Model describes how one Go value is selected and decoded from LDAP.
type Model[T any] struct {
	baseDN     arden.LDAPDN
	scope      arden.SearchScope
	filter     arden.Filter
	attributes arden.AttributeSelectors
	decode     func(arden.Entry) (T, error)
}

// NewModel constructs an immutable model description. Its arguments are
// expected to come from generated or handwritten model code. Attribute selectors
// may be initialized once and shared by models with different search bases.
func NewModel[T any](
	baseDN arden.LDAPDN,
	scope arden.SearchScope,
	filter arden.Filter,
	attributes arden.AttributeSelectors,
	decode func(arden.Entry) (T, error),
) Model[T] {
	return Model[T]{
		baseDN:     baseDN,
		scope:      scope,
		filter:     filter,
		attributes: attributes,
		decode:     decode,
	}
}

// Criterion is a model-specific search predicate. The model type parameter
// prevents criteria generated for different projections from being mixed.
type Criterion[T any] struct {
	filter arden.Filter
}

// NewCriterion constructs a typed criterion for model query helpers.
func NewCriterion[T any](filter arden.Filter) Criterion[T] {
	return Criterion[T]{filter: filter}
}

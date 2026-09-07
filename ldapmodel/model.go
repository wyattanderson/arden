package ldapmodel

import (
	"slices"

	"github.com/wyattanderson/arden"
)

const defaultPageSize uint32 = 100

// Model describes an LDAP identity, its creation classes, and its read projection.
type Model[T any] struct {
	baseDN     arden.LDAPDN
	scope      arden.SearchScope
	classes    []string
	rdn        Attribute[T, string]
	filter     arden.Filter
	attributes arden.AttributeSelectors
	decode     func(arden.Entry) (T, error)
}

// NewModel constructs an immutable model description. Its arguments are
// expected to come from generated or handwritten model code. Attribute selectors
// may be initialized once and shared by models with different search bases.
// Base classes are copied: searches require every class, and Add supplies them
// as objectClass values. Supply at least one class; schema validity is server-owned.
// The naming attribute supplies Add's single-valued RDN and initial attribute.
// It must have a short LDAP attribute name (without options) and a codec producing
// UTF-8 strings. The base DN is both the search base and the parent for new entries.
func NewModel[T any](
	baseDN arden.LDAPDN,
	scope arden.SearchScope,
	baseClasses []string,
	naming Attribute[T, string],
	attributes arden.AttributeSelectors,
	decode func(arden.Entry) (T, error),
) Model[T] {
	classes := slices.Clone(baseClasses)
	filters := make([]arden.Filter, len(classes))
	for i, class := range classes {
		filters[i] = arden.Equal("objectClass", class)
	}
	return Model[T]{
		baseDN:     baseDN,
		scope:      scope,
		classes:    classes,
		rdn:        naming,
		filter:     arden.All(filters...),
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

package rfc4511

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/wyattanderson/arden/ber"
)

var (
	andFilterIdentifier        = contextConstructed(0)
	orFilterIdentifier         = contextConstructed(1)
	notFilterIdentifier        = contextConstructed(2)
	equalityMatchIdentifier    = contextConstructed(3)
	substringsIdentifier       = contextConstructed(4)
	greaterOrEqualIdentifier   = contextConstructed(5)
	lessOrEqualIdentifier      = contextConstructed(6)
	presentIdentifier          = contextPrimitive(7)
	approximateMatchIdentifier = contextConstructed(8)
	extensibleMatchIdentifier  = contextConstructed(9)
	initialSubstringIdentifier = contextPrimitive(0)
	anySubstringIdentifier     = contextPrimitive(1)
	finalSubstringIdentifier   = contextPrimitive(2)
	matchingRuleIdentifier     = contextPrimitive(1)
	matchingTypeIdentifier     = contextPrimitive(2)
	matchValueIdentifier       = contextPrimitive(3)
	dnAttributesIdentifier     = contextPrimitive(4)
)

// Filter is an unsealed RFC 4511 Filter CHOICE. Extensions can implement it
// without registration or access to an RFC-private dispatch path.
//
// RFC 4511 section 4.5.1.7.
type Filter interface {
	ber.Marshaler
	FilterIdentifier() ber.Identifier
}

// Equal constructs a text equality filter without filter-string interpolation.
func Equal(attribute, value string) Filter {
	return EqualityMatch{Assertion: AttributeValueAssertion{
		Type: AttributeDescription(attribute), Value: AssertionValue(value),
	}}
}

// EqualBytes constructs an equality filter for a binary assertion value.
func EqualBytes(attribute string, value []byte) Filter {
	return EqualityMatch{Assertion: AttributeValueAssertion{
		Type: AttributeDescription(attribute), Value: bytes.Clone(value),
	}}
}

// Has constructs a presence filter.
func Has(attribute string) Filter { return Present{Attribute: AttributeDescription(attribute)} }

// All constructs an AND filter.
func All(filters ...Filter) Filter { return And{Filters: slices.Clone(filters)} }

// Any constructs an OR filter.
func Any(filters ...Filter) Filter { return Or{Filters: slices.Clone(filters)} }

// Negate constructs a NOT filter.
func Negate(filter Filter) Filter { return Not{Filter: filter} }

// UnknownFilter preserves an unrecognized extensible Filter alternative. It
// can be returned by RFC decoders and re-encoded, while third-party filters
// implement Filter directly for values they understand.
type UnknownFilter struct {
	identifier ber.Identifier
	raw        []byte
}

// FilterIdentifier returns the preserved filter choice identifier.
func (f UnknownFilter) FilterIdentifier() ber.Identifier { return f.identifier }

//revive:disable-next-line:exported
func (f UnknownFilter) AppendBER(dst []byte) ([]byte, error) {
	if len(f.raw) == 0 {
		return dst, errors.New("arden: unknown filter was not decoded")
	}
	return append(dst, f.raw...), nil
}

// Raw returns an independent complete BER encoding of the unknown filter.
func (f UnknownFilter) Raw() []byte { return bytes.Clone(f.raw) }

// And is an AND filter and requires at least one child filter.
type And struct{ Filters []Filter }

// FilterIdentifier returns the context-specific AND filter identifier.
func (And) FilterIdentifier() ber.Identifier { return andFilterIdentifier }

//revive:disable-next-line:exported
func (f And) AppendBER(dst []byte) ([]byte, error) {
	return appendFilterSet(dst, andFilterIdentifier, f.Filters, "AND")
}

//revive:disable-next-line:exported
func (f *And) UnmarshalBER(r *ber.Reader) error {
	if f == nil {
		return nilReceiver("And")
	}
	filters, err := decodeFilterSet(r, andFilterIdentifier, "AND")
	if err != nil {
		return err
	}
	*f = And{Filters: filters}
	return nil
}

// Or is an OR filter and requires at least one child filter.
type Or struct{ Filters []Filter }

// FilterIdentifier returns the context-specific OR filter identifier.
func (Or) FilterIdentifier() ber.Identifier { return orFilterIdentifier }

//revive:disable-next-line:exported
func (f Or) AppendBER(dst []byte) ([]byte, error) {
	return appendFilterSet(dst, orFilterIdentifier, f.Filters, "OR")
}

//revive:disable-next-line:exported
func (f *Or) UnmarshalBER(r *ber.Reader) error {
	if f == nil {
		return nilReceiver("Or")
	}
	filters, err := decodeFilterSet(r, orFilterIdentifier, "OR")
	if err != nil {
		return err
	}
	*f = Or{Filters: filters}
	return nil
}

// Not is a NOT filter with exactly one child filter.
type Not struct{ Filter Filter }

// FilterIdentifier returns the context-specific NOT filter identifier.
func (Not) FilterIdentifier() ber.Identifier { return notFilterIdentifier }

//revive:disable-next-line:exported
func (f Not) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if f.Filter == nil {
		return dst, errors.New("arden: NOT filter has no child")
	}
	contents, err := appendFilter(nil, f.Filter)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, notFilterIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (f *Not) UnmarshalBER(r *ber.Reader) error {
	if f == nil {
		return nilReceiver("Not")
	}
	contents, err := r.Constructed(notFilterIdentifier)
	if err != nil {
		return err
	}
	child, err := decodeFilter(contents)
	if err != nil {
		return err
	}
	if err := contents.RequireEmpty(); err != nil {
		return err
	}
	*f = Not{Filter: child}
	return nil
}

// EqualityMatch compares an attribute value assertion for equality.
type EqualityMatch struct{ Assertion AttributeValueAssertion }

// FilterIdentifier returns the context-specific equality-match filter identifier.
func (EqualityMatch) FilterIdentifier() ber.Identifier { return equalityMatchIdentifier }

//revive:disable-next-line:exported
func (f EqualityMatch) AppendBER(dst []byte) ([]byte, error) {
	return appendAssertionFilter(dst, equalityMatchIdentifier, f.Assertion)
}

//revive:disable-next-line:exported
func (f *EqualityMatch) UnmarshalBER(r *ber.Reader) error {
	if f == nil {
		return nilReceiver("EqualityMatch")
	}
	assertion, err := decodeAssertionFilter(r, equalityMatchIdentifier)
	if err != nil {
		return err
	}
	*f = EqualityMatch{Assertion: assertion}
	return nil
}

// GreaterOrEqual compares an attribute value assertion using >=.
type GreaterOrEqual struct{ Assertion AttributeValueAssertion }

// FilterIdentifier returns the context-specific greater-or-equal filter identifier.
func (GreaterOrEqual) FilterIdentifier() ber.Identifier { return greaterOrEqualIdentifier }

//revive:disable-next-line:exported
func (f GreaterOrEqual) AppendBER(dst []byte) ([]byte, error) {
	return appendAssertionFilter(dst, greaterOrEqualIdentifier, f.Assertion)
}

//revive:disable-next-line:exported
func (f *GreaterOrEqual) UnmarshalBER(r *ber.Reader) error {
	if f == nil {
		return nilReceiver("GreaterOrEqual")
	}
	assertion, err := decodeAssertionFilter(r, greaterOrEqualIdentifier)
	if err != nil {
		return err
	}
	*f = GreaterOrEqual{Assertion: assertion}
	return nil
}

// LessOrEqual compares an attribute value assertion using <=.
type LessOrEqual struct{ Assertion AttributeValueAssertion }

// FilterIdentifier returns the context-specific less-or-equal filter identifier.
func (LessOrEqual) FilterIdentifier() ber.Identifier { return lessOrEqualIdentifier }

//revive:disable-next-line:exported
func (f LessOrEqual) AppendBER(dst []byte) ([]byte, error) {
	return appendAssertionFilter(dst, lessOrEqualIdentifier, f.Assertion)
}

//revive:disable-next-line:exported
func (f *LessOrEqual) UnmarshalBER(r *ber.Reader) error {
	if f == nil {
		return nilReceiver("LessOrEqual")
	}
	assertion, err := decodeAssertionFilter(r, lessOrEqualIdentifier)
	if err != nil {
		return err
	}
	*f = LessOrEqual{Assertion: assertion}
	return nil
}

// ApproximateMatch compares an attribute value assertion approximately.
type ApproximateMatch struct{ Assertion AttributeValueAssertion }

// FilterIdentifier returns the context-specific approximate-match filter identifier.
func (ApproximateMatch) FilterIdentifier() ber.Identifier { return approximateMatchIdentifier }

//revive:disable-next-line:exported
func (f ApproximateMatch) AppendBER(dst []byte) ([]byte, error) {
	return appendAssertionFilter(dst, approximateMatchIdentifier, f.Assertion)
}

//revive:disable-next-line:exported
func (f *ApproximateMatch) UnmarshalBER(r *ber.Reader) error {
	if f == nil {
		return nilReceiver("ApproximateMatch")
	}
	assertion, err := decodeAssertionFilter(r, approximateMatchIdentifier)
	if err != nil {
		return err
	}
	*f = ApproximateMatch{Assertion: assertion}
	return nil
}

// Present matches entries containing Attribute.
type Present struct{ Attribute AttributeDescription }

// FilterIdentifier returns the context-specific presence filter identifier.
func (Present) FilterIdentifier() ber.Identifier { return presentIdentifier }

//revive:disable-next-line:exported
func (f Present) AppendBER(dst []byte) ([]byte, error) {
	if err := requireNonEmpty("present attribute description", f.Attribute); err != nil {
		return dst, err
	}
	return ber.AppendPrimitive(dst, presentIdentifier, []byte(f.Attribute))
}

//revive:disable-next-line:exported
func (f *Present) UnmarshalBER(r *ber.Reader) error {
	if f == nil {
		return nilReceiver("Present")
	}
	attribute, err := r.Primitive(presentIdentifier)
	if err != nil {
		return err
	}
	if err := requireNonEmpty("present attribute description", attribute); err != nil {
		return err
	}
	*f = Present{Attribute: AttributeDescription(string(attribute))}
	return nil
}

// SubstringFilter has at most one Initial and Final part, any number of Any
// parts, and at least one total part. Extensions retains unknown trailing
// substring alternatives.
type SubstringFilter struct {
	Type       AttributeDescription
	Initial    *AssertionValue
	Any        []AssertionValue
	Final      *AssertionValue
	Extensions []UnknownField
}

// FilterIdentifier returns the context-specific substring filter identifier.
func (SubstringFilter) FilterIdentifier() ber.Identifier { return substringsIdentifier }

//revive:disable-next-line:exported
func (f SubstringFilter) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if err := requireNonEmpty("substring attribute description", f.Type); err != nil {
		return dst, err
	}
	if f.Initial == nil && len(f.Any) == 0 && f.Final == nil {
		return dst, errors.New("arden: substring filter requires at least one part")
	}
	contents, err := ber.AppendOctetString(nil, []byte(f.Type))
	if err != nil {
		return dst[:start], err
	}
	parts := make([]byte, 0)
	if f.Initial != nil {
		parts, err = appendImplicitOctets(parts, initialSubstringIdentifier, *f.Initial)
		if err != nil {
			return dst[:start], err
		}
	}
	for i, value := range f.Any {
		parts, err = appendImplicitOctets(parts, anySubstringIdentifier, value)
		if err != nil {
			return dst[:start], fmt.Errorf("arden: substring any part %d: %w", i, err)
		}
	}
	if f.Final != nil {
		parts, err = appendImplicitOctets(parts, finalSubstringIdentifier, *f.Final)
		if err != nil {
			return dst[:start], err
		}
	}
	parts, err = appendUnknownFields(parts, f.Extensions)
	if err != nil {
		return dst[:start], err
	}
	contents, err = ber.AppendSequence(contents, parts)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, substringsIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (f *SubstringFilter) UnmarshalBER(r *ber.Reader) error {
	if f == nil {
		return nilReceiver("SubstringFilter")
	}
	contents, err := r.Constructed(substringsIdentifier)
	if err != nil {
		return err
	}
	typeValue, err := contents.OctetString()
	if err != nil {
		return err
	}
	if err := requireNonEmpty("substring attribute description", typeValue); err != nil {
		return err
	}
	parts, err := contents.Sequence()
	if err != nil {
		return err
	}
	decoded := SubstringFilter{Type: AttributeDescription(string(typeValue))}
	for !parts.Empty() {
		id, err := parts.PeekIdentifier()
		if err != nil {
			return err
		}
		switch id {
		case initialSubstringIdentifier:
			if decoded.Initial != nil || len(decoded.Any) != 0 || decoded.Final != nil {
				return errors.New("arden: substring initial part is out of order")
			}
			value, err := readImplicitOctets(parts, initialSubstringIdentifier)
			if err != nil {
				return err
			}
			initial := AssertionValue(value)
			decoded.Initial = &initial
		case anySubstringIdentifier:
			if decoded.Final != nil {
				return errors.New("arden: substring any part follows final part")
			}
			value, err := readImplicitOctets(parts, anySubstringIdentifier)
			if err != nil {
				return err
			}
			decoded.Any = append(decoded.Any, AssertionValue(value))
		case finalSubstringIdentifier:
			if decoded.Final != nil {
				return errors.New("arden: substring has multiple final parts")
			}
			value, err := readImplicitOctets(parts, finalSubstringIdentifier)
			if err != nil {
				return err
			}
			final := AssertionValue(value)
			decoded.Final = &final
		default:
			decoded.Extensions, err = decodeUnknownFields(parts)
			if err != nil {
				return err
			}
		}
	}
	if decoded.Initial == nil && len(decoded.Any) == 0 && decoded.Final == nil {
		return errors.New("arden: substring filter requires at least one part")
	}
	if err := contents.RequireEmpty(); err != nil {
		return err
	}
	*f = decoded
	return nil
}

// ExtensibleMatch is the extensible matching-rule filter alternative.
type ExtensibleMatch struct {
	MatchingRule *MatchingRuleID
	Type         *AttributeDescription
	MatchValue   AssertionValue
	DNAttributes bool
	Extensions   []UnknownField
}

// FilterIdentifier returns the context-specific extensible-match filter identifier.
func (ExtensibleMatch) FilterIdentifier() ber.Identifier { return extensibleMatchIdentifier }

//revive:disable-next-line:exported
func (f ExtensibleMatch) AppendBER(dst []byte) ([]byte, error) {
	start := len(dst)
	if err := f.validate(); err != nil {
		return dst, err
	}
	contents := make([]byte, 0)
	var err error
	if f.MatchingRule != nil {
		contents, err = appendImplicitOctets(contents, matchingRuleIdentifier, *f.MatchingRule)
		if err != nil {
			return dst[:start], err
		}
	}
	if f.Type != nil {
		contents, err = appendImplicitOctets(contents, matchingTypeIdentifier, *f.Type)
		if err != nil {
			return dst[:start], err
		}
	}
	contents, err = appendImplicitOctets(contents, matchValueIdentifier, f.MatchValue)
	if err != nil {
		return dst[:start], err
	}
	if f.DNAttributes {
		contents, err = appendImplicitBoolean(contents, dnAttributesIdentifier, true)
		if err != nil {
			return dst[:start], err
		}
	}
	contents, err = appendUnknownFields(contents, f.Extensions)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, extensibleMatchIdentifier, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

//revive:disable-next-line:exported
func (f *ExtensibleMatch) UnmarshalBER(r *ber.Reader) error {
	if f == nil {
		return nilReceiver("ExtensibleMatch")
	}
	contents, err := r.Constructed(extensibleMatchIdentifier)
	if err != nil {
		return err
	}
	decoded := ExtensibleMatch{}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == matchingRuleIdentifier {
			value, err := readImplicitOctets(contents, matchingRuleIdentifier)
			if err != nil {
				return err
			}
			if err := requireNonEmpty("matching rule", value); err != nil {
				return err
			}
			matchingRule := MatchingRuleID(value)
			decoded.MatchingRule = &matchingRule
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == matchingTypeIdentifier {
			value, err := readImplicitOctets(contents, matchingTypeIdentifier)
			if err != nil {
				return err
			}
			if err := requireNonEmpty("matching type", value); err != nil {
				return err
			}
			typeValue := AttributeDescription(value)
			decoded.Type = &typeValue
		}
	}
	value, err := readImplicitOctets(contents, matchValueIdentifier)
	if err != nil {
		return err
	}
	decoded.MatchValue = AssertionValue(value)
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == dnAttributesIdentifier {
			decoded.DNAttributes, err = readImplicitBoolean(contents, dnAttributesIdentifier)
			if err != nil {
				return err
			}
		}
	}
	if !contents.Empty() {
		id, err := contents.PeekIdentifier()
		if err != nil {
			return err
		}
		if id == matchingRuleIdentifier || id == matchingTypeIdentifier || id == matchValueIdentifier || id == dnAttributesIdentifier {
			return fmt.Errorf("arden: duplicate or out-of-order extensible match field %s", id)
		}
		decoded.Extensions, err = decodeUnknownFields(contents)
		if err != nil {
			return err
		}
	}
	if err := decoded.validate(); err != nil {
		return err
	}
	*f = decoded
	return nil
}

func (f ExtensibleMatch) validate() error {
	if f.MatchingRule == nil && f.Type == nil {
		return errors.New("arden: extensible match requires a matching rule or type")
	}
	if f.MatchingRule != nil {
		if err := requireNonEmpty("matching rule", *f.MatchingRule); err != nil {
			return err
		}
	}
	if f.Type != nil {
		if err := requireNonEmpty("matching type", *f.Type); err != nil {
			return err
		}
	}
	return nil
}

func appendFilterSet(dst []byte, id ber.Identifier, filters []Filter, name string) ([]byte, error) {
	start := len(dst)
	if len(filters) == 0 {
		return dst, fmt.Errorf("arden: %s filter requires at least one child", name)
	}
	contents := make([]byte, 0)
	var err error
	for i, filter := range filters {
		contents, err = appendFilter(contents, filter)
		if err != nil {
			return dst[:start], fmt.Errorf("arden: %s filter child %d: %w", name, i, err)
		}
	}
	encoded, err := ber.AppendConstructed(dst, id, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

func decodeFilterSet(r *ber.Reader, id ber.Identifier, name string) ([]Filter, error) {
	contents, err := r.Constructed(id)
	if err != nil {
		return nil, err
	}
	var filters []Filter
	for !contents.Empty() {
		filter, err := decodeFilter(contents)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	if len(filters) == 0 {
		return nil, fmt.Errorf("arden: %s filter requires at least one child", name)
	}
	return filters, nil
}

func appendFilter(dst []byte, filter Filter) ([]byte, error) {
	start := len(dst)
	if filter == nil {
		return dst, errors.New("arden: nil filter")
	}
	id := filter.FilterIdentifier()
	if !id.Valid() || id.Class != ber.ClassContextSpecific {
		return dst, fmt.Errorf("arden: filter identifier %s is not context-specific", id)
	}
	encoded, err := filter.AppendBER(dst)
	if err != nil {
		return dst[:start], err
	}
	value, err := ber.DecodeElement(encoded[start:], validationLimits())
	if err != nil {
		return dst[:start], fmt.Errorf("arden: filter encoding: %w", err)
	}
	if value.Identifier != id {
		return dst[:start], fmt.Errorf("arden: filter encoded %s, declared %s", value.Identifier, id)
	}
	return encoded, nil
}

func decodeFilter(r *ber.Reader) (Filter, error) {
	id, err := r.PeekIdentifier()
	if err != nil {
		return nil, err
	}
	switch id {
	case andFilterIdentifier:
		var filter And
		err = filter.UnmarshalBER(r)
		return filter, err
	case orFilterIdentifier:
		var filter Or
		err = filter.UnmarshalBER(r)
		return filter, err
	case notFilterIdentifier:
		var filter Not
		err = filter.UnmarshalBER(r)
		return filter, err
	case equalityMatchIdentifier:
		var filter EqualityMatch
		err = filter.UnmarshalBER(r)
		return filter, err
	case substringsIdentifier:
		var filter SubstringFilter
		err = filter.UnmarshalBER(r)
		return filter, err
	case greaterOrEqualIdentifier:
		var filter GreaterOrEqual
		err = filter.UnmarshalBER(r)
		return filter, err
	case lessOrEqualIdentifier:
		var filter LessOrEqual
		err = filter.UnmarshalBER(r)
		return filter, err
	case presentIdentifier:
		var filter Present
		err = filter.UnmarshalBER(r)
		return filter, err
	case approximateMatchIdentifier:
		var filter ApproximateMatch
		err = filter.UnmarshalBER(r)
		return filter, err
	case extensibleMatchIdentifier:
		var filter ExtensibleMatch
		err = filter.UnmarshalBER(r)
		return filter, err
	default:
		if id.Class != ber.ClassContextSpecific {
			return nil, fmt.Errorf("arden: filter identifier %s is not context-specific", id)
		}
		e, err := r.SkipElement()
		if err != nil {
			return nil, err
		}
		return UnknownFilter{identifier: e.Identifier, raw: bytes.Clone(e.Raw)}, nil
	}
}

func appendAssertionFilter(dst []byte, id ber.Identifier, assertion AttributeValueAssertion) ([]byte, error) {
	start := len(dst)
	contents, err := assertion.appendContents(nil)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, id, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

func decodeAssertionFilter(r *ber.Reader, id ber.Identifier) (AttributeValueAssertion, error) {
	contents, err := r.Constructed(id)
	if err != nil {
		return AttributeValueAssertion{}, err
	}
	return decodeAssertionContents(contents)
}

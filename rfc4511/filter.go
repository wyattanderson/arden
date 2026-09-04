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
	ber.Packeter
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

// BERPacket returns the preserved complete filter packet.
func (f UnknownFilter) BERPacket() ber.Packet { return ber.Encoded(f.raw) }

// Raw returns an independent complete BER encoding of the unknown filter.
func (f UnknownFilter) Raw() []byte { return bytes.Clone(f.raw) }

// And is an AND filter and requires at least one child filter.
type And struct{ Filters []Filter }

// FilterIdentifier returns the context-specific AND filter identifier.
func (And) FilterIdentifier() ber.Identifier { return andFilterIdentifier }

// BERPacket returns the AND filter packet.
func (f And) BERPacket() ber.Packet {
	return ber.Constructed(andFilterIdentifier).Add(f.Filters...).BERPacket()
}

//revive:disable-next-line:exported
func (f *And) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(andFilterIdentifier)
	decoded := And{Filters: d.AllUsing(decodeFilter)}
	if err := d.End(); err != nil {
		return err
	}
	if len(decoded.Filters) == 0 {
		return errors.New("arden: AND filter requires at least one child")
	}
	*f = decoded
	return nil
}

// Or is an OR filter and requires at least one child filter.
type Or struct{ Filters []Filter }

// FilterIdentifier returns the context-specific OR filter identifier.
func (Or) FilterIdentifier() ber.Identifier { return orFilterIdentifier }

// BERPacket returns the OR filter packet.
func (f Or) BERPacket() ber.Packet {
	return ber.Constructed(orFilterIdentifier).Add(f.Filters...).BERPacket()
}

//revive:disable-next-line:exported
func (f *Or) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(orFilterIdentifier)
	decoded := Or{Filters: d.AllUsing(decodeFilter)}
	if err := d.End(); err != nil {
		return err
	}
	if len(decoded.Filters) == 0 {
		return errors.New("arden: OR filter requires at least one child")
	}
	*f = decoded
	return nil
}

// Not is a NOT filter with exactly one child filter.
type Not struct{ Filter Filter }

// FilterIdentifier returns the context-specific NOT filter identifier.
func (Not) FilterIdentifier() ber.Identifier { return notFilterIdentifier }

// BERPacket returns the NOT filter packet.
func (f Not) BERPacket() ber.Packet {
	return ber.Constructed(notFilterIdentifier).Add(f.Filter).BERPacket()
}

//revive:disable-next-line:exported
func (f *Not) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(notFilterIdentifier)
	decoded := Not{Filter: d.Using(decodeFilter)}
	if err := d.End(); err != nil {
		return err
	}
	*f = decoded
	return nil
}

// EqualityMatch compares an attribute value assertion for equality.
type EqualityMatch struct{ Assertion AttributeValueAssertion }

// FilterIdentifier returns the context-specific equality-match filter identifier.
func (EqualityMatch) FilterIdentifier() ber.Identifier { return equalityMatchIdentifier }

// BERPacket returns the equality-match filter packet.
func (f EqualityMatch) BERPacket() ber.Packet {
	return assertionFilterPacket(equalityMatchIdentifier, f.Assertion)
}

//revive:disable-next-line:exported
func (f *EqualityMatch) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := EqualityMatch{Assertion: d.ReadAs[AttributeValueAssertion](equalityMatchIdentifier)}
	if err := d.Err(); err != nil {
		return err
	}
	*f = decoded
	return nil
}

// GreaterOrEqual compares an attribute value assertion using >=.
type GreaterOrEqual struct{ Assertion AttributeValueAssertion }

// FilterIdentifier returns the context-specific greater-or-equal filter identifier.
func (GreaterOrEqual) FilterIdentifier() ber.Identifier { return greaterOrEqualIdentifier }

// BERPacket returns the greater-or-equal filter packet.
func (f GreaterOrEqual) BERPacket() ber.Packet {
	return assertionFilterPacket(greaterOrEqualIdentifier, f.Assertion)
}

//revive:disable-next-line:exported
func (f *GreaterOrEqual) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := GreaterOrEqual{Assertion: d.ReadAs[AttributeValueAssertion](greaterOrEqualIdentifier)}
	if err := d.Err(); err != nil {
		return err
	}
	*f = decoded
	return nil
}

// LessOrEqual compares an attribute value assertion using <=.
type LessOrEqual struct{ Assertion AttributeValueAssertion }

// FilterIdentifier returns the context-specific less-or-equal filter identifier.
func (LessOrEqual) FilterIdentifier() ber.Identifier { return lessOrEqualIdentifier }

// BERPacket returns the less-or-equal filter packet.
func (f LessOrEqual) BERPacket() ber.Packet {
	return assertionFilterPacket(lessOrEqualIdentifier, f.Assertion)
}

//revive:disable-next-line:exported
func (f *LessOrEqual) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := LessOrEqual{Assertion: d.ReadAs[AttributeValueAssertion](lessOrEqualIdentifier)}
	if err := d.Err(); err != nil {
		return err
	}
	*f = decoded
	return nil
}

// ApproximateMatch compares an attribute value assertion approximately.
type ApproximateMatch struct{ Assertion AttributeValueAssertion }

// FilterIdentifier returns the context-specific approximate-match filter identifier.
func (ApproximateMatch) FilterIdentifier() ber.Identifier { return approximateMatchIdentifier }

// BERPacket returns the approximate-match filter packet.
func (f ApproximateMatch) BERPacket() ber.Packet {
	return assertionFilterPacket(approximateMatchIdentifier, f.Assertion)
}

//revive:disable-next-line:exported
func (f *ApproximateMatch) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := ApproximateMatch{Assertion: d.ReadAs[AttributeValueAssertion](approximateMatchIdentifier)}
	if err := d.Err(); err != nil {
		return err
	}
	*f = decoded
	return nil
}

// Present matches entries containing Attribute.
type Present struct{ Attribute AttributeDescription }

// FilterIdentifier returns the context-specific presence filter identifier.
func (Present) FilterIdentifier() ber.Identifier { return presentIdentifier }

// BERPacket returns the presence filter packet.
func (f Present) BERPacket() ber.Packet {
	return ber.Primitive(presentIdentifier, []byte(f.Attribute))
}

//revive:disable-next-line:exported
func (f *Present) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r)
	decoded := Present{Attribute: d.ReadAs[AttributeDescription](presentIdentifier)}
	if err := d.Err(); err != nil {
		return err
	}
	if err := requireNonEmpty("present attribute description", decoded.Attribute); err != nil {
		return err
	}
	*f = decoded
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

// BERPacket returns the substring filter packet.
func (f SubstringFilter) BERPacket() ber.Packet {
	parts := ber.Sequence()
	if f.Initial != nil {
		parts.Add(implicitOctetsPacket(initialSubstringIdentifier, *f.Initial))
	}
	for _, value := range f.Any {
		parts.Add(implicitOctetsPacket(anySubstringIdentifier, value))
	}
	if f.Final != nil {
		parts.Add(implicitOctetsPacket(finalSubstringIdentifier, *f.Final))
	}
	parts.Add(f.Extensions...)
	return ber.Constructed(substringsIdentifier).
		Add(ber.OctetString(f.Type)).
		Add(parts).
		BERPacket()
}

//revive:disable-next-line:exported
func (f *SubstringFilter) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(substringsIdentifier)
	decoded := SubstringFilter{Type: d.Read[AttributeDescription]()}
	parts := d.Sequence()
	if parts.NextIs(initialSubstringIdentifier) {
		initial := parts.ReadAs[AssertionValue](initialSubstringIdentifier)
		decoded.Initial = &initial
	}
	for parts.NextIs(anySubstringIdentifier) {
		decoded.Any = append(decoded.Any, parts.ReadAs[AssertionValue](anySubstringIdentifier))
	}
	if parts.NextIs(finalSubstringIdentifier) {
		final := parts.ReadAs[AssertionValue](finalSubstringIdentifier)
		decoded.Final = &final
	}
	decoded.Extensions = parts.Extensions[UnknownField](
		initialSubstringIdentifier, anySubstringIdentifier, finalSubstringIdentifier,
	)
	if err := d.End(); err != nil {
		return err
	}
	if err := requireNonEmpty("substring attribute description", decoded.Type); err != nil {
		return err
	}
	if decoded.Initial == nil && len(decoded.Any) == 0 && decoded.Final == nil {
		return errors.New("arden: substring filter requires at least one part")
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

// BERPacket returns the extensible-match filter packet.
func (f ExtensibleMatch) BERPacket() ber.Packet {
	filter := ber.Constructed(extensibleMatchIdentifier)
	if f.MatchingRule != nil {
		filter.Add(implicitOctetsPacket(matchingRuleIdentifier, *f.MatchingRule))
	}
	if f.Type != nil {
		filter.Add(implicitOctetsPacket(matchingTypeIdentifier, *f.Type))
	}
	filter.Add(implicitOctetsPacket(matchValueIdentifier, f.MatchValue))
	if f.DNAttributes {
		filter.Add(implicitBooleanPacket(dnAttributesIdentifier, true))
	}
	return filter.Add(f.Extensions...).BERPacket()
}

//revive:disable-next-line:exported
func (f *ExtensibleMatch) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Constructed(extensibleMatchIdentifier)
	var decoded ExtensibleMatch
	if d.NextIs(matchingRuleIdentifier) {
		rule := d.ReadAs[MatchingRuleID](matchingRuleIdentifier)
		decoded.MatchingRule = &rule
	}
	if d.NextIs(matchingTypeIdentifier) {
		attribute := d.ReadAs[AttributeDescription](matchingTypeIdentifier)
		decoded.Type = &attribute
	}
	decoded.MatchValue = d.ReadAs[AssertionValue](matchValueIdentifier)
	if d.NextIs(dnAttributesIdentifier) {
		decoded.DNAttributes = d.BooleanAs(dnAttributesIdentifier)
	}
	decoded.Extensions = d.Extensions[UnknownField](
		matchingRuleIdentifier, matchingTypeIdentifier, matchValueIdentifier, dnAttributesIdentifier,
	)
	if err := d.End(); err != nil {
		return err
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

func decodeFilter(r *ber.Reader) (Filter, error) {
	d := ber.NewDecoder(r)
	id := d.PeekIdentifier()
	var decoded Filter
	switch id {
	case andFilterIdentifier:
		decoded = d.Read[And]()
	case orFilterIdentifier:
		decoded = d.Read[Or]()
	case notFilterIdentifier:
		decoded = d.Read[Not]()
	case equalityMatchIdentifier:
		decoded = d.Read[EqualityMatch]()
	case substringsIdentifier:
		decoded = d.Read[SubstringFilter]()
	case greaterOrEqualIdentifier:
		decoded = d.Read[GreaterOrEqual]()
	case lessOrEqualIdentifier:
		decoded = d.Read[LessOrEqual]()
	case presentIdentifier:
		decoded = d.Read[Present]()
	case approximateMatchIdentifier:
		decoded = d.Read[ApproximateMatch]()
	case extensibleMatchIdentifier:
		decoded = d.Read[ExtensibleMatch]()
	default:
		if id.Class != ber.ClassContextSpecific {
			d.Fail(fmt.Errorf("arden: filter identifier %s is not context-specific", id))
		}
		field := d.Read[UnknownField]()
		decoded = UnknownFilter(field)
	}
	if err := d.Err(); err != nil {
		return nil, err
	}
	return decoded, nil
}

func assertionFilterPacket(id ber.Identifier, assertion AttributeValueAssertion) ber.Packet {
	return ber.Constructed(id).
		Add(
			ber.OctetString(assertion.Type),
			ber.OctetString(assertion.Value),
		).
		Add(assertion.Extensions...).
		BERPacket()
}

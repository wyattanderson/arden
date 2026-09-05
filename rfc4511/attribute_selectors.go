package rfc4511

import (
	"iter"
	"slices"

	"github.com/wyattanderson/arden/ber"
)

// AttributeSelectors is an immutable, ordered list of search attribute selectors
// with a cached BER encoding. Copies may be shared between requests and goroutines.
// The zero value is an empty selection, requesting all user attributes.
type AttributeSelectors struct {
	values  []AttributeSelector
	encoded []byte
}

// NewAttributeSelectors copies selectors and encodes their complete BER SEQUENCE
// once. Like other packet constructors, it does not validate the selector text.
func NewAttributeSelectors[T ~string](selectors []T) AttributeSelectors {
	if len(selectors) == 0 {
		return AttributeSelectors{}
	}
	values := make([]AttributeSelector, len(selectors))
	for i, selector := range selectors {
		values[i] = AttributeSelector(selector)
	}
	return AttributeSelectors{
		values:  values,
		encoded: ber.Sequence().Add(values...).BERPacket().Encode(),
	}
}

// Len returns the number of selectors.
func (v AttributeSelectors) Len() int { return len(v.values) }

// All returns an iterator over the selectors in wire order.
func (v AttributeSelectors) All() iter.Seq[AttributeSelector] { return slices.Values(v.values) }

// BERPacket returns the cached complete attribute-selection sequence.
func (v AttributeSelectors) BERPacket() ber.Packet {
	if len(v.encoded) == 0 {
		return ber.Sequence().BERPacket()
	}
	return ber.Encoded(v.encoded)
}

// UnmarshalBER decodes and validates an attribute-selection sequence, retaining
// no input bytes. The receiver is unchanged if decoding fails.
func (v *AttributeSelectors) UnmarshalBER(r *ber.Reader) error {
	d := ber.NewDecoder(r).Sequence()
	values := d.All[AttributeSelector]()
	if err := d.End(); err != nil {
		return err
	}
	*v = NewAttributeSelectors(values)
	return nil
}

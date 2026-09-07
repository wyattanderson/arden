package ldapmodel

import (
	"fmt"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/schema"
)

// Replacement records explicit replacement intent for one typed attribute.
// Its zero value leaves the attribute unchanged. Model patches keep these
// fields private and expose only operations allowed by their schema metadata.
type Replacement[T any] struct {
	present bool
	values  []T
}

// Set replaces the previous intent with values. With no values it removes the
// attribute. The value slice is copied, but storage referenced by individual
// values (such as []byte) is shared. Setting a copied Replacement does not
// change the original.
func (r *Replacement[T]) Set(values ...T) {
	*r = Replacement[T]{present: true, values: append([]T(nil), values...)}
}

// Clear records intent to remove the attribute.
func (r *Replacement[T]) Clear() {
	*r = Replacement[T]{present: true}
}

// AppendChanges appends one LDAP Replace when intent is present, including a
// replacement with no values for Clear. An unset replacement returns changes
// unchanged without invoking the codec. Encoding failure returns nil and an
// error without modifying changes. Bytes returned by the codec are retained.
func (r Replacement[T]) AppendChanges(changes []arden.Change, attribute schema.Attribute[T]) ([]arden.Change, error) {
	if !r.present {
		return changes, nil
	}
	if attribute.Codec == nil {
		return nil, fmt.Errorf("ldapmodel: attribute %q has no codec", attribute.Name())
	}
	encoded := make([][]byte, len(r.values))
	for i, value := range r.values {
		wire, err := attribute.Codec.Encode(value)
		if err != nil {
			return nil, fmt.Errorf("encode replacement for %s value %d: %w", attribute.Name(), i, err)
		}
		encoded[i] = wire
	}
	return append(changes, arden.ReplaceBytes(attribute.Name(), encoded...)), nil
}

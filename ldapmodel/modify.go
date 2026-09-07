package ldapmodel

import (
	"fmt"

	"github.com/wyattanderson/arden"
)

// Change is an opaque LDAP modification for model M. Construct changes with
// Add, Delete, or Replace; the zero value is invalid. Encoding errors are
// retained until Modify, which checks every change before sending a request.
type Change[M any] struct {
	wire arden.Change
	err  error
}

// Add constructs a change adding values to an attribute. Values are encoded
// immediately; bytes returned by the codec are retained without copying.
// Attribute cardinality and allowed operations are validated by the server.
func Add[M, T any](attribute Attribute[M, T], values ...T) Change[M] {
	return encodeChange(attribute, arden.AddBytes, values)
}

// Delete constructs a change deleting the specified values. With no values it
// removes the entire attribute. Encoding and ownership are the same as Add.
func Delete[M, T any](attribute Attribute[M, T], values ...T) Change[M] {
	return encodeChange(attribute, arden.DeleteBytes, values)
}

// Replace constructs a change replacing all values of an attribute. With no
// values it removes the attribute. Encoding and ownership are the same as Add.
func Replace[M, T any](attribute Attribute[M, T], values ...T) Change[M] {
	return encodeChange(attribute, arden.ReplaceBytes, values)
}

func encodeChange[M, T any](
	attribute Attribute[M, T],
	operation func(string, ...[]byte) arden.Change,
	values []T,
) Change[M] {
	if attribute.Codec == nil {
		return Change[M]{err: fmt.Errorf("ldapmodel: attribute %q has no codec", attribute.Name())}
	}
	encoded := make([][]byte, len(values))
	for i, value := range values {
		wire, err := attribute.Codec.Encode(value)
		if err != nil {
			return Change[M]{err: fmt.Errorf("ldapmodel: encode %s value %d: %w", attribute.Name(), i, err)}
		}
		encoded[i] = wire
	}
	return Change[M]{wire: operation(attribute.Name(), encoded...)}
}

// Modify applies changes in caller order as one LDAP Modify, including repeated
// operations on an attribute. It performs no implicit read, retry, or coalescing.
// An empty change set, invalid change, or encoding error sends no request.
func (d DAO[M]) Modify(dn arden.LDAPDN, changes ...Change[M]) error {
	if len(changes) == 0 {
		return ErrEmptyChanges
	}
	wire := make([]arden.Change, len(changes))
	for i, change := range changes {
		if change.err != nil {
			return fmt.Errorf("ldapmodel: change %d: %w", i, change.err)
		}
		if change.wire.Modification.Type == "" {
			return fmt.Errorf("ldapmodel: change %d has no attribute", i)
		}
		wire[i] = change.wire
	}
	return d.client.Modify(d.ctx, dn, wire...)
}

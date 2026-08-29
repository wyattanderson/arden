package ldapmodel

import "github.com/wyattanderson/arden"

// Mutation is an opaque, model-specific set of LDAP changes produced by model
// patch code.
type Mutation[T any] struct {
	changes []arden.Change
}

// NewMutation constructs a typed mutation for patch implementations.
func NewMutation[T any](changes ...arden.Change) Mutation[T] {
	return Mutation[T]{changes: append([]arden.Change(nil), changes...)}
}

// Patch is implemented by patch values for model T.
type Patch[T any] interface {
	Mutation() (Mutation[T], error)
}

// Update applies a patch as one LDAP Modify. The method's P type parameter uses
// Go 1.27 generic methods to infer the concrete patch type.
func (d DAO[T]) Update[P Patch[T]](dn arden.LDAPDN, patch P) error {
	mutation, err := patch.Mutation()
	if err != nil {
		return err
	}
	if len(mutation.changes) == 0 {
		return ErrEmptyPatch
	}
	return d.client.Modify(d.ctx, dn, mutation.changes...)
}

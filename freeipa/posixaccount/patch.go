package posixaccount

import (
	"fmt"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ldapmodel"
	"github.com/wyattanderson/arden/schema"
)

// UserPatch is an explicit set of LDAP replacements. Its zero value contains
// no changes. Calling a method again replaces the earlier intent for that
// field, and generated field order determines Modify change order.
//
// AccountName is deliberately absent: changing uid can also change the RDN and
// therefore needs a separate rename contract built around ModifyDN.
type UserPatch struct {
	commonName     replacement[string]
	uidNumber      replacement[uint32]
	gidNumber      replacement[uint32]
	homeDirectory  replacement[string]
	gecos          replacement[string]
	loginShell     replacement[string]
	emailAddresses replacement[string]
}

type replacement[T any] struct {
	present bool
	values  []T
}

// SetCommonName replaces the required cn value.
func (p *UserPatch) SetCommonName(value string) {
	p.commonName = replaceWith(value)
}

// SetUIDNumber replaces the required uidNumber value.
func (p *UserPatch) SetUIDNumber(value uint32) {
	p.uidNumber = replaceWith(value)
}

// SetGIDNumber replaces the required gidNumber value.
func (p *UserPatch) SetGIDNumber(value uint32) {
	p.gidNumber = replaceWith(value)
}

// SetHomeDirectory replaces the required homeDirectory value.
func (p *UserPatch) SetHomeDirectory(value string) {
	p.homeDirectory = replaceWith(value)
}

// SetGECOS replaces the optional gecos value.
func (p *UserPatch) SetGECOS(value string) {
	p.gecos = replaceWith(value)
}

// ClearGECOS removes the optional gecos attribute.
func (p *UserPatch) ClearGECOS() {
	p.gecos = clear[string]()
}

// SetLoginShell replaces the optional loginShell value.
func (p *UserPatch) SetLoginShell(value string) {
	p.loginShell = replaceWith(value)
}

// ClearLoginShell removes the optional loginShell attribute.
func (p *UserPatch) ClearLoginShell() {
	p.loginShell = clear[string]()
}

// ReplaceEmailAddresses replaces all mail values. With no values it removes
// the attribute.
func (p *UserPatch) ReplaceEmailAddresses(values ...string) {
	p.emailAddresses = replacement[string]{present: true, values: append([]string(nil), values...)}
}

func replaceWith[T any](value T) replacement[T] {
	return replacement[T]{present: true, values: []T{value}}
}

func clear[T any]() replacement[T] {
	return replacement[T]{present: true}
}

// Mutation converts this generated patch to the generic DAO's model-typed
// mutation contract.
func (p UserPatch) Mutation() (ldapmodel.Mutation[User], error) {
	changes, err := p.changes()
	if err != nil {
		return ldapmodel.Mutation[User]{}, err
	}
	return ldapmodel.NewMutation[User](changes...), nil
}

func (p UserPatch) changes() ([]arden.Change, error) {
	changes := make([]arden.Change, 0, 7)
	var err error
	if changes, err = appendReplacement(changes, UserAttributes.CommonName, p.commonName); err != nil {
		return nil, err
	}
	if changes, err = appendReplacement(changes, UserAttributes.UIDNumber, p.uidNumber); err != nil {
		return nil, err
	}
	if changes, err = appendReplacement(changes, UserAttributes.GIDNumber, p.gidNumber); err != nil {
		return nil, err
	}
	if changes, err = appendReplacement(changes, UserAttributes.HomeDirectory, p.homeDirectory); err != nil {
		return nil, err
	}
	if changes, err = appendReplacement(changes, UserAttributes.GECOS, p.gecos); err != nil {
		return nil, err
	}
	if changes, err = appendReplacement(changes, UserAttributes.LoginShell, p.loginShell); err != nil {
		return nil, err
	}
	if changes, err = appendReplacement(changes, UserAttributes.EmailAddresses, p.emailAddresses); err != nil {
		return nil, err
	}
	return changes, nil
}

func appendReplacement[T any](
	changes []arden.Change,
	attribute schema.Attribute[T],
	replacement replacement[T],
) ([]arden.Change, error) {
	if !replacement.present {
		return changes, nil
	}
	encoded := make([][]byte, len(replacement.values))
	for i, value := range replacement.values {
		wire, err := attribute.Codec.Encode(value)
		if err != nil {
			return nil, fmt.Errorf("encode replacement for %s value %d: %w", attribute.Name, i, err)
		}
		encoded[i] = wire
	}
	return append(changes, arden.ReplaceBytes(attribute.Name, encoded...)), nil
}

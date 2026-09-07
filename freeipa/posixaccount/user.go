// Package posixaccount demonstrates the complete output of an LDAP model generator.
//
// This file is a hand-written prototype of generated output; no generator exists
// yet. All model-specific code lives here: the projection, attribute mappings,
// decoder, indexed predicates, and legal patch operations. Reusable behavior
// lives in schema (codecs and filters) and ldapmodel (decoding cardinality,
// replacement encoding, and DAO lifecycle).
package posixaccount

import (
	"fmt"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ldapmodel"
	"github.com/wyattanderson/arden/schema"
)

// UserAttributes is the generated, typed vocabulary shared by model decoding,
// indexed predicates, and patches. Go field names are application vocabulary;
// descriptor names are LDAP schema vocabulary.
var UserAttributes = struct {
	AccountName    schema.Attribute[string]
	CommonName     schema.Attribute[string]
	UIDNumber      schema.Attribute[uint32]
	GIDNumber      schema.Attribute[uint32]
	HomeDirectory  schema.Attribute[string]
	GECOS          schema.Attribute[string]
	LoginShell     schema.Attribute[string]
	EmailAddresses schema.Attribute[string]
}{
	AccountName:    schema.NewAttribute("uid", schema.StringCodec),
	CommonName:     schema.NewAttribute("cn", schema.StringCodec),
	UIDNumber:      schema.NewAttribute("uidNumber", schema.Uint32Codec),
	GIDNumber:      schema.NewAttribute("gidNumber", schema.Uint32Codec),
	HomeDirectory:  schema.NewAttribute("homeDirectory", schema.StringCodec),
	GECOS:          schema.NewAttribute("gecos", schema.StringCodec),
	LoginShell:     schema.NewAttribute("loginShell", schema.StringCodec),
	EmailAddresses: schema.NewAttribute("mail", schema.StringCodec),
}

var userProjection = arden.NewAttributeSelectors(
	UserAttributes.AccountName.Name(),
	UserAttributes.CommonName.Name(),
	UserAttributes.UIDNumber.Name(),
	UserAttributes.GIDNumber.Name(),
	UserAttributes.HomeDirectory.Name(),
	UserAttributes.GECOS.Name(),
	UserAttributes.LoginShell.Name(),
	UserAttributes.EmailAddresses.Name(),
)

// User is the fixed projection decoded by the generated Users model. Required,
// single-valued POSIX attributes use values; optional single-valued attributes
// use pointers; multi-valued attributes use slices.
type User struct {
	DN             arden.LDAPDN
	AccountName    string
	CommonName     string
	UIDNumber      uint32
	GIDNumber      uint32
	HomeDirectory  string
	GECOS          *string
	LoginShell     *string
	EmailAddresses []string
}

// DecodeUser validates and converts the fixed User projection. It is exported
// so higher-level packages can reuse the generated model with entries obtained
// through controls or extensions that the generic DAO does not know about.
func DecodeUser(entry arden.Entry) (User, error) {
	accountName, err := ldapmodel.RequiredOne(UserAttributes.AccountName, entry)
	if err != nil {
		return User{}, decodeUserError(entry, err)
	}
	commonName, err := ldapmodel.RequiredOne(UserAttributes.CommonName, entry)
	if err != nil {
		return User{}, decodeUserError(entry, err)
	}
	uidNumber, err := ldapmodel.RequiredOne(UserAttributes.UIDNumber, entry)
	if err != nil {
		return User{}, decodeUserError(entry, err)
	}
	gidNumber, err := ldapmodel.RequiredOne(UserAttributes.GIDNumber, entry)
	if err != nil {
		return User{}, decodeUserError(entry, err)
	}
	homeDirectory, err := ldapmodel.RequiredOne(UserAttributes.HomeDirectory, entry)
	if err != nil {
		return User{}, decodeUserError(entry, err)
	}
	gecos, err := ldapmodel.OptionalOne(UserAttributes.GECOS, entry)
	if err != nil {
		return User{}, decodeUserError(entry, err)
	}
	loginShell, err := ldapmodel.OptionalOne(UserAttributes.LoginShell, entry)
	if err != nil {
		return User{}, decodeUserError(entry, err)
	}
	emailAddresses, err := UserAttributes.EmailAddresses.Values(entry)
	if err != nil {
		return User{}, decodeUserError(entry, err)
	}

	return User{
		DN:             entry.DN,
		AccountName:    accountName,
		CommonName:     commonName,
		UIDNumber:      uidNumber,
		GIDNumber:      gidNumber,
		HomeDirectory:  homeDirectory,
		GECOS:          gecos,
		LoginShell:     loginShell,
		EmailAddresses: emailAddresses,
	}, nil
}

func decodeUserError(entry arden.Entry, err error) error {
	return fmt.Errorf("decode user %q: %w", entry.DN, err)
}

// Users returns the generated User model bound to a directory search base.
// The generic ldapmodel.DAO supplies query and mutation behavior.
func Users(baseDN arden.LDAPDN) ldapmodel.Model[User] {
	return ldapmodel.NewModel(
		baseDN,
		arden.ScopeChildren,
		arden.Equal("objectClass", "posixAccount"),
		userProjection,
		DecodeUser,
	)
}

// AccountNameIs matches the POSIX uid index.
func AccountNameIs(value string) ldapmodel.Criterion[User] {
	return ldapmodel.NewCriterion[User](UserAttributes.AccountName.MustEqual(value))
}

// UIDNumberIs matches the POSIX uidNumber index.
func UIDNumberIs(value uint32) ldapmodel.Criterion[User] {
	return ldapmodel.NewCriterion[User](UserAttributes.UIDNumber.MustEqual(value))
}

// GIDNumberIs matches the POSIX gidNumber index.
func GIDNumberIs(value uint32) ldapmodel.Criterion[User] {
	return ldapmodel.NewCriterion[User](UserAttributes.GIDNumber.MustEqual(value))
}

// UserPatch is an explicit set of LDAP replacements. Its zero value contains
// no changes. Calling a method again replaces the earlier intent for that
// field, and generated field order determines Modify change order.
//
// AccountName is deliberately absent: changing uid can also change the RDN and
// therefore needs a separate rename contract built around ModifyDN.
type UserPatch struct {
	commonName     ldapmodel.Replacement[string]
	uidNumber      ldapmodel.Replacement[uint32]
	gidNumber      ldapmodel.Replacement[uint32]
	homeDirectory  ldapmodel.Replacement[string]
	gecos          ldapmodel.Replacement[string]
	loginShell     ldapmodel.Replacement[string]
	emailAddresses ldapmodel.Replacement[string]
}

// SetCommonName replaces the required cn value.
func (p *UserPatch) SetCommonName(value string) {
	p.commonName.Set(value)
}

// SetUIDNumber replaces the required uidNumber value.
func (p *UserPatch) SetUIDNumber(value uint32) {
	p.uidNumber.Set(value)
}

// SetGIDNumber replaces the required gidNumber value.
func (p *UserPatch) SetGIDNumber(value uint32) {
	p.gidNumber.Set(value)
}

// SetHomeDirectory replaces the required homeDirectory value.
func (p *UserPatch) SetHomeDirectory(value string) {
	p.homeDirectory.Set(value)
}

// SetGECOS replaces the optional gecos value.
func (p *UserPatch) SetGECOS(value string) {
	p.gecos.Set(value)
}

// ClearGECOS removes the optional gecos attribute.
func (p *UserPatch) ClearGECOS() {
	p.gecos.Clear()
}

// SetLoginShell replaces the optional loginShell value.
func (p *UserPatch) SetLoginShell(value string) {
	p.loginShell.Set(value)
}

// ClearLoginShell removes the optional loginShell attribute.
func (p *UserPatch) ClearLoginShell() {
	p.loginShell.Clear()
}

// ReplaceEmailAddresses replaces all mail values. With no values it removes
// the attribute.
func (p *UserPatch) ReplaceEmailAddresses(values ...string) {
	p.emailAddresses.Set(values...)
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
	if changes, err = p.commonName.AppendChanges(changes, UserAttributes.CommonName); err != nil {
		return nil, err
	}
	if changes, err = p.uidNumber.AppendChanges(changes, UserAttributes.UIDNumber); err != nil {
		return nil, err
	}
	if changes, err = p.gidNumber.AppendChanges(changes, UserAttributes.GIDNumber); err != nil {
		return nil, err
	}
	if changes, err = p.homeDirectory.AppendChanges(changes, UserAttributes.HomeDirectory); err != nil {
		return nil, err
	}
	if changes, err = p.gecos.AppendChanges(changes, UserAttributes.GECOS); err != nil {
		return nil, err
	}
	if changes, err = p.loginShell.AppendChanges(changes, UserAttributes.LoginShell); err != nil {
		return nil, err
	}
	if changes, err = p.emailAddresses.AppendChanges(changes, UserAttributes.EmailAddresses); err != nil {
		return nil, err
	}
	return changes, nil
}

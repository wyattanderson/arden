// Package posixaccount demonstrates the complete output of an LDAP model generator.
//
// This file is a hand-written prototype of generated output; no generator exists
// yet. All model-specific code lives here: the projection, attribute mappings,
// decoder, indexed predicates, and model-specific attributes. Reusable behavior
// lives in ldapmodel (attributes, codecs, filters, decoding cardinality,
// change encoding, and DAO lifecycle).
package posixaccount

import (
	"fmt"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ldapmodel"
)

// UserAttributes is the generated, typed vocabulary shared by model decoding,
// indexed predicates, and changes. Go field names are application vocabulary;
// descriptor names are LDAP schema vocabulary.
var UserAttributes = struct {
	AccountName    ldapmodel.Attribute[User, string]
	CommonName     ldapmodel.Attribute[User, string]
	UIDNumber      ldapmodel.Attribute[User, uint32]
	GIDNumber      ldapmodel.Attribute[User, uint32]
	HomeDirectory  ldapmodel.Attribute[User, string]
	GECOS          ldapmodel.Attribute[User, string]
	LoginShell     ldapmodel.Attribute[User, string]
	EmailAddresses ldapmodel.Attribute[User, string]
}{
	AccountName:    ldapmodel.NewAttribute[User]("uid", ldapmodel.StringCodec),
	CommonName:     ldapmodel.NewAttribute[User]("cn", ldapmodel.StringCodec),
	UIDNumber:      ldapmodel.NewAttribute[User]("uidNumber", ldapmodel.Uint32Codec),
	GIDNumber:      ldapmodel.NewAttribute[User]("gidNumber", ldapmodel.Uint32Codec),
	HomeDirectory:  ldapmodel.NewAttribute[User]("homeDirectory", ldapmodel.StringCodec),
	GECOS:          ldapmodel.NewAttribute[User]("gecos", ldapmodel.StringCodec),
	LoginShell:     ldapmodel.NewAttribute[User]("loginShell", ldapmodel.StringCodec),
	EmailAddresses: ldapmodel.NewAttribute[User]("mail", ldapmodel.StringCodec),
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

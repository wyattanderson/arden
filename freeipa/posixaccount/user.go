package posixaccount

import (
	"fmt"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ldapmodel"
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

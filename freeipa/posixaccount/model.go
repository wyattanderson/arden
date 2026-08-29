package posixaccount

import (
	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ldapmodel"
)

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

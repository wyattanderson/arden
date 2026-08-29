package posixaccount

import (
	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ldapmodel"
)

// AccountNameIs matches the POSIX uid index.
func AccountNameIs(value string) ldapmodel.Criterion[User] {
	return ldapmodel.NewCriterion[User](arden.Equal(UserAttributes.AccountName.Name, value))
}

// UIDNumberIs matches the POSIX uidNumber index.
func UIDNumberIs(value uint32) ldapmodel.Criterion[User] {
	return ldapmodel.NewCriterion[User](equalUint32(UserAttributes.UIDNumber.Name, value))
}

// GIDNumberIs matches the POSIX gidNumber index.
func GIDNumberIs(value uint32) ldapmodel.Criterion[User] {
	return ldapmodel.NewCriterion[User](equalUint32(UserAttributes.GIDNumber.Name, value))
}

func equalUint32(attribute string, value uint32) arden.Filter {
	encoded, err := uint32Codec.Encode(value)
	if err != nil {
		// This codec cannot fail to encode a uint32. Treat a future change to
		// that invariant as a generated-code defect, not a query-time error.
		panic(err)
	}
	return arden.EqualBytes(attribute, encoded)
}

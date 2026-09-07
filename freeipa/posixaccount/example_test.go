package posixaccount_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ldapmodel"

	"github.com/wyattanderson/arden/freeipa/posixaccount"
)

func Example() {
	// client is an *arden.Client connected and authenticated elsewhere.
	var client = newLDAPClientForExample()
	ctx := context.Background()
	dao := ldapmodel.NewDAO(
		client,
		posixaccount.Users("cn=users,cn=accounts,dc=arden,dc=test"),
	).WithContext(ctx)

	user, err := dao.Where(posixaccount.AccountNameIs("alice")).One()
	if err != nil && !errors.Is(err, errExampleOnly) {
		panic(err)
	}
	_ = user

	users, err := dao.Where(
		posixaccount.UIDNumberIs(1200),
		posixaccount.GIDNumberIs(1200),
	).All()
	if err != nil && !errors.Is(err, errExampleOnly) {
		panic(err)
	}
	for _, user := range users {
		fmt.Println(user.AccountName)
	}

	if user.DN != "" {
		if err := dao.Modify(user.DN,
			ldapmodel.Replace(posixaccount.UserAttributes.LoginShell, "/bin/zsh"),
			ldapmodel.Replace(posixaccount.UserAttributes.GECOS, "Alice Example"),
			ldapmodel.Replace(posixaccount.UserAttributes.EmailAddresses, "alice@example.test"),
		); err != nil {
			panic(err)
		}
	}
}

// The example is compile-checked but does not need a live directory.
var errExampleOnly = errors.New("example only")

func newLDAPClientForExample() *arden.Client {
	return arden.NewClient(exampleExecutor{})
}

type exampleExecutor struct{}

func (exampleExecutor) Do(context.Context, arden.AnyOperation) (arden.ResponseStream, error) {
	return nil, errExampleOnly
}

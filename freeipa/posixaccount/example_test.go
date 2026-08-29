package posixaccount_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/freeipa/posixaccount"
	"github.com/wyattanderson/arden/ldapmodel"
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

	var patch posixaccount.UserPatch
	patch.SetLoginShell("/bin/zsh")
	patch.SetGECOS("Alice Example")
	patch.ReplaceEmailAddresses("alice@example.test")
	if user.DN != "" {
		if err := dao.Update(user.DN, patch); err != nil {
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

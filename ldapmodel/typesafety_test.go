package ldapmodel_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile real callers so changes to generic signatures cannot silently weaken
// the model or value constraints. These programs never contact a directory.
func TestMutationTypeSafety(t *testing.T) {
	const declarations = `package typesafety
import "github.com/wyattanderson/arden/ldapmodel"
import "github.com/wyattanderson/arden"
type User struct{}
type Group struct{}
var mail = ldapmodel.NewAttribute[User]("mail", ldapmodel.StringCodec)
var uid = ldapmodel.NewAttribute[User]("uidNumber", ldapmodel.Uint32Codec)
var photo = ldapmodel.NewAttribute[User]("jpegPhoto", ldapmodel.BytesCodec)
var groupName = ldapmodel.NewAttribute[Group]("cn", ldapmodel.StringCodec)
var dao ldapmodel.DAO[User]
var selectors arden.AttributeSelectors
var decode = func(arden.Entry) (User, error) { return User{}, nil }
func example() {
`
	for _, test := range []struct {
		name string
		body string
		want string
	}{
		{"mixed values", `dao.Modify("uid=alice", ldapmodel.Add(mail, "alice@example.test"), ldapmodel.Delete(mail), ldapmodel.Replace(uid, 1200), ldapmodel.Replace(photo, []byte{1}))`, ""},
		{"wrong model", `dao.Modify("uid=alice", ldapmodel.Replace(groupName, "admins"))`, "as ldapmodel.Change[User] value"},
		{"wrong add value", `ldapmodel.Add(uid, "1200")`, "as uint32 value"},
		{"wrong delete value", `ldapmodel.Delete(mail, 1200)`, "as string value"},
		{"wrong replace value", `ldapmodel.Replace(uid, "1200")`, "as uint32 value"},
		{"add mixed values", `dao.Add("alice", ldapmodel.Set(mail, "alice@example.test"), ldapmodel.Set(uid, 1200), ldapmodel.Set(photo, []byte{1}))`, ""},
		{"add wrong model", `dao.Add("alice", ldapmodel.Set(groupName, "admins"))`, "as ldapmodel.Assignment[User] value"},
		{"assignment wrong value", `ldapmodel.Set(uid, "1200")`, "as uint32 value"},
		{"add rejects change", `dao.Add("alice", ldapmodel.Delete(mail))`, "as ldapmodel.Assignment[User] value"},
		{"naming descriptor", `ldapmodel.NewModel("dc=example", arden.ScopeSubtree, []string{"person"}, mail, selectors, decode)`, ""},
		{"naming wrong model", `ldapmodel.NewModel("dc=example", arden.ScopeSubtree, []string{"person"}, groupName, selectors, decode)`, "does not match inferred type"},
		{"naming wrong type", `ldapmodel.NewModel("dc=example", arden.ScopeSubtree, []string{"person"}, uid, selectors, decode)`, "does not match inferred type"},
		{"modify rejects assignment", `dao.Modify("uid=alice", ldapmodel.Set(mail, "alice@example.test"))`, "as ldapmodel.Change[User] value"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "caller.go")
			require.NoError(t, os.WriteFile(source, []byte(declarations+test.body+"\n}\n"), 0o600))
			output, err := exec.CommandContext(t.Context(), "go", "test", "-vet=off", source).CombinedOutput()
			if test.want == "" {
				require.NoError(t, err, "valid caller failed to compile:\n%s", output)
				return
			}
			require.Error(t, err, "invalid caller compiled successfully")
			// Compiler diagnostics must identify the intended type mismatch, rather
			// than an unrelated build or environment failure.
			assert.Contains(t, string(output), test.want)
		})
	}
}

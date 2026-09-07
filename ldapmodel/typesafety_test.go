package ldapmodel_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Compile real callers so changes to generic signatures cannot silently weaken
// the model or value constraints. These programs never contact a directory.
func TestModifyTypeSafety(t *testing.T) {
	const declarations = `package typesafety
import "github.com/wyattanderson/arden/ldapmodel"
type User struct{}
type Group struct{}
var mail = ldapmodel.NewAttribute[User]("mail", ldapmodel.StringCodec)
var uid = ldapmodel.NewAttribute[User]("uidNumber", ldapmodel.Uint32Codec)
var photo = ldapmodel.NewAttribute[User]("jpegPhoto", ldapmodel.BytesCodec)
var groupName = ldapmodel.NewAttribute[Group]("cn", ldapmodel.StringCodec)
var dao ldapmodel.DAO[User]
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
	} {
		t.Run(test.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "caller.go")
			if err := os.WriteFile(source, []byte(declarations+test.body+"\n}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := exec.CommandContext(t.Context(), "go", "test", "-vet=off", source).CombinedOutput()
			if test.want == "" {
				if err != nil {
					t.Fatalf("valid caller failed to compile: %v\n%s", err, output)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid caller compiled successfully")
			}
			// Compiler diagnostics must identify the intended type mismatch, rather
			// than an unrelated build or environment failure.
			if !strings.Contains(string(output), test.want) {
				t.Fatalf("expected diagnostic containing %q, got:\n%s", test.want, output)
			}
		})
	}
}

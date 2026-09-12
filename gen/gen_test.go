package gen_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/gen"
)

func clientConfig(t *testing.T) gen.Config {
	t.Helper()
	data, err := os.ReadFile("testdata/client.yaml")
	require.NoError(t, err)
	c, err := gen.Parse(data)
	require.NoError(t, err)
	return c
}

func TestClientArtifactsAreCurrent(t *testing.T) {
	c := clientConfig(t)
	result, err := gen.Generate(c)
	require.NoError(t, err)
	for name, content := range result.Models {
		checkedIn, err := os.ReadFile(filepath.Join("internal", name))
		require.NoError(t, err)
		assert.Equal(t, string(checkedIn), string(content), "regenerate with cmd/gen")
	}
	schema, err := os.ReadFile("testdata/client.generated.ldif")
	require.NoError(t, err)
	assert.Equal(t, string(schema), string(result.Schema))
	assert.Equal(t, 15, strings.Count(string(result.Schema), "attributeTypes:"))
	assert.Contains(t, string(result.Schema), "1.3.6.1.4.1.66553.1.1.8 NAME 'ipaOidcIdpResponseType'")
	assert.Contains(t, string(result.Schema), "1.3.6.1.4.1.66553.1.2.2 NAME 'ipaOidcIdpClient'")
	assert.NotContains(t, string(result.Schema), "NAME 'ipaUniqueID'")
	assert.NotContains(t, string(result.Schema), "\n\nobjectClasses:")
	for range 5 {
		again, err := gen.Generate(c)
		require.NoError(t, err)
		assert.Equal(t, result, again)
	}
}

func TestSchemaInferenceWithoutOverrides(t *testing.T) {
	c := clientConfig(t)
	c.Models[0].Overrides = nil
	result, err := gen.Generate(c)
	require.NoError(t, err)
	code := string(result.Models["clientmodel/client_gen.go"])
	// Ignore gofmt alignment when checking the inferred public contract.
	compact := strings.Join(strings.Fields(code), " ")
	for _, want := range []string{"ClientId string", "Descriptions []string", "ResponseTypes []string", "Enabled bool", "RequireConsent *bool", "MaxAuthAge *int64", "PolicyDns []arden.LDAPDN", "IpaUniqueIDs []string", "DisplayName *string", "SecretDigest *[]byte"} {
		assert.Contains(t, compact, want)
	}
	assert.Contains(t, code, "ldapmodel.RequiredMany(ClientAttributes.IpaUniqueIDs, entry)")
}

func TestRejectInvalidYAML(t *testing.T) {
	for _, input := range []string{
		"version: 1\nschema:\n  single_value: true\n",
		"version: 1\nversion: 1\n",
		"version: 1\n---\nversion: 1\n",
		"version: 2\n",
		"version: 1\nschema: &schema {}\n",
		"version: 1\nmodels:\n- name: A\n  overrides:\n    cn:\n      reed: none\n",
	} {
		_, err := gen.Parse([]byte(input))
		require.Error(t, err, input)
	}
}

func TestRejectInvalidDefinitions(t *testing.T) {
	tests := []struct {
		name, match string
		change      func(*gen.Config)
	}{
		{"missing external cardinality", "requires syntax and singleValue", func(c *gen.Config) {
			a := c.Schema.External.Attributes["ipaUniqueID"]
			a.SingleValue = nil
			c.Schema.External.Attributes["ipaUniqueID"] = a
		}},
		{"duplicate OID", "duplicate OID", func(c *gen.Config) {
			a := c.Schema.Attributes["ipaOidcIdpClientId"]
			a.OID = "3"
			c.Schema.Attributes["ipaOidcIdpClientId"] = a
		}},
		{"invalid base", "invalid OID", func(c *gen.Config) { c.Schema.OIDBases.Attributes = "1.999" }},
		{"duplicate LDAP name", "duplicate LDAP name", func(c *gen.Config) {
			c.Schema.Attributes["IPAOIDCIdpCLIENTID"] = gen.Attribute{OID: "100", Syntax: "directoryString"}
		}},
		{"missing member", "unknown attribute", func(c *gen.Config) { delete(c.Schema.Attributes, "ipaOidcIdpClientId") }},
		{"class cycle", "inheritance cycle", func(c *gen.Config) {
			cl := c.Schema.ObjectClasses["ipaOidcIdpClient"]
			cl.Sup = []string{"ipaOidcIdpClient"}
			c.Schema.ObjectClasses["ipaOidcIdpClient"] = cl
		}},
		{"attribute cycle", "inheritance cycle", func(c *gen.Config) {
			a := c.Schema.Attributes["ipaOidcIdpClientId"]
			a.Sup = "ipaOidcIdpClientId"
			c.Schema.Attributes["ipaOidcIdpClientId"] = a
		}},
		{"unknown override", "nonmember", func(c *gen.Config) { c.Models[0].Overrides["typo"] = gen.Override{Name: "Oops"} }},
		{"field collision", "duplicate inferred field", func(c *gen.Config) { c.Models[0].Overrides["ipaOidcIdpEnabled"] = gen.Override{Name: "ClientID"} }},
		{"reserved DN", "duplicate inferred field", func(c *gen.Config) { c.Models[0].Overrides["ipaOidcIdpEnabled"] = gen.Override{Name: "DN"} }},
		{"scope", "invalid scope", func(c *gen.Config) { c.Models[0].Scope = "all" }},
		{"naming type", "value type string", func(c *gen.Config) { c.Models[0].NamingAttribute = "ipaOidcIdpEnabled" }},
		{"unknown read", "invalid read", func(c *gen.Config) { c.Models[0].Overrides["ipaOidcIdpEnabled"] = gen.Override{Read: "first"} }},
		{"unknown syntax", "explicit type and codec", func(c *gen.Config) {
			a := c.Schema.Attributes["ipaOidcIdpEnabled"]
			a.Syntax = "1.2.3.4"
			c.Schema.Attributes["ipaOidcIdpEnabled"] = a
		}},
		{"expression", "unsupported Go expression", func(c *gen.Config) { c.Models[0].Overrides["ipaOidcIdpEnabled"] = gen.Override{Codec: "panic(1)"} }},
		{"missing import", "missing import", func(c *gen.Config) { c.Models[0].Overrides["ipaOidcIdpEnabled"] = gen.Override{Codec: "custom.Codec"} }},
		{"predicate collision", "duplicate generated symbol", func(c *gen.Config) { other := c.Models[0]; other.Name = "Other"; c.Models = append(c.Models, other) }},
		{"unknown index", "nonmember", func(c *gen.Config) { c.Models[0].Indexes.Equality = []string{"typo"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := clientConfig(t)
			test.change(&c)
			_, err := gen.Generate(c)
			require.ErrorContains(t, err, test.match)
		})
	}
}

func TestInheritanceOverridesAndEscaping(t *testing.T) {
	c := clientConfig(t)
	c.Schema.Origin = "origin'\n\\é"
	c.Schema.Attributes["extra"] = gen.Attribute{OID: "1.2.3.4", Sup: "ipaOidcIdpClientId"}
	c.Schema.ObjectClasses["derivedClient"] = gen.ObjectClass{OID: "99", Sup: []string{"ipaOidcIdpClient"}, Kind: "structural", Must: []string{"extra"}}
	c.Models[0].ObjectClasses = []string{"derivedClient"}
	c.Models[0].Overrides["ipaOidcIdpSecretDigest"] = gen.Override{Read: "none"}
	c.Models[0].Validate = "validateClient"
	result, err := gen.Generate(c)
	require.NoError(t, err)
	code := string(result.Models["clientmodel/client_gen.go"])
	assert.Contains(t, code, `[]string{"top", "ipaOidcIdpClient", "derivedClient"}`)
	assert.Contains(t, code, "ldapmodel.RequiredOne(ClientAttributes.Extra, entry)")
	assert.Contains(t, code, "validateClient(value)")
	assert.Contains(t, code, "SecretDigest") // Descriptor is still available for writes.
	assert.NotContains(t, code, "value.SecretDigest")
	assert.Contains(t, string(result.Schema), `X-ORIGIN 'origin\27\0a\5c\c3\a9'`)
	assert.Contains(t, string(result.Schema), "attributeTypes: ( 1.2.3.4 NAME 'extra' SUP ipaOidcIdpClientId")
}

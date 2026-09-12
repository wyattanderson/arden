// Package gen generates LDAP schema LDIF and reflection-free Go models from YAML.
package gen

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"
)

// Config is the versioned generator input. Maps are emitted in sorted order.
type Config struct {
	Version int     `yaml:"version"`
	Schema  Schema  `yaml:"schema"`
	Models  []Model `yaml:"models"`
}

// Schema contains owned definitions and metadata about definitions installed elsewhere.
type Schema struct {
	Origin   string `yaml:"origin"`
	OIDBases struct {
		Attributes    string `yaml:"attributes"`
		ObjectClasses string `yaml:"objectClasses"`
	} `yaml:"oidBases"`
	External struct {
		Attributes    map[string]Attribute `yaml:"attributes"`
		ObjectClasses []string             `yaml:"objectClasses"`
	} `yaml:"external"`
	Attributes    map[string]Attribute   `yaml:"attributes"`
	ObjectClasses map[string]ObjectClass `yaml:"objectClasses"`
}

// Attribute defines an LDAP value; nil SingleValue inherits from Sup or defaults to false.
type Attribute struct {
	OID         string `yaml:"oid"`
	Description string `yaml:"description"`
	Sup         string `yaml:"sup"`
	Syntax      string `yaml:"syntax"`
	Equality    string `yaml:"equality"`
	Ordering    string `yaml:"ordering"`
	Substr      string `yaml:"substr"`
	SingleValue *bool  `yaml:"singleValue"`
}

// ObjectClass defines membership and inheritance independently of Go projections.
type ObjectClass struct {
	OID         string   `yaml:"oid"`
	Description string   `yaml:"description"`
	Sup         []string `yaml:"sup"`
	Kind        string   `yaml:"kind"`
	Must        []string `yaml:"must"`
	May         []string `yaml:"may"`
}

// Model selects object classes and overrides inferred Go representation.
type Model struct {
	Name            string              `yaml:"name"`
	Package         string              `yaml:"package"`
	Constructor     string              `yaml:"constructor"`
	AttributePrefix string              `yaml:"attributePrefix"`
	ObjectClasses   []string            `yaml:"objectClasses"`
	Scope           string              `yaml:"scope"`
	NamingAttribute string              `yaml:"namingAttribute"`
	Overrides       map[string]Override `yaml:"overrides"`
	// Imports supplies aliases for custom types, codecs, and validation functions.
	Imports map[string]string `yaml:"imports"`
	// Validate names a handwritten func(Model) error, called after decoding.
	Validate string `yaml:"validate"`
	Indexes  struct {
		Equality []string `yaml:"equality"`
	} `yaml:"indexes"`
}

// Override changes application representation without changing emitted LDAP schema.
type Override struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"`
	Codec string `yaml:"codec"`
	Read  string `yaml:"read"`
}

// Parse reads exactly one YAML document, rejecting unknown keys, aliases, and merges.
// Generate performs semantic validation before emitting any artifacts.
func Parse(data []byte) (Config, error) {
	var c Config
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return c, fmt.Errorf("gen: YAML: %w", err)
	}
	if err := plainYAML(&root); err != nil {
		return c, err
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("gen: YAML: %w", err)
	}
	var extra yaml.Node
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return c, errors.New("gen: expected exactly one YAML document")
	}
	if c.Version != 1 {
		return c, fmt.Errorf("gen: unsupported format version %d", c.Version)
	}
	return c, nil
}

func plainYAML(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag == "!!merge" {
		return fmt.Errorf("gen: YAML line %d: anchors, aliases, and merges are unsupported", n.Line)
	}
	for _, child := range n.Content {
		if err := plainYAML(child); err != nil {
			return err
		}
	}
	return nil
}

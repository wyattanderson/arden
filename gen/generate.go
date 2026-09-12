package gen

import (
	"bytes"
	"embed"
	"fmt"
	"go/format"
	"path"
	"strconv"
	"strings"
	"text/template"
)

//go:embed model.go.tmpl schema.ldif.tmpl
var templateFiles embed.FS

var templates = template.Must(template.New("gen").Funcs(template.FuncMap{
	"quote":       strconv.Quote,
	"schemaQuote": schemaQuote,
	"upper":       strings.ToUpper,
	"exported":    exported,
	"base":        path.Base,
	"contains":    strings.Contains,
	"join":        strings.Join,
	"syntaxOID":   func(s string) string { return syntaxFor(s).oid },
	"singleValue": func(value *bool) bool { return value != nil && *value },
}).ParseFS(templateFiles, "model.go.tmpl", "schema.ldif.tmpl"))

// Result contains deterministic outputs. Models paths are relative to an output
// directory: <package>/<lowercase model>_gen.go. No files are written by Generate.
type Result struct {
	Schema []byte
	Models map[string][]byte
}

// Generate validates the complete configuration and renders both output formats.
func Generate(c Config) (Result, error) {
	r, err := resolve(c)
	if err != nil {
		return Result{}, fmt.Errorf("gen: %w", err)
	}
	schema, err := renderSchema(c, r)
	if err != nil {
		return Result{}, fmt.Errorf("gen: schema: %w", err)
	}
	result := Result{Schema: schema, Models: map[string][]byte{}}
	for _, m := range r.models {
		file := path.Join(m.Package, strings.ToLower(m.Name)+"_gen.go")
		if _, exists := result.Models[file]; exists {
			return Result{}, fmt.Errorf("gen: duplicate output path %s", file)
		}
		code, err := renderModel(m)
		if err != nil {
			return Result{}, fmt.Errorf("gen: model %s: %w", m.Name, err)
		}
		result.Models[file] = code
	}
	return result, nil
}

// schemaQuote escapes RFC 4512 quoted strings, including non-ASCII UTF-8 octets.
func schemaQuote(s string) string {
	const hex = "0123456789abcdef"
	var b strings.Builder
	b.WriteByte('\'')
	for _, c := range []byte(s) {
		if c < 32 || c > 126 || c == '\'' || c == '\\' {
			b.WriteByte('\\')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		} else {
			b.WriteByte(c)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

func renderSchema(c Config, r *resolved) ([]byte, error) {
	data := struct {
		Origin        string
		Attributes    []resolvedAttribute
		ObjectClasses []resolvedClass
	}{Origin: c.Schema.Origin}
	for _, key := range r.ownedAttrs {
		data.Attributes = append(data.Attributes, r.attrs[key])
	}
	for _, key := range r.ownedClasses {
		data.ObjectClasses = append(data.ObjectClasses, r.classes[key])
	}
	var b bytes.Buffer
	if err := templates.ExecuteTemplate(&b, "schema.ldif.tmpl", data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func renderModel(m resolvedModel) ([]byte, error) {
	m.UsedImports["fmt"] = "fmt"
	m.UsedImports["arden"] = "github.com/wyattanderson/arden"
	m.UsedImports["ldapmodel"] = "github.com/wyattanderson/arden/ldapmodel"
	data := struct {
		resolvedModel
		Projection []field
	}{resolvedModel: m}
	for _, a := range m.Fields {
		if a.Read != "none" {
			data.Projection = append(data.Projection, a)
		}
	}
	var b bytes.Buffer
	if err := templates.ExecuteTemplate(&b, "model.go.tmpl", data); err != nil {
		return nil, err
	}
	return format.Source(b.Bytes())
}

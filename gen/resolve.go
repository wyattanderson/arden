package gen

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var ldapName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)
var numericOID = regexp.MustCompile(`^(0|1|2)(\.(0|[1-9][0-9]*))+$`)
var oidSuffix = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

type resolvedAttribute struct {
	Name string
	Attribute
}
type resolvedClass struct {
	Name string
	ObjectClass
}
type field struct {
	LDAP, Name, Type, Codec, Read string
}
type resolvedModel struct {
	Model
	Fields      []field
	Classes     []string
	Naming      string
	Predicates  []field
	UsedImports map[string]string
}
type resolved struct {
	attrs                    map[string]resolvedAttribute
	classes                  map[string]resolvedClass
	ownedAttrs, ownedClasses []string
	models                   []resolvedModel
}

func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

func expandOID(base, value string) (string, error) {
	if oidSuffix.MatchString(value) && base != "" {
		value = base + "." + value
	}
	if !numericOID.MatchString(value) {
		return "", fmt.Errorf("invalid OID %q", value)
	}
	parts := strings.Split(value, ".")
	if parts[0] != "2" {
		second, err := strconv.Atoi(parts[1])
		if err != nil || second > 39 {
			return "", fmt.Errorf("invalid OID %q", value)
		}
	}
	return value, nil
}

func resolve(c Config) (*resolved, error) {
	if c.Version != 1 {
		return nil, fmt.Errorf("gen: unsupported format version %d", c.Version)
	}
	r := &resolved{attrs: map[string]resolvedAttribute{}, classes: map[string]resolvedClass{}}
	names, oids := map[string]bool{}, map[string]bool{}
	claim := func(name, oid string) error {
		key := strings.ToLower(name)
		if !ldapName.MatchString(name) {
			return fmt.Errorf("invalid LDAP name %q", name)
		}
		if names[key] {
			return fmt.Errorf("duplicate LDAP name %q", name)
		}
		names[key] = true
		if oid != "" {
			if oids[oid] {
				return fmt.Errorf("duplicate OID %s", oid)
			}
			oids[oid] = true
		}
		return nil
	}
	for _, base := range []string{c.Schema.OIDBases.Attributes, c.Schema.OIDBases.ObjectClasses} {
		if base != "" {
			if _, err := expandOID("", base); err != nil {
				return nil, err
			}
		}
	}
	for _, external := range []bool{true, false} {
		attrs := c.Schema.Attributes
		if external {
			attrs = c.Schema.External.Attributes
		}
		for _, name := range sortedKeys(attrs) {
			a := attrs[name]
			if external {
				if a.Syntax == "" || a.SingleValue == nil {
					return nil, fmt.Errorf("external attribute %s requires syntax and singleValue", name)
				}
				if a.OID != "" {
					return nil, fmt.Errorf("external attribute %s must not declare an owned OID", name)
				}
			} else {
				var err error
				a.OID, err = expandOID(c.Schema.OIDBases.Attributes, a.OID)
				if err != nil {
					return nil, fmt.Errorf("attribute %s: %w", name, err)
				}
				r.ownedAttrs = append(r.ownedAttrs, strings.ToLower(name))
			}
			if err := claim(name, a.OID); err != nil {
				return nil, err
			}
			r.attrs[strings.ToLower(name)] = resolvedAttribute{name, a}
		}
	}
	for _, name := range c.Schema.External.ObjectClasses {
		if err := claim(name, ""); err != nil {
			return nil, err
		}
		r.classes[strings.ToLower(name)] = resolvedClass{Name: name}
	}
	for _, name := range sortedKeys(c.Schema.ObjectClasses) {
		cl := c.Schema.ObjectClasses[name]
		var err error
		cl.OID, err = expandOID(c.Schema.OIDBases.ObjectClasses, cl.OID)
		if err != nil {
			return nil, fmt.Errorf("object class %s: %w", name, err)
		}
		if err := claim(name, cl.OID); err != nil {
			return nil, err
		}
		switch cl.Kind {
		case "structural", "auxiliary", "abstract":
		default:
			return nil, fmt.Errorf("object class %s: invalid kind %q", name, cl.Kind)
		}
		key := strings.ToLower(name)
		r.classes[key] = resolvedClass{name, cl}
		r.ownedClasses = append(r.ownedClasses, key)
	}
	// Validate every definition, including those not selected by a model.
	for _, key := range sortedKeys(r.attrs) {
		if _, err := r.attribute(key, map[string]bool{}); err != nil {
			return nil, err
		}
	}
	for _, key := range sortedKeys(r.classes) {
		if _, _, err := r.members([]string{key}); err != nil {
			return nil, err
		}
	}
	for _, m := range c.Models {
		model, err := r.model(m)
		if err != nil {
			return nil, fmt.Errorf("model %s: %w", m.Name, err)
		}
		r.models = append(r.models, model)
	}
	// Package-level names (including predicates) cannot silently collide across models.
	symbols := map[string]bool{}
	for _, m := range r.models {
		names := []string{m.Name, m.Constructor, m.Name + "Attributes", "Decode" + m.Name, "decode" + m.Name + "Error", "projection" + m.Name}
		for _, f := range m.Predicates {
			names = append(names, f.Name+"Is")
		}
		for _, name := range names {
			key := m.Package + "." + name
			if symbols[key] {
				return nil, fmt.Errorf("duplicate generated symbol %s", key)
			}
			symbols[key] = true
		}
	}
	return r, nil
}

func (r *resolved) attribute(key string, visiting map[string]bool) (resolvedAttribute, error) {
	key = strings.ToLower(key)
	a, ok := r.attrs[key]
	if !ok {
		return a, fmt.Errorf("unknown attribute %q", key)
	}
	if visiting[key] {
		return a, fmt.Errorf("attribute inheritance cycle at %s", a.Name)
	}
	visiting[key] = true
	defer delete(visiting, key)
	if a.Sup != "" {
		parent, err := r.attribute(a.Sup, visiting)
		if err != nil {
			return a, err
		}
		if a.Syntax == "" {
			a.Syntax = parent.Syntax
		}
		if a.SingleValue == nil {
			a.SingleValue = parent.SingleValue
		}
		if parent.SingleValue != nil && *parent.SingleValue && a.SingleValue != nil && !*a.SingleValue {
			return a, fmt.Errorf("attribute %s cannot relax inherited singleValue", a.Name)
		}
		if a.Equality == "" {
			a.Equality = parent.Equality
		}
		if a.Ordering == "" {
			a.Ordering = parent.Ordering
		}
		if a.Substr == "" {
			a.Substr = parent.Substr
		}
	}
	a.Syntax = syntaxFor(a.Syntax).oid
	if _, err := expandOID("", a.Syntax); err != nil {
		return a, fmt.Errorf("attribute %s: invalid syntax %q", a.Name, a.Syntax)
	}
	for _, rule := range []string{a.Equality, a.Ordering, a.Substr} {
		if rule != "" && !ldapName.MatchString(rule) && !numericOID.MatchString(rule) {
			return a, fmt.Errorf("attribute %s: invalid matching rule %q", a.Name, rule)
		}
	}
	return a, nil
}

// members resolves superclass-first order and unions MUST/MAY, with MUST winning.
func (r *resolved) members(roots []string) ([]string, map[string]bool, error) {
	classes, attrs := []string{}, map[string]bool{}
	seen, active := map[string]bool{}, map[string]bool{}
	var walk func(string) error
	walk = func(key string) error {
		key = strings.ToLower(key)
		cl, ok := r.classes[key]
		if !ok {
			return fmt.Errorf("unknown object class %q", key)
		}
		if active[key] {
			return fmt.Errorf("object class inheritance cycle at %s", cl.Name)
		}
		if seen[key] {
			return nil
		}
		active[key] = true
		for _, sup := range cl.Sup {
			if err := walk(sup); err != nil {
				return err
			}
		}
		delete(active, key)
		seen[key] = true
		classes = append(classes, cl.Name)
		declared := map[string]bool{}
		for _, list := range []struct {
			names    []string
			required bool
		}{{cl.Must, true}, {cl.May, false}} {
			for _, name := range list.names {
				a := strings.ToLower(name)
				if _, ok := r.attrs[a]; !ok {
					return fmt.Errorf("object class %s: unknown attribute %q", cl.Name, name)
				}
				if declared[a] {
					return fmt.Errorf("object class %s: duplicate member %s", cl.Name, name)
				}
				declared[a] = true
				attrs[a] = attrs[a] || list.required
			}
		}
		return nil
	}
	for _, root := range roots {
		if err := walk(root); err != nil {
			return nil, nil, err
		}
	}
	return classes, attrs, nil
}

func (r *resolved) model(m Model) (resolvedModel, error) {
	result := resolvedModel{Model: m, UsedImports: map[string]string{}}
	for alias, imported := range m.Imports {
		if !token.IsIdentifier(alias) || alias == "_" || imported == "" || strings.ContainsAny(imported, "\n\r\"\\ ") {
			return result, fmt.Errorf("invalid import %q", alias)
		}
		if alias == "fmt" {
			return result, errors.New("reserved import alias fmt")
		}
	}
	if !token.IsIdentifier(m.Name) || !ast.IsExported(m.Name) {
		return result, errors.New("name must be an exported Go identifier")
	}
	if !token.IsIdentifier(m.Package) || m.Package == "_" || m.Package == "main" {
		return result, errors.New("package must be a non-main Go identifier")
	}
	if m.Constructor == "" {
		result.Constructor = plural(m.Name)
	}
	if !token.IsIdentifier(result.Constructor) || !ast.IsExported(result.Constructor) {
		return result, errors.New("constructor must be an exported Go identifier")
	}
	if result.Scope == "" {
		result.Scope = "children"
	}
	switch result.Scope {
	case "base", "children", "subtree":
	default:
		return result, fmt.Errorf("invalid scope %q", result.Scope)
	}
	if len(m.ObjectClasses) == 0 {
		return result, errors.New("objectClasses is empty")
	}
	classes, members, err := r.members(m.ObjectClasses)
	if err != nil {
		return result, err
	}
	result.Classes = classes
	overrides := map[string]Override{}
	for name, override := range m.Overrides {
		key := strings.ToLower(name)
		if _, ok := members[key]; !ok {
			return result, fmt.Errorf("override references nonmember %q", name)
		}
		if _, ok := overrides[key]; ok {
			return result, fmt.Errorf("duplicate override %q", name)
		}
		overrides[key] = override
	}
	usedNames := map[string]bool{"DN": true}
	for _, key := range sortedKeys(members) {
		if key == "objectclass" {
			continue
		} // Managed by Model, never a mutable descriptor.
		a, err := r.attribute(key, map[string]bool{})
		if err != nil {
			return result, err
		}
		single := a.SingleValue != nil && *a.SingleValue
		o := overrides[key]
		name := exported(strings.TrimPrefix(a.Name, m.AttributePrefix))
		if !single {
			name = plural(name)
		}
		if o.Name != "" {
			name = o.Name
		}
		if !token.IsIdentifier(name) || !ast.IsExported(name) || usedNames[name] {
			return result, fmt.Errorf("invalid or duplicate inferred field %q; set a name override", name)
		}
		usedNames[name] = true
		s := syntaxFor(a.Syntax)
		f := field{LDAP: a.Name, Name: name, Type: s.goType, Codec: s.codec}
		if o.Type != "" && o.Type != f.Type {
			f.Type = o.Type
			f.Codec = typeCodecs[o.Type]
		}
		if o.Codec != "" {
			f.Codec = o.Codec
		}
		if f.Type == "" || f.Codec == "" {
			return result, fmt.Errorf("attribute %s needs an explicit type and codec", a.Name)
		}
		if err := result.expression(f.Type, true); err != nil {
			return result, err
		}
		if err := result.expression(f.Codec, false); err != nil {
			return result, err
		}
		f.Read = "optionalMany"
		if members[key] {
			f.Read = "requiredMany"
		}
		if single {
			f.Read = "optionalOne"
			if members[key] {
				f.Read = "requiredOne"
			}
		}
		if o.Read != "" {
			f.Read = o.Read
		}
		switch f.Read {
		case "requiredOne", "optionalOne", "requiredMany", "optionalMany", "none":
		default:
			return result, fmt.Errorf("attribute %s: invalid read %q", a.Name, f.Read)
		}
		if strings.EqualFold(m.NamingAttribute, a.Name) {
			if f.Type != "string" {
				return result, errors.New("namingAttribute must have Go value type string")
			}
			result.Naming = f.Name
		}
		result.Fields = append(result.Fields, f)
	}
	if result.Naming == "" {
		return result, errors.New("namingAttribute must reference a model attribute")
	}
	indexed := map[string]bool{}
	for _, name := range m.Indexes.Equality {
		key := strings.ToLower(name)
		if indexed[key] {
			return result, fmt.Errorf("duplicate equality index %q", name)
		}
		indexed[key] = true
		found := false
		for _, f := range result.Fields {
			if strings.EqualFold(f.LDAP, name) {
				a, err := r.attribute(key, map[string]bool{})
				if err != nil {
					return result, err
				}
				if a.Equality == "" {
					return result, fmt.Errorf("indexed attribute %s has no equality matching rule", name)
				}
				result.Predicates = append(result.Predicates, f)
				found = true
			}
		}
		if !found {
			return result, fmt.Errorf("equality index references nonmember %q", name)
		}
	}
	if m.Validate != "" {
		if err := result.expression(m.Validate, false); err != nil {
			return result, err
		}
	}
	return result, nil
}

// expression allows type expressions and symbol references, never executable YAML.
func (m *resolvedModel) expression(value string, isType bool) error {
	expr, err := parser.ParseExpr(value)
	if err != nil {
		return fmt.Errorf("invalid Go expression %q", value)
	}
	var walk func(ast.Expr) error
	walk = func(e ast.Expr) error {
		switch e := e.(type) {
		case *ast.Ident:
			if e.Name == "_" {
				return errors.New("blank Go identifier")
			}
			return nil
		case *ast.SelectorExpr:
			alias, ok := e.X.(*ast.Ident)
			if !ok {
				break
			}
			path := map[string]string{"arden": "github.com/wyattanderson/arden", "ldapmodel": "github.com/wyattanderson/arden/ldapmodel", "time": "time"}[alias.Name]
			if custom := m.Imports[alias.Name]; custom != "" {
				if path != "" && path != custom {
					return fmt.Errorf("reserved import alias %s", alias.Name)
				}
				path = custom
			}
			if path == "" || strings.ContainsAny(path, "\n\r\"\\ ") || !ast.IsExported(e.Sel.Name) {
				return fmt.Errorf("invalid or missing import for %q", value)
			}
			m.UsedImports[alias.Name] = path
			return nil
		case *ast.ArrayType:
			if isType && e.Len == nil {
				return walk(e.Elt)
			}
		case *ast.StarExpr:
			if isType {
				return walk(e.X)
			}
		}
		return fmt.Errorf("unsupported Go expression %q: use a type or named symbol", value)
	}
	return walk(expr)
}

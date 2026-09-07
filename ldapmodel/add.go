package ldapmodel

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/wyattanderson/arden"
)

var rdnAttributeName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)

// Assignment contains initial values for one attribute of model M. Construct
// assignments with Set; the zero value is invalid. Encoding errors are retained
// until Add, which checks every assignment before sending a request.
type Assignment[M any] struct {
	wire arden.Attribute
	err  error
}

// Set encodes initial attribute values immediately, retaining codec-produced
// bytes without copying. The caller's outer values slice is not retained.
// Omit an assignment to omit an attribute; zero values are rejected by Add.
func Set[M, T any](attribute Attribute[M, T], values ...T) Assignment[M] {
	wire, err := attribute.encode(values)
	return Assignment[M]{wire: wire, err: err}
}

// Add creates an immediate child of the model's base DN. It encodes name with
// the model's naming attribute, escapes that value for the RDN, and supplies the
// same encoded value as an attribute alongside the model's base object classes.
// Repeated assignments replace earlier values for the same normalized description.
// Assignments cannot override objectClass, including its OID or optioned forms.
// They also cannot assign the naming attribute, including case and option variants.
// Invalid assignments or encoding errors send no request. Schema requiredness and
// cardinality are validated by the server. Add performs no implicit read or retry;
// keep shared value bytes unchanged until it returns.
func (d DAO[M]) Add(name string, attributes ...Assignment[M]) error {
	if len(d.model.classes) == 0 {
		return errors.New("ldapmodel: model has no base object classes")
	}
	naming := d.model.rdn
	if !rdnAttributeName.MatchString(naming.Name()) || strings.EqualFold(naming.Name(), "objectClass") {
		return errors.New("ldapmodel: model has an invalid naming attribute")
	}
	initial, err := naming.encode([]string{name})
	if err != nil {
		return err
	}
	if !utf8.Valid(initial.Values[0]) {
		return errors.New("ldapmodel: naming attribute encoded invalid UTF-8")
	}
	dn := arden.LDAPDN(naming.Name() + "=" + escapeRDNValue(initial.Values[0]))
	if d.model.baseDN != "" {
		dn += "," + d.model.baseDN
	}
	entry := arden.NewEntry(dn)
	entry.Set("objectClass", d.model.classes...)
	entry.Attributes.Set(initial)
	for i, attribute := range attributes {
		if attribute.err != nil {
			return fmt.Errorf("ldapmodel: assignment %d: %w", i, attribute.err)
		}
		if attribute.wire.Type == "" {
			return fmt.Errorf("ldapmodel: assignment %d has no attribute", i)
		}
		name, _, _ := strings.Cut(string(attribute.wire.Type), ";")
		if strings.EqualFold(name, "objectClass") || name == "2.5.4.0" {
			return fmt.Errorf("ldapmodel: assignment %d: objectClass is defined by the model", i)
		}
		if strings.EqualFold(name, naming.Name()) {
			return fmt.Errorf("ldapmodel: assignment %d: naming attribute %q is defined by the model", i, naming.Name())
		}
		if len(attribute.wire.Values) == 0 {
			return fmt.Errorf("ldapmodel: assignment %d: attribute %q has no values", i, attribute.wire.Type)
		}
		entry.Attributes.Set(attribute.wire)
	}
	return d.client.Add(d.ctx, entry)
}

// escapeRDNValue implements RFC 4514 section 2.4 for a UTF-8 attribute value.
// https://www.rfc-editor.org/rfc/rfc4514.html#section-2.4
func escapeRDNValue(value []byte) string {
	const hex = "0123456789abcdef"
	var escaped strings.Builder
	for i, b := range value {
		switch {
		case b < 0x20 || b == 0x7f:
			escaped.WriteByte('\\')
			escaped.WriteByte(hex[b>>4])
			escaped.WriteByte(hex[b&0xf])
		case strings.ContainsRune(`"+,;<>\=`, rune(b)) ||
			(i == 0 && (b == ' ' || b == '#')) || (i == len(value)-1 && b == ' '):
			escaped.WriteByte('\\')
			escaped.WriteByte(b)
		default:
			escaped.WriteByte(b)
		}
	}
	return escaped.String()
}

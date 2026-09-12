package gen

import (
	"strings"
	"unicode"
)

type syntaxInfo struct{ oid, goType, codec string }

var syntaxes = map[string]syntaxInfo{
	"directoryString": {"1.3.6.1.4.1.1466.115.121.1.15", "string", "ldapmodel.DirectoryStringCodec"},
	"ia5String":       {"1.3.6.1.4.1.1466.115.121.1.26", "string", "ldapmodel.IA5StringCodec"},
	"numericString":   {"1.3.6.1.4.1.1466.115.121.1.36", "string", "ldapmodel.NumericStringCodec"},
	"boolean":         {"1.3.6.1.4.1.1466.115.121.1.7", "bool", "ldapmodel.BoolCodec"},
	"integer":         {"1.3.6.1.4.1.1466.115.121.1.27", "int64", "ldapmodel.Int64Codec"},
	"octetString":     {"1.3.6.1.4.1.1466.115.121.1.40", "[]byte", "ldapmodel.BytesCodec"},
	"dn":              {"1.3.6.1.4.1.1466.115.121.1.12", "arden.LDAPDN", "ldapmodel.DNCodec"},
	"generalizedTime": {"1.3.6.1.4.1.1466.115.121.1.24", "time.Time", "ldapmodel.GeneralizedTimeCodec"},
}

var typeCodecs = map[string]string{
	"string": "ldapmodel.StringCodec", "bool": "ldapmodel.BoolCodec",
	"int64": "ldapmodel.Int64Codec", "uint32": "ldapmodel.Uint32Codec", "uint64": "ldapmodel.Uint64Codec",
	"[]byte": "ldapmodel.BytesCodec", "arden.LDAPDN": "ldapmodel.DNCodec", "time.Time": "ldapmodel.GeneralizedTimeCodec",
}

func syntaxFor(value string) syntaxInfo {
	if s, ok := syntaxes[value]; ok {
		return s
	}
	for _, s := range syntaxes {
		if s.oid == value {
			return s
		}
	}
	return syntaxInfo{oid: value}
}

func exported(name string) string {
	runes := []rune(name)
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
	}
	return string(runes)
}

// ponytail: English suffix rules cover schema names; use name overrides for irregular nouns.
func plural(name string) string {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, "y") && len(lower) > 1 && !strings.ContainsRune("aeiou", rune(lower[len(lower)-2])) {
		return name[:len(name)-1] + "ies"
	}
	for _, suffix := range []string{"s", "x", "z", "ch", "sh"} {
		if strings.HasSuffix(lower, suffix) {
			return name + "es"
		}
	}
	return name + "s"
}

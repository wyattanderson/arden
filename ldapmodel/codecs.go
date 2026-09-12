package ldapmodel

import (
	"errors"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wyattanderson/arden"
)

// DirectoryStringCodec validates the nonempty UTF-8 LDAP Directory String syntax.
var DirectoryStringCodec = textCodec(func(s string) bool { return s != "" && utf8.ValidString(s) })

// IA5StringCodec accepts ASCII strings, including the empty string.
var IA5StringCodec = textCodec(func(s string) bool {
	for _, c := range s {
		if c > 127 {
			return false
		}
	}
	return true
})

// NumericStringCodec preserves digits and spaces without numeric conversion.
var NumericStringCodec = textCodec(func(s string) bool {
	for _, c := range s {
		if c != ' ' && (c < '0' || c > '9') {
			return false
		}
	}
	return s != ""
})

func textCodec(valid func(string) bool) ValueCodec[string] {
	decode := func(raw []byte) (string, error) {
		if !valid(string(raw)) {
			return "", errors.New("invalid LDAP string syntax")
		}
		return string(raw), nil
	}
	return Codec[string]{
		EncodeFunc: func(s string) ([]byte, error) {
			if !valid(s) {
				return nil, errors.New("invalid LDAP string syntax")
			}
			return []byte(s), nil
		},
		DecodeFunc: decode,
	}
}

// BoolCodec encodes the LDAP TRUE/FALSE literals; decoding rejects other spellings.
var BoolCodec ValueCodec[bool] = Codec[bool]{
	EncodeFunc: func(v bool) ([]byte, error) {
		if v {
			return []byte("TRUE"), nil
		}
		return []byte("FALSE"), nil
	},
	DecodeFunc: func(raw []byte) (bool, error) {
		switch string(raw) {
		case "TRUE":
			return true, nil
		case "FALSE":
			return false, nil
		}
		return false, errors.New("invalid LDAP boolean")
	},
}

var integerSyntax = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)

// Int64Codec maps LDAP Integer to int64 and rejects syntax errors and overflow.
// LDAP Integer itself is unbounded; use a custom codec for larger integers.
var Int64Codec ValueCodec[int64] = Codec[int64]{
	EncodeFunc: func(v int64) ([]byte, error) { return strconv.AppendInt(nil, v, 10), nil },
	DecodeFunc: func(raw []byte) (int64, error) {
		if !integerSyntax.Match(raw) {
			return 0, errors.New("invalid LDAP integer")
		}
		v, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return 0, errors.New("LDAP integer outside int64 range")
		}
		return v, nil
	},
}

// Uint64Codec maps nonnegative LDAP Integer values to uint64.
var Uint64Codec ValueCodec[uint64] = Codec[uint64]{
	EncodeFunc: func(v uint64) ([]byte, error) { return strconv.AppendUint(nil, v, 10), nil },
	DecodeFunc: func(raw []byte) (uint64, error) {
		if !integerSyntax.Match(raw) {
			return 0, errors.New("invalid LDAP integer")
		}
		v, err := strconv.ParseUint(string(raw), 10, 64)
		if err != nil {
			return 0, errors.New("LDAP integer outside uint64 range")
		}
		return v, nil
	},
}

// DNCodec preserves a UTF-8 textual DN. Full DN syntax and referential validation
// remain server/application responsibilities; it does not normalize DNs.
var DNCodec ValueCodec[arden.LDAPDN] = Codec[arden.LDAPDN]{
	EncodeFunc: func(v arden.LDAPDN) ([]byte, error) {
		if !utf8.ValidString(string(v)) {
			return nil, errors.New("DN is not UTF-8")
		}
		return []byte(v), nil
	},
	DecodeFunc: func(raw []byte) (arden.LDAPDN, error) {
		if !utf8.Valid(raw) {
			return "", errors.New("DN is not UTF-8")
		}
		return arden.LDAPDN(raw), nil
	},
}

var generalizedTimeSyntax = regexp.MustCompile(`^([0-9]{10})([0-9]{2})?([0-9]{2})?([.,][0-9]+)?(Z|[+-][0-9]{2}([0-9]{2})?)$`)

// GeneralizedTimeCodec emits UTC LDAP generalized time and accepts hour/minute/
// second precision, fractions, and numeric UTC offsets. Leap seconds and fractions
// not exactly representable in time.Time's nanoseconds are rejected, never rounded.
var GeneralizedTimeCodec ValueCodec[time.Time] = Codec[time.Time]{
	EncodeFunc: func(v time.Time) ([]byte, error) {
		v = v.UTC()
		if v.Year() < 0 || v.Year() > 9999 {
			return nil, errors.New("generalized time year outside four-digit range")
		}
		return []byte(v.Format("20060102150405.999999999Z")), nil
	},
	DecodeFunc: decodeGeneralizedTime,
}

func decodeGeneralizedTime(raw []byte) (time.Time, error) {
	invalid := errors.New("invalid or unrepresentable LDAP generalized time")
	m := generalizedTimeSyntax.FindStringSubmatch(string(raw))
	if m == nil {
		return time.Time{}, invalid
	}
	date, unit := m[1], time.Hour
	if m[2] == "" {
		date += "00"
	} else {
		date += m[2]
		unit = time.Minute
	}
	if m[3] == "" {
		date += "00"
	} else {
		date += m[3]
		unit = time.Second
	}
	zone := m[5]
	if zone == "Z" {
		zone = "+0000"
	} else if len(zone) == 3 {
		zone += "00"
	}
	if zone[1:3] > "23" || zone[3:5] > "59" {
		return time.Time{}, invalid
	}
	v, err := time.Parse("20060102150405-0700", date+zone)
	if err != nil {
		return time.Time{}, invalid
	}
	if m[4] != "" {
		fraction, ok := new(big.Rat).SetString("0." + strings.TrimLeft(m[4], ".,"))
		if !ok {
			return time.Time{}, invalid
		}
		fraction.Mul(fraction, new(big.Rat).SetInt64(int64(unit)))
		if !fraction.IsInt() || !fraction.Num().IsInt64() {
			return time.Time{}, invalid
		}
		v = v.Add(time.Duration(fraction.Num().Int64()))
	}
	return v.UTC(), nil
}

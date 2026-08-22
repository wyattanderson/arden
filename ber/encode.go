package ber

import "fmt"

// Universal BER identifiers used by the primitive and constructed encoders.
var (
	BooleanIdentifier     = Identifier{Class: ClassUniversal, Number: 1}
	IntegerIdentifier     = Identifier{Class: ClassUniversal, Number: 2}
	OctetStringIdentifier = Identifier{Class: ClassUniversal, Number: 4}
	NullIdentifier        = Identifier{Class: ClassUniversal, Number: 5}
	EnumeratedIdentifier  = Identifier{Class: ClassUniversal, Number: 10}
	SequenceIdentifier    = Identifier{Class: ClassUniversal, Constructed: true, Number: 16}
	SetIdentifier         = Identifier{Class: ClassUniversal, Constructed: true, Number: 17}
)

// AppendElement appends a complete BER element. It is suitable for raw
// application and context-specific values as well as unknown extension fields.
func AppendElement(dst []byte, id Identifier, value []byte) ([]byte, error) {
	start := len(dst)
	var err error
	if dst, err = AppendIdentifier(dst, id, ^uint32(0)); err != nil {
		return dst[:start], err
	}
	if dst, err = AppendLength(dst, len(value)); err != nil {
		return dst[:start], err
	}
	return append(dst, value...), nil
}

// AppendPrimitive appends a primitive BER element.
func AppendPrimitive(dst []byte, id Identifier, value []byte) ([]byte, error) {
	if id.Constructed {
		return dst, fmt.Errorf("%w: %s", ErrPrimitiveRequired, id)
	}
	return AppendElement(dst, id, value)
}

// AppendConstructed appends a constructed BER element. value must already
// contain complete BER child elements.
func AppendConstructed(dst []byte, id Identifier, value []byte) ([]byte, error) {
	if !id.Constructed {
		return dst, fmt.Errorf("%w: %s", ErrConstructedRequired, id)
	}
	return AppendElement(dst, id, value)
}

// AppendBoolean appends the LDAP-required BOOLEAN representation: 00 for
// false and FF for true.
func AppendBoolean(dst []byte, value bool) ([]byte, error) {
	b := byte(0)
	if value {
		b = 0xff
	}
	return AppendPrimitive(dst, BooleanIdentifier, []byte{b})
}

// AppendInteger appends a minimally encoded signed INTEGER.
func AppendInteger(dst []byte, value int64) ([]byte, error) {
	return appendInt(dst, IntegerIdentifier, value)
}

// AppendIntegerWithIdentifier appends a minimally encoded signed INTEGER using
// an implicitly tagged primitive identifier.
func AppendIntegerWithIdentifier(dst []byte, id Identifier, value int64) ([]byte, error) {
	return appendInt(dst, id, value)
}

// AppendEnumerated appends a minimally encoded signed ENUMERATED value.
func AppendEnumerated(dst []byte, value int64) ([]byte, error) {
	return appendInt(dst, EnumeratedIdentifier, value)
}

func appendInt(dst []byte, id Identifier, value int64) ([]byte, error) {
	var raw [8]byte
	for i := len(raw) - 1; i >= 0; i-- {
		raw[i] = byte(value)
		value >>= 8
	}
	start := 0
	for start < len(raw)-1 {
		if raw[start] == 0x00 && raw[start+1]&0x80 == 0 {
			start++
			continue
		}
		if raw[start] == 0xff && raw[start+1]&0x80 != 0 {
			start++
			continue
		}
		break
	}
	return AppendPrimitive(dst, id, raw[start:])
}

// AppendOctetString appends a primitive universal OCTET STRING.
func AppendOctetString(dst []byte, value []byte) ([]byte, error) {
	return AppendPrimitive(dst, OctetStringIdentifier, value)
}

// AppendNull appends a universal NULL.
func AppendNull(dst []byte) ([]byte, error) {
	return AppendPrimitive(dst, NullIdentifier, nil)
}

// AppendSequence appends a universal SEQUENCE containing value.
func AppendSequence(dst []byte, value []byte) ([]byte, error) {
	return AppendConstructed(dst, SequenceIdentifier, value)
}

// AppendSet appends a universal SET containing value.
func AppendSet(dst []byte, value []byte) ([]byte, error) {
	return AppendConstructed(dst, SetIdentifier, value)
}

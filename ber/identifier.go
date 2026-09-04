package ber

import "fmt"

// Class is the two-bit BER identifier class.
type Class uint8

// BER identifier classes.
const (
	ClassUniversal Class = iota
	ClassApplication
	ClassContextSpecific
	ClassPrivate
)

// Identifier is a lossless, comparable BER identifier. Number is deliberately
// wider than LDAP's current application tags so extension values do not need a
// privileged representation.
type Identifier struct {
	Class       Class
	Constructed bool
	Number      uint32
}

// Universal BER identifiers used by the packet encoder and typed reader.
var (
	BooleanIdentifier     = Identifier{Class: ClassUniversal, Number: 1}
	IntegerIdentifier     = Identifier{Class: ClassUniversal, Number: 2}
	OctetStringIdentifier = Identifier{Class: ClassUniversal, Number: 4}
	NullIdentifier        = Identifier{Class: ClassUniversal, Number: 5}
	EnumeratedIdentifier  = Identifier{Class: ClassUniversal, Number: 10}
	SequenceIdentifier    = Identifier{Class: ClassUniversal, Constructed: true, Number: 16}
	SetIdentifier         = Identifier{Class: ClassUniversal, Constructed: true, Number: 17}
)

// Valid reports whether the identifier class can be encoded in BER.
func (id Identifier) Valid() bool {
	return id.Class <= ClassPrivate
}

func (id Identifier) String() string {
	form := "primitive"
	if id.Constructed {
		form = "constructed"
	}
	return fmt.Sprintf("%s/%s/%d", id.Class, form, id.Number)
}

func (c Class) String() string {
	switch c {
	case ClassUniversal:
		return "universal"
	case ClassApplication:
		return "application"
	case ClassContextSpecific:
		return "context-specific"
	case ClassPrivate:
		return "private"
	default:
		return fmt.Sprintf("class(%d)", uint8(c))
	}
}

// Unmarshaler consumes one complete BER value of its expected type from r.
// Implementations must leave their receiver unchanged when they return an
// error. The reader position is unspecified after an error.
type Unmarshaler interface {
	UnmarshalBER(r *Reader) error
}

func appendIdentifier(dst []byte, id Identifier) []byte {
	first := byte(id.Class << 6)
	if id.Constructed {
		first |= 0x20
	}
	if id.Number < 31 {
		return append(dst, first|byte(id.Number))
	}

	first |= 0x1f
	var encoded [5]byte
	n := len(encoded)
	value := id.Number
	for {
		n--
		encoded[n] = byte(value & 0x7f)
		value >>= 7
		if value == 0 {
			break
		}
	}
	for i := n; i < len(encoded)-1; i++ {
		encoded[i] |= 0x80
	}
	return append(append(dst, first), encoded[n:]...)
}

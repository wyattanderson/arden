package ber

import "fmt"

// Class is the two-bit BER identifier class.
type Class uint8

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

// Marshaler appends one complete BER value to dst. Implementations must leave
// dst unchanged when they return an error.
type Marshaler interface {
	AppendBER(dst []byte) ([]byte, error)
}

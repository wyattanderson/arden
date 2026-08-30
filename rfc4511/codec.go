package rfc4511

import (
	"bytes"
	"fmt"

	"github.com/wyattanderson/arden/ber"
)

func contextPrimitive(number uint32) ber.Identifier {
	return ber.Identifier{Class: ber.ClassContextSpecific, Number: number}
}

func contextConstructed(number uint32) ber.Identifier {
	return ber.Identifier{Class: ber.ClassContextSpecific, Constructed: true, Number: number}
}

func applicationPrimitive(number uint32) ber.Identifier {
	return ber.Identifier{Class: ber.ClassApplication, Number: number}
}

func applicationConstructed(number uint32) ber.Identifier {
	return ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: number}
}

// validationLimits only checks a locally produced complete top-level value.
// Wire-size policy belongs to the connection's explicit BER limits, not an RFC
// encoder's self-consistency check.
func validationLimits() ber.Limits {
	limits := ber.DefaultLimits()
	limits.MaxFrameBytes = int(^uint(0) >> 1)
	return limits
}

func appendImplicitOctets[T ~string | ~[]byte](dst []byte, id ber.Identifier, value T) ([]byte, error) {
	return ber.AppendPrimitive(dst, id, []byte(value))
}

func readImplicitOctets(r *ber.Reader, id ber.Identifier) ([]byte, error) {
	value, err := r.Primitive(id)
	if err != nil {
		return nil, err
	}
	return bytes.Clone(value), nil
}

func appendImplicitBoolean(dst []byte, id ber.Identifier, value bool) ([]byte, error) {
	b := byte(0)
	if value {
		b = 0xff
	}
	return ber.AppendPrimitive(dst, id, []byte{b})
}

func readImplicitBoolean(r *ber.Reader, id ber.Identifier) (bool, error) {
	value, err := r.Primitive(id)
	if err != nil {
		return false, err
	}
	if len(value) != 1 || (value[0] != 0 && value[0] != 0xff) {
		return false, fmt.Errorf("arden: invalid implicit BOOLEAN %s", id)
	}
	return value[0] == 0xff, nil
}

func appendResultResponse(dst []byte, id ber.Identifier, result LDAPResult) ([]byte, error) {
	start := len(dst)
	contents, err := result.appendContents(nil)
	if err != nil {
		return dst[:start], err
	}
	encoded, err := ber.AppendConstructed(dst, id, contents)
	if err != nil {
		return dst[:start], err
	}
	return encoded, nil
}

func decodeResultResponse(r *ber.Reader, id ber.Identifier) (LDAPResult, error) {
	contents, err := r.Constructed(id)
	if err != nil {
		return LDAPResult{}, err
	}
	return decodeLDAPResultContents(contents)
}

func requireNonEmpty[T ~string | ~[]byte](name string, value T) error {
	if len(value) == 0 {
		return fmt.Errorf("arden: %s is empty", name)
	}
	return nil
}

func cloneAttributeValues[T ~[]byte](values []T) []AttributeValue {
	cloned := make([]AttributeValue, len(values))
	for i := range values {
		cloned[i] = bytes.Clone(values[i])
	}
	return cloned
}

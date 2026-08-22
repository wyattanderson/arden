package ber

import (
	"errors"
	"fmt"
)

// Sentinel errors classify BER parsing and encoding failures.
var (
	ErrTruncated            = errors.New("ber: truncated value")
	ErrInvalidIdentifier    = errors.New("ber: invalid identifier")
	ErrInvalidLength        = errors.New("ber: invalid length")
	ErrIndefiniteLength     = errors.New("ber: indefinite length is not allowed")
	ErrLengthOverflow       = errors.New("ber: length overflows int")
	ErrTrailingData         = errors.New("ber: trailing data")
	ErrUnexpectedIdentifier = errors.New("ber: unexpected identifier")
	ErrPrimitiveRequired    = errors.New("ber: primitive value required")
	ErrConstructedRequired  = errors.New("ber: constructed value required")
	ErrInvalidBoolean       = errors.New("ber: invalid boolean")
	ErrInvalidInteger       = errors.New("ber: invalid integer")
	ErrInvalidNull          = errors.New("ber: invalid null")
)

// DecodeError identifies the byte offset at which a BER decode failed. Offset
// is relative to the complete byte slice or framed message passed to a reader.
type DecodeError struct {
	Offset int
	Err    error
}

func (e *DecodeError) Error() string {
	if e == nil {
		return "ber: <nil decode error>"
	}
	return fmt.Sprintf("ber: decode at byte %d: %v", e.Offset, e.Err)
}

func (e *DecodeError) Unwrap() error { return e.Err }

// LimitError reports a configured BER resource limit. It deliberately does
// not include any decoded value bytes.
type LimitError struct {
	Limit string
	Value uint64
	Max   uint64
}

func (e *LimitError) Error() string {
	if e == nil {
		return "ber: <nil limit error>"
	}
	return fmt.Sprintf("ber: resource limit %q exceeded: %d > %d", e.Limit, e.Value, e.Max)
}

func decodeError(offset int, err error) error {
	var existing *DecodeError
	if errors.As(err, &existing) {
		return err
	}
	return &DecodeError{Offset: offset, Err: err}
}

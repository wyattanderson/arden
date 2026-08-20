package ber

import (
	"bytes"
	"fmt"
	"math"
)

// Element is a view of one complete BER element. Value and Raw alias the
// caller-owned input passed to NewReader; use Clone when the bytes must outlive
// that input.
type Element struct {
	Identifier Identifier
	Value      []byte
	Raw        []byte
	Offset     int
}

// Clone returns an owned copy of the complete element.
func (e Element) Clone() []byte { return bytes.Clone(e.Raw) }

type readerState struct {
	elements int
}

// Reader is a bounded cursor over one BER value or its contents. It has no I/O
// and never allocates based on a length received from the input.
type Reader struct {
	data   []byte
	pos    int
	base   int
	depth  int
	limits Limits
	state  *readerState
}

// NewReader constructs a top-level reader over data. data is caller-owned and
// must remain unchanged while returned slices are in use.
func NewReader(data []byte, limits Limits) (*Reader, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if len(data) > limits.MaxFrameBytes {
		return nil, &LimitError{Limit: "frame bytes", Value: uint64(len(data)), Max: uint64(limits.MaxFrameBytes)}
	}
	return &Reader{data: data, limits: limits, state: new(readerState)}, nil
}

// Offset is the absolute offset of the next unread byte.
func (r *Reader) Offset() int { return r.base + r.pos }

// Remaining returns the unread byte count in this reader's bounded region.
func (r *Reader) Remaining() int { return len(r.data) - r.pos }

// Empty reports whether all bytes in this reader's bounded region were read.
func (r *Reader) Empty() bool { return r.Remaining() == 0 }

// RequireEmpty rejects unread bytes. Typed decoders should call it when a type
// requires complete consumption; extensible SEQUENCE codecs can instead
// preserve or explicitly skip trailing elements.
func (r *Reader) RequireEmpty() error {
	if !r.Empty() {
		return decodeError(r.Offset(), ErrTrailingData)
	}
	return nil
}

// PeekIdentifier returns the identifier of the next element without advancing
// the reader. It is useful for ASN.1 OPTIONAL fields and extensible trailing
// components, where a decoder must decide whether it recognizes the next
// element before consuming it.
func (r *Reader) PeekIdentifier() (Identifier, error) {
	id, _, err := decodeIdentifier(r.data[r.pos:], r.limits.MaxTagNumber)
	if err != nil {
		return Identifier{}, decodeError(r.Offset(), err)
	}
	return id, nil
}

// ReadElement reads one complete BER element and advances only after its
// identifier, length, and bounded value have all been validated.
func (r *Reader) ReadElement() (Element, error) {
	start := r.pos
	absolute := r.base + start
	id, idBytes, err := decodeIdentifier(r.data[start:], r.limits.MaxTagNumber)
	if err != nil {
		return Element{}, decodeError(absolute, err)
	}
	length, lengthBytes, err := decodeLength(r.data[start+idBytes:])
	if err != nil {
		return Element{}, decodeError(absolute+idBytes, err)
	}
	header := idBytes + lengthBytes
	if length > len(r.data)-start-header {
		return Element{}, decodeError(absolute+header, ErrTruncated)
	}
	end := start + header + length
	if r.state.elements == r.limits.MaxElements {
		return Element{}, decodeError(absolute, &LimitError{Limit: "elements", Value: uint64(r.state.elements + 1), Max: uint64(r.limits.MaxElements)})
	}
	r.state.elements++
	e := Element{
		Identifier: id,
		Value:      r.data[start+header : end],
		Raw:        r.data[start:end],
		Offset:     absolute,
	}
	r.pos = end
	return e, nil
}

// SkipElement reads one complete element and validates all nested BER
// elements without interpreting their schema. It is intended for an allowed
// unknown extension field that a typed decoder needs to preserve. The returned
// element remains a view of the reader's caller-owned input.
func (r *Reader) SkipElement() (Element, error) {
	e, err := r.ReadElement()
	if err != nil {
		return Element{}, err
	}
	if err := r.validateContents(e); err != nil {
		return Element{}, err
	}
	return e, nil
}

func (r *Reader) validateContents(e Element) error {
	if !e.Identifier.Constructed {
		return nil
	}
	if r.depth == r.limits.MaxDepth {
		return decodeError(e.Offset, &LimitError{Limit: "depth", Value: uint64(r.depth + 1), Max: uint64(r.limits.MaxDepth)})
	}
	child := Reader{
		data:   e.Value,
		base:   e.Offset + len(e.Raw) - len(e.Value),
		depth:  r.depth + 1,
		limits: r.limits,
		state:  r.state,
	}
	for !child.Empty() {
		nested, err := child.ReadElement()
		if err != nil {
			return err
		}
		if err := child.validateContents(nested); err != nil {
			return err
		}
	}
	return nil
}

// Primitive reads the next primitive element with id. The returned value is a
// view of caller-owned bytes. The reader advances only on success.
func (r *Reader) Primitive(id Identifier) ([]byte, error) {
	start := r.pos
	elements := r.state.elements
	e, err := r.ReadElement()
	if err != nil {
		return nil, err
	}
	if e.Identifier != id {
		r.pos = start
		r.state.elements = elements
		if e.Identifier.Class == id.Class && e.Identifier.Number == id.Number && e.Identifier.Constructed {
			return nil, decodeError(e.Offset, fmt.Errorf("%w: %s", ErrPrimitiveRequired, id))
		}
		return nil, decodeError(e.Offset, fmt.Errorf("%w: got %s, want %s", ErrUnexpectedIdentifier, e.Identifier, id))
	}
	if e.Identifier.Constructed {
		r.pos = start
		r.state.elements = elements
		return nil, decodeError(e.Offset, fmt.Errorf("%w: %s", ErrPrimitiveRequired, id))
	}
	return e.Value, nil
}

// Constructed enters the next constructed element with id. The parent is
// advanced past the child before the child reader is returned.
func (r *Reader) Constructed(id Identifier) (*Reader, error) {
	start := r.pos
	elements := r.state.elements
	e, err := r.ReadElement()
	if err != nil {
		return nil, err
	}
	if e.Identifier != id {
		r.pos = start
		r.state.elements = elements
		if e.Identifier.Class == id.Class && e.Identifier.Number == id.Number && !e.Identifier.Constructed {
			return nil, decodeError(e.Offset, fmt.Errorf("%w: %s", ErrConstructedRequired, id))
		}
		return nil, decodeError(e.Offset, fmt.Errorf("%w: got %s, want %s", ErrUnexpectedIdentifier, e.Identifier, id))
	}
	if !e.Identifier.Constructed {
		r.pos = start
		r.state.elements = elements
		return nil, decodeError(e.Offset, fmt.Errorf("%w: %s", ErrConstructedRequired, id))
	}
	if r.depth == r.limits.MaxDepth {
		r.pos = start
		r.state.elements = elements
		return nil, decodeError(e.Offset, &LimitError{Limit: "depth", Value: uint64(r.depth + 1), Max: uint64(r.limits.MaxDepth)})
	}
	return &Reader{
		data:   e.Value,
		base:   e.Offset + len(e.Raw) - len(e.Value),
		depth:  r.depth + 1,
		limits: r.limits,
		state:  r.state,
	}, nil
}

// Boolean reads an LDAP BOOLEAN. RFC 4511 requires true to be encoded as FF.
func (r *Reader) Boolean() (bool, error) {
	start, elements := r.pos, r.state.elements
	value, err := r.Primitive(BooleanIdentifier)
	if err != nil {
		return false, err
	}
	if len(value) != 1 || (value[0] != 0 && value[0] != 0xff) {
		r.pos, r.state.elements = start, elements
		return false, decodeError(r.base+start, ErrInvalidBoolean)
	}
	return value[0] == 0xff, nil
}

// Integer reads a signed BER INTEGER that fits in int64 and the configured
// integer-size limit.
func (r *Reader) Integer() (int64, error) { return r.integer(IntegerIdentifier) }

// IntegerWithIdentifier reads a signed BER INTEGER that has an implicit
// primitive identifier, such as an LDAP application-tagged MessageID.
func (r *Reader) IntegerWithIdentifier(id Identifier) (int64, error) {
	return r.integer(id)
}

// Enumerated reads a signed BER ENUMERATED value.
func (r *Reader) Enumerated() (int64, error) { return r.integer(EnumeratedIdentifier) }

func (r *Reader) integer(id Identifier) (int64, error) {
	start, elements := r.pos, r.state.elements
	value, err := r.Primitive(id)
	if err != nil {
		return 0, err
	}
	if len(value) == 0 {
		r.pos, r.state.elements = start, elements
		return 0, decodeError(r.base+start, ErrInvalidInteger)
	}
	if len(value) > r.limits.MaxIntegerBytes {
		r.pos, r.state.elements = start, elements
		return 0, decodeError(r.base+start, &LimitError{Limit: "integer bytes", Value: uint64(len(value)), Max: uint64(r.limits.MaxIntegerBytes)})
	}
	if len(value) > 8 {
		r.pos, r.state.elements = start, elements
		return 0, decodeError(r.base+start, ErrInvalidInteger)
	}
	var result int64
	for _, b := range value {
		result = result<<8 | int64(b)
	}
	if value[0]&0x80 != 0 && len(value) < 8 {
		result |= -1 << (uint(len(value)) * 8)
	}
	return result, nil
}

// OctetString reads a primitive universal OCTET STRING. Constructed OCTET
// STRING is forbidden by RFC 4511 and therefore rejected.
func (r *Reader) OctetString() ([]byte, error) { return r.Primitive(OctetStringIdentifier) }

// Null reads a universal NULL with empty contents.
func (r *Reader) Null() error {
	start, elements := r.pos, r.state.elements
	value, err := r.Primitive(NullIdentifier)
	if err != nil {
		return err
	}
	if len(value) != 0 {
		r.pos, r.state.elements = start, elements
		return decodeError(r.base+start, ErrInvalidNull)
	}
	return nil
}

// Sequence enters a universal SEQUENCE.
func (r *Reader) Sequence() (*Reader, error) { return r.Constructed(SequenceIdentifier) }

// Set enters a universal SET.
func (r *Reader) Set() (*Reader, error) { return r.Constructed(SetIdentifier) }

// DecodeElement decodes exactly one complete element from data.
func DecodeElement(data []byte, limits Limits) (Element, error) {
	r, err := NewReader(data, limits)
	if err != nil {
		return Element{}, err
	}
	e, err := r.ReadElement()
	if err != nil {
		return Element{}, err
	}
	if err := r.RequireEmpty(); err != nil {
		return Element{}, err
	}
	return e, nil
}

func decodeIdentifier(data []byte, max uint32) (Identifier, int, error) {
	if len(data) == 0 {
		return Identifier{}, 0, ErrTruncated
	}
	first := data[0]
	id := Identifier{Class: Class(first >> 6), Constructed: first&0x20 != 0, Number: uint32(first & 0x1f)}
	if id.Number != 0x1f {
		return id, 1, nil
	}
	if len(data) == 1 {
		return Identifier{}, 0, ErrTruncated
	}
	var number uint64
	for i := 1; ; i++ {
		if i == len(data) {
			return Identifier{}, 0, ErrTruncated
		}
		b := data[i]
		if i == 1 && b&0x7f == 0 {
			return Identifier{}, 0, ErrInvalidIdentifier
		}
		if number > math.MaxUint32>>7 {
			return Identifier{}, 0, ErrInvalidIdentifier
		}
		number = number<<7 | uint64(b&0x7f)
		if number > uint64(max) {
			return Identifier{}, 0, &LimitError{Limit: "tag number", Value: number, Max: uint64(max)}
		}
		if b&0x80 == 0 {
			if number < 31 {
				return Identifier{}, 0, ErrInvalidIdentifier
			}
			id.Number = uint32(number)
			return id, i + 1, nil
		}
	}
}

func decodeLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, ErrTruncated
	}
	first := data[0]
	if first&0x80 == 0 {
		return int(first), 1, nil
	}
	n := int(first & 0x7f)
	if n == 0 {
		return 0, 0, ErrIndefiniteLength
	}
	if n > len(data)-1 {
		return 0, 0, ErrTruncated
	}
	if n > 8 || (n > 1 && data[1] == 0) {
		return 0, 0, ErrInvalidLength
	}
	var value uint64
	for _, b := range data[1 : n+1] {
		if value > math.MaxInt>>8 {
			return 0, 0, ErrLengthOverflow
		}
		value = value<<8 | uint64(b)
	}
	if value < 128 {
		return 0, 0, ErrInvalidLength
	}
	if value > uint64(math.MaxInt) {
		return 0, 0, ErrLengthOverflow
	}
	return int(value), n + 1, nil
}

package ber

import (
	"bufio"
	"errors"
	"io"
)

// Framer incrementally acquires complete, owned top-level BER elements from an
// io.Reader. It accepts arbitrary underlying read boundaries and is separate
// from schema decoding.
type Framer struct {
	r      *bufio.Reader
	limits Limits
}

// NewFramer constructs a BER framer with explicit resource limits.
func NewFramer(r io.Reader, limits Limits) (*Framer, error) {
	if r == nil {
		return nil, errors.New("ber: nil frame reader")
	}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	return &Framer{r: bufio.NewReader(r), limits: limits}, nil
}

// Next returns one complete BER element in an owned byte slice. Framing errors
// carry offsets relative to the prospective frame; I/O errors are returned
// unchanged so callers can distinguish transport failure from malformed BER.
func (f *Framer) Next() ([]byte, error) {
	var header []byte
	// Preserve EOF before a prospective frame as a transport condition. Once a
	// frame has begun, EOF is a malformed/truncated BER value instead.
	first, err := f.r.ReadByte()
	if err != nil {
		return nil, err
	}
	header = append(header, first)

	if first&0x1f == 0x1f {
		for {
			b, err := f.readByte(len(header))
			if err != nil {
				return nil, err
			}
			header = append(header, b)
			if b&0x80 == 0 {
				break
			}
			if len(header) == 6 {
				return nil, decodeError(0, ErrInvalidIdentifier)
			}
		}
	}
	if _, _, err := decodeIdentifier(header, f.limits.MaxTagNumber); err != nil {
		return nil, decodeError(0, err)
	}

	firstLength, err := f.readByte(len(header))
	if err != nil {
		return nil, err
	}
	header = append(header, firstLength)
	if firstLength&0x80 != 0 {
		n := int(firstLength & 0x7f)
		if n == 0 {
			return nil, decodeError(len(header)-1, ErrIndefiniteLength)
		}
		for range n {
			b, err := f.readByte(len(header))
			if err != nil {
				return nil, err
			}
			header = append(header, b)
		}
	}
	length, _, err := decodeLength(header[len(header)-(1+lengthByteCount(firstLength)):])
	if err != nil {
		return nil, decodeError(len(header)-(1+lengthByteCount(firstLength)), err)
	}
	if len(header)+length > f.limits.MaxFrameBytes {
		return nil, decodeError(len(header), &LimitError{Limit: "frame bytes", Value: uint64(len(header) + length), Max: uint64(f.limits.MaxFrameBytes)})
	}

	frame := make([]byte, len(header)+length)
	copy(frame, header)
	if _, err := io.ReadFull(f.r, frame[len(header):]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, decodeError(len(header), ErrTruncated)
		}
		return nil, err
	}
	return frame, nil
}

func (f *Framer) readByte(offset int) (byte, error) {
	b, err := f.r.ReadByte()
	if err == nil {
		return b, nil
	}
	if err == io.EOF {
		return 0, decodeError(offset, ErrTruncated)
	}
	return 0, err
}

func lengthByteCount(first byte) int {
	if first&0x80 == 0 {
		return 0
	}
	return int(first & 0x7f)
}

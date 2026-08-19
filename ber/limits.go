package ber

import (
	"fmt"
	"math"
)

// Limits bounds BER decoding and framing work. Every field must be positive;
// a zero value never means unbounded.
type Limits struct {
	MaxFrameBytes   int
	MaxDepth        int
	MaxElements     int
	MaxIntegerBytes int
	MaxTagNumber    uint32
}

// DefaultLimits are deliberately conservative for LDAP messages while leaving
// room for ordinary search responses and extension payloads.
func DefaultLimits() Limits {
	return Limits{
		MaxFrameBytes:   16 << 20,
		MaxDepth:        32,
		MaxElements:     100_000,
		MaxIntegerBytes: 8,
		MaxTagNumber:    math.MaxUint32,
	}
}

// Validate checks that all bounds are explicit and usable.
func (l Limits) Validate() error {
	switch {
	case l.MaxFrameBytes <= 0:
		return fmt.Errorf("ber: MaxFrameBytes must be positive")
	case l.MaxDepth <= 0:
		return fmt.Errorf("ber: MaxDepth must be positive")
	case l.MaxElements <= 0:
		return fmt.Errorf("ber: MaxElements must be positive")
	case l.MaxIntegerBytes <= 0:
		return fmt.Errorf("ber: MaxIntegerBytes must be positive")
	case l.MaxTagNumber == 0:
		return fmt.Errorf("ber: MaxTagNumber must be positive")
	}
	return nil
}

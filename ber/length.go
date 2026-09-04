package ber

import "math/bits"

// AppendLength appends a definite BER length in shortest form.
func AppendLength(dst []byte, length int) ([]byte, error) {
	if length < 0 {
		return dst, ErrInvalidLength
	}
	return appendLength(dst, length), nil
}

func appendLength(dst []byte, length int) []byte {
	if length < 128 {
		return append(dst, byte(length))
	}
	n := (bits.Len(uint(length)) + 7) / 8
	dst = append(dst, 0x80|byte(n))
	for shift := (n - 1) * 8; shift >= 0; shift -= 8 {
		dst = append(dst, byte(uint(length)>>shift))
	}
	return dst
}

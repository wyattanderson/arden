package ldapmodel

import (
	"fmt"
	"strconv"
)

// Uint32Codec encodes uint32 values as decimal LDAP bytes and rejects decoded
// values outside the uint32 range. It is an application mapping, not a general
// representation of LDAP's unbounded Integer syntax. Encoding cannot fail.
var Uint32Codec ValueCodec[uint32] = Codec[uint32]{
	EncodeFunc: func(value uint32) ([]byte, error) {
		return strconv.AppendUint(nil, uint64(value), 10), nil
	},
	DecodeFunc: func(value []byte) (uint32, error) {
		decoded, err := strconv.ParseUint(string(value), 10, 32)
		if err != nil {
			return 0, fmt.Errorf("decode unsigned 32-bit integer: %w", err)
		}
		return uint32(decoded), nil
	},
}

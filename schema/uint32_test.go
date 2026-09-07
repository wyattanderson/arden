package schema

import (
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUint32Codec(t *testing.T) {
	for _, value := range []uint32{0, 1200, 1<<32 - 1} {
		encoded, err := Uint32Codec.Encode(value)
		require.NoError(t, err)
		assert.Equal(t, strconv.FormatUint(uint64(value), 10), string(encoded))
		decoded, err := Uint32Codec.Decode(encoded)
		require.NoError(t, err)
		assert.Equal(t, value, decoded)
	}
	for _, raw := range []string{"", "-1", "4294967296", "1.5", "abc"} {
		_, err := Uint32Codec.Decode([]byte(raw))
		require.ErrorContains(t, err, "decode unsigned 32-bit integer")
		var numberError *strconv.NumError
		assert.True(t, errors.As(err, &numberError))
	}
}

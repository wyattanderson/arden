package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestControlOptionalFieldSemantics(t *testing.T) {
	tests := []struct {
		name string
		in   Control
	}{
		{"defaults omitted", Control{Type: LDAPOID("1.2.3")}},
		{"critical", Control{Type: LDAPOID("1.2.3"), Criticality: true}},
		{"present empty value", Control{Type: LDAPOID("1.2.3"), HasValue: true, Value: []byte{}}},
		{"binary value", Control{Type: LDAPOID("1.2.3"), HasValue: true, Value: []byte{0x00, 0xff}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := test.in.AppendBER(nil)
			require.NoError(t, err)
			var got Control
			decode(t, encoded, &got)
			assert.Equal(t, test.in, got)
		})
	}

	encoded, err := (Control{Type: LDAPOID("1.2.3")}).AppendBER(nil)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x07, 0x04, 0x05, '1', '.', '2', '.', '3'}, encoded)
}

func TestControlValidationAndFieldOrdering(t *testing.T) {
	for _, control := range []Control{
		{},
		{Type: LDAPOID("1")},
		{Type: LDAPOID("1..2")},
	} {
		dst := []byte{0xde, 0xad}
		got, err := control.AppendBER(dst)
		require.Error(t, err)
		assert.Equal(t, dst, got)
	}

	malformed := [][]byte{
		// Duplicate criticality.
		{0x30, 0x0d, 0x04, 0x05, '1', '.', '2', '.', '3', 0x01, 0x01, 0xff, 0x01, 0x01, 0x00},
		// Duplicate value.
		{0x30, 0x0b, 0x04, 0x05, '1', '.', '2', '.', '3', 0x04, 0x00, 0x04, 0x00},
		// Criticality after the value.
		{0x30, 0x0e, 0x04, 0x05, '1', '.', '2', '.', '3', 0x04, 0x01, 'x', 0x01, 0x01, 0xff},
	}
	for _, encoded := range malformed {
		prior := Control{Type: LDAPOID("9.9"), Criticality: true}
		requireDecodeError(t, encoded, &prior)
		assert.Equal(t, LDAPOID("9.9"), prior.Type)
	}
}

func TestControlPreservesExtensionAndCopiesValue(t *testing.T) {
	encoded := []byte{0x30, 0x0d, 0x04, 0x05, '1', '.', '2', '.', '3', 0x04, 0x02, 0x00, 0xff, 0x85, 0x00}
	var control Control
	decode(t, encoded, &control)
	assert.True(t, control.HasValue)
	assert.Equal(t, []byte{0x00, 0xff}, control.Value)
	require.Len(t, control.Extensions, 1)
	assert.Equal(t, ber.Identifier{Class: ber.ClassContextSpecific, Number: 5}, control.Extensions[0].Identifier())

	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, []byte{0x00, 0xff}, control.Value)
	assert.Equal(t, []byte{0x85, 0x00}, control.Extensions[0].Bytes())
}

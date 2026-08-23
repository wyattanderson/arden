package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestAttributeAndPartialAttributeCardinality(t *testing.T) {
	partial := PartialAttribute{Type: AttributeDescription("description")}
	encoded, err := partial.AppendBER(nil)
	require.NoError(t, err)
	var partialGot PartialAttribute
	decode(t, encoded, &partialGot)
	assert.Equal(t, partial, partialGot)

	for _, value := range []ber.Marshaler{
		PartialAttribute{},
		Attribute{Type: AttributeDescription("cn")},
		Attribute{Values: []AttributeValue{AttributeValue("Jane")}},
	} {
		dst := []byte{0xde, 0xad}
		got, err := value.AppendBER(dst)
		require.Error(t, err)
		assert.Equal(t, dst, got)
	}
}

func TestAttributeCopiesBinaryValuesAndPreservesExtension(t *testing.T) {
	contents, err := ber.AppendOctetString(nil, []byte("jpegPhoto"))
	require.NoError(t, err)
	values, err := ber.AppendOctetString(nil, []byte{0x00, 0xff})
	require.NoError(t, err)
	contents, err = ber.AppendSet(contents, values)
	require.NoError(t, err)
	contents, err = ber.AppendPrimitive(contents, ber.Identifier{Class: ber.ClassContextSpecific, Number: 5}, []byte{0x7f})
	require.NoError(t, err)
	encoded, err := ber.AppendSequence(nil, contents)
	require.NoError(t, err)

	var attribute Attribute
	decode(t, encoded, &attribute)
	assert.Equal(t, AttributeValue{0x00, 0xff}, attribute.Values[0])
	require.Len(t, attribute.Extensions, 1)
	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, AttributeValue{0x00, 0xff}, attribute.Values[0])
	assert.Equal(t, []byte{0x85, 0x01, 0x7f}, attribute.Extensions[0].Bytes())
}

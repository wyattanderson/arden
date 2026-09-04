package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestAttributeAndPartialAttributeCardinality(t *testing.T) {
	partial := PartialAttribute{Type: AttributeDescription("description")}
	encoded := partial.BERPacket().Encode()
	var partialGot PartialAttribute
	decode(t, encoded, &partialGot)
	assert.Equal(t, partial, partialGot)

	for _, value := range []interface {
		ber.Packeter
		ber.Unmarshaler
	}{
		&PartialAttribute{},
		&Attribute{Type: AttributeDescription("cn")},
		&Attribute{Values: []AttributeValue{AttributeValue("Jane")}},
	} {
		requireDecodeError(t, value.BERPacket().Encode(), value)
	}
}

func TestAttributeCopiesBinaryValuesAndPreservesExtension(t *testing.T) {
	encoded := ber.Sequence().
		Add(ber.OctetString("jpegPhoto")).
		Add(ber.Set().Add(ber.OctetString([]byte{0x00, 0xff}))).
		Add(ber.Primitive(ber.Identifier{Class: ber.ClassContextSpecific, Number: 5}, []byte{0x7f})).
		BERPacket().Encode()

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

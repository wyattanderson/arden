package rfc4511

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestAttributeAllowsEmptyValues(t *testing.T) {
	attribute := Attribute{Type: AttributeDescription("description")}
	encoded := attribute.BERPacket().Encode()
	var got Attribute
	decode(t, encoded, &got)
	assert.Equal(t, attribute, got)
}

func TestAttributeRejectsEmptyTypeAtomically(t *testing.T) {
	for _, value := range []Attribute{
		{},
		{Values: []AttributeValue{AttributeValue("Jane")}},
	} {
		prior := Attribute{Type: "keep", Values: []AttributeValue{AttributeValue("keep")}}
		requireDecodeError(t, value.BERPacket().Encode(), &prior)
		assert.Equal(t, Attribute{Type: "keep", Values: []AttributeValue{AttributeValue("keep")}}, prior)
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

package rfc4511

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestAttributeKeyEquivalence(t *testing.T) {
	for _, names := range [][]AttributeDescription{
		{"homeDirectory", "HoMeDiReCtOrY", "homedirectory"},
		{"cn;lang-en;lang-de", "CN;LANG-DE;LANG-EN", "cn;lang-de;lang-en;LANG-DE"},
		{"2.5.4.3;BINARY", "2.5.4.3;binary"},
	} {
		for _, name := range names {
			assert.Equal(t, names[0].Key(), name.Key())
		}
	}
	assert.NotEqual(t, AttributeDescription("cn").Key(), AttributeDescription("cn;lang-en").Key())
	assert.NotEqual(t, AttributeDescription("cn").Key(), AttributeDescription("2.5.4.3").Key())
	assert.NotEqual(t, AttributeDescription("cn").Key(), AttributeDescription("commonName").Key())
}

func TestAttributesLookupSetDeleteAndOrder(t *testing.T) {
	var attributes Attributes
	assert.Zero(t, attributes.Len())
	_, ok := attributes.Lookup("absent")
	assert.False(t, ok)
	assert.Empty(t, slices.Collect(attributes.All()))
	assert.False(t, attributes.Delete("absent"))
	attributes.Set(Attribute{Type: "cn"})
	attributes.Set(Attribute{Type: "homeDirectory", Values: []AttributeValue{[]byte("/home/alice")}})
	attributes.Set(Attribute{Type: "cn;lang-en;lang-de"})
	empty, ok := attributes.Lookup("CN")
	require.True(t, ok)
	assert.Empty(t, empty.Values)
	attributes.Set(Attribute{Type: "HOMEDIRECTORY", Values: []AttributeValue{[]byte("/srv/alice")}})
	attributes.Set(Attribute{Type: "CN;LANG-DE;LANG-EN", Values: []AttributeValue{[]byte("Alice")}})
	assert.Equal(t, 3, attributes.Len())
	all := slices.Collect(attributes.All())
	assert.Equal(t, AttributeDescription("HOMEDIRECTORY"), all[1].Type)
	assert.Equal(t, "/srv/alice", string(all[1].Values[0]))
	assert.True(t, attributes.Delete("HoMeDiReCtOrY"))
	assert.False(t, attributes.Delete("homedirectory"))
	attribute, ok := attributes.Lookup("cn;lang-en;lang-de")
	require.True(t, ok)
	assert.Equal(t, "Alice", string(attribute.Values[0]))
	assert.Equal(t, AttributeDescription("CN;LANG-DE;LANG-EN"), slices.Collect(attributes.All())[1].Type)
	visited := 0
	for range attributes.All() {
		visited++
		break
	}
	assert.Equal(t, 1, visited)
}

func TestAttributesCopiesStayCoherentAndCloneDetaches(t *testing.T) {
	input := []Attribute{{Type: "cn", Values: []AttributeValue{[]byte("Alice")}}}
	attributes := NewAttributes(input...)
	input[0].Type = "changed"
	shared := attributes
	clone := attributes.Clone()
	for i := range 32 {
		shared.Set(Attribute{Type: AttributeDescription(fmt.Sprintf("extra%d", i))})
	}
	assert.Equal(t, 33, attributes.Len())
	assert.Equal(t, 1, clone.Len())
	assert.True(t, shared.Delete("extra0"))
	assert.Equal(t, 32, attributes.Len())
	value, ok := attributes.Lookup("CN")
	require.True(t, ok)
	value.Type = "renamed"
	value.Values[0][0] = 'a'
	value.Values = append(value.Values, []byte("uncommitted"))
	stored, ok := shared.Lookup("cn")
	require.True(t, ok)
	assert.Equal(t, AttributeDescription("cn"), stored.Type)
	assert.Len(t, stored.Values, 1)
	assert.Equal(t, "alice", string(stored.Values[0]))
	copyValue, ok := clone.Lookup("cn")
	require.True(t, ok)
	assert.Equal(t, "Alice", string(copyValue.Values[0]))
	clone.Set(Attribute{Type: "CN"})
	assert.Len(t, stored.Values, 1)
	var empty Attributes
	assert.Zero(t, empty.Clone().Len())
	empty.Set(Attribute{Type: "cn"})
	empty.Delete("cn")
	assert.Zero(t, empty.Clone().Len())
}

func TestAttributesDecodeOwnsBytesAndPreservesWireDetails(t *testing.T) {
	// One attribute with an unknown trailing component and noncanonical options.
	attributePacket := ber.Sequence().Add(
		ber.OctetString("CN;lang-en;LANG-DE"),
		ber.Set().Add(ber.OctetString("Alice")).BERPacket(),
		ber.Primitive(contextPrimitive(9), []byte{7}),
	).BERPacket()
	encoded := ber.Sequence().Add(attributePacket).BERPacket().Encode()
	var attributes Attributes
	decode(t, encoded, &attributes)
	assert.Equal(t, encoded, attributes.BERPacket().Encode())
	clear(encoded)
	attribute, ok := attributes.Lookup("cn;lang-de;lang-en")
	require.True(t, ok)
	assert.Equal(t, "Alice", string(attribute.Values[0]))
	require.Len(t, attribute.Extensions, 1)
	clone := attributes.Clone()
	attribute.Values[0][0] = 'a'
	attribute.Extensions[0] = UnknownField{}
	cloned, ok := clone.LookupKey(AttributeDescription("CN;LANG-DE;LANG-EN").Key())
	require.True(t, ok)
	assert.Equal(t, "Alice", string(cloned.Values[0]))
	assert.Equal(t, []byte{0x89, 0x01, 0x07}, cloned.Extensions[0].Bytes())
}

func TestAttributesRejectDuplicateDescriptionsAtomically(t *testing.T) {
	for _, names := range [][2]AttributeDescription{
		{"cn", "CN"},
		{"cn;lang-en;lang-de", "CN;LANG-DE;LANG-EN"},
		{"cn;lang-en", "cn;lang-en;LANG-EN"},
	} {
		encoded := ber.Sequence().Add(Attribute{Type: names[0]}, Attribute{Type: names[1]}).BERPacket().Encode()
		prior := NewAttributes(Attribute{Type: "keep"})
		shared := prior
		requireDecodeError(t, encoded, &prior)
		assert.Equal(t, []Attribute{{Type: "keep"}}, slices.Collect(shared.All()))
		assert.Equal(t, shared, prior)
	}
}

func TestAttributesEncodingObservesSharedValues(t *testing.T) {
	values := []AttributeValue{[]byte("Alice")}
	attributes := NewAttributes(Attribute{Type: "cn", Values: values})
	before := attributes.BERPacket().Encode()
	values[0][0] = 'a'
	after := attributes.BERPacket().Encode()
	assert.NotEqual(t, before, after)
	var decoded Attributes
	decode(t, after, &decoded)
	value, ok := decoded.Lookup("CN")
	require.True(t, ok)
	assert.Equal(t, "alice", string(value.Values[0]))
}

var benchmarkAttribute Attribute

func BenchmarkAttributesLookupKey(b *testing.B) {
	attributes := NewAttributes(Attribute{Type: "homeDirectory", Values: []AttributeValue{[]byte("/home/alice")}})
	key := AttributeDescription("HoMeDiReCtOrY").Key()
	b.ReportAllocs()
	for b.Loop() {
		benchmarkAttribute, _ = attributes.LookupKey(key)
	}
}

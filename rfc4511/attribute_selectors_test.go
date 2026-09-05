package rfc4511

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden/ber"
)

func TestAttributeSelectorsEncodingAndOwnership(t *testing.T) {
	for _, values := range [][]AttributeSelector{
		nil, {}, {"cn", "*", "+", "1.1", "cn", "cn;lang-en"},
		{AttributeSelector(strings.Repeat("a", 128)), "sn"},
	} {
		want := ber.Sequence().Add(values...).BERPacket().Encode()
		selectors := NewAttributeSelectors(values)
		assert.Equal(t, len(values), selectors.Len())
		assert.Equal(t, want, selectors.BERPacket().Encode())
		copyOfSelectors := selectors
		if len(values) > 0 {
			values[0] = "changed"
			slices.Collect(selectors.All())[0] = "also changed"
		}
		assert.Equal(t, want, copyOfSelectors.BERPacket().Encode())

		var decoded AttributeSelectors
		decode(t, want, &decoded)
		assert.Equal(t, slices.Collect(selectors.All()), slices.Collect(decoded.All()))
		assert.Equal(t, selectors, decoded)
		clear(want)
		assert.Equal(t, selectors.BERPacket().Encode(), decoded.BERPacket().Encode())
		packet := selectors.BERPacket()
		decode(t, []byte{0x30, 0x00}, &selectors)
		assert.Zero(t, selectors.Len())
		assert.Equal(t, copyOfSelectors.BERPacket().Encode(), packet.Encode())
	}
}

func TestAttributeSelectorsRejectMalformedSequenceAtomically(t *testing.T) {
	for _, encoded := range [][]byte{
		{0x04, 0x00},                   // wrong outer tag
		{0x30, 0x03, 0x02, 0x01, 0x01}, // non-string selector
		{0x30, 0x03, 0x04, 0x01, 0xff}, // invalid UTF-8
		{0x30, 0x03, 0x04, 0x02, 'a'},  // truncated selector
	} {
		prior := NewAttributeSelectors([]string{"keep"})
		got := prior
		requireDecodeError(t, encoded, &got)
		assert.Equal(t, prior, got)
	}
}

func TestAttributeSelectorsReuseDoesNotAllocate(t *testing.T) {
	for _, selectors := range []AttributeSelectors{{}, NewAttributeSelectors([]string{"cn", "sn", "*", "+"})} {
		want := selectors.BERPacket().Encode()
		dst := make([]byte, 0, len(want))
		allocations := testing.AllocsPerRun(100, func() {
			dst = selectors.BERPacket().AppendTo(dst[:0])
		})
		require.Equal(t, want, dst)
		assert.Zero(t, allocations)
	}
}

func BenchmarkAttributeSelectors(b *testing.B) {
	values := []AttributeSelector{"uid", "cn", "sn", "mail", "objectClass", "uidNumber", "gidNumber", "homeDirectory", "loginShell"}
	selectors := NewAttributeSelectors(values)
	dst := make([]byte, 0, len(selectors.BERPacket().Encode()))
	b.Run("rebuild", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dst = ber.Sequence().Add(values...).BERPacket().AppendTo(dst[:0])
		}
	})
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			dst = selectors.BERPacket().AppendTo(dst[:0])
		}
	})
}

package ldapmodel

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestNewModelRetainsAttributeSelection(t *testing.T) {
	attributes := []string{"uid", "cn"}
	model := NewModel("dc=example", arden.ScopeSubtree, arden.Has("uid"), arden.NewAttributeSelectors(attributes...),
		func(entry arden.Entry) (arden.Entry, error) { return entry, nil })
	attributes[0] = "changed"
	assert.Equal(t, []rfc4511.AttributeSelector{"uid", "cn"}, slices.Collect(model.attributes.All()))

	selection := model.attributes
	packet := selection.BERPacket()
	assert.Equal(t, arden.NewAttributeSelectors("uid", "cn").BERPacket().Encode(), packet.Encode())
}

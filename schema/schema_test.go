package schema

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/rfc4511"
)

func TestTypedAttributeRoundTripAndFilter(t *testing.T) {
	uid := NewAttribute("uid", StringCodec)
	entry := arden.NewEntry("uid=alice,dc=example")
	require.NoError(t, uid.Set(entry, "alice"))

	values, err := uid.Values(*entry)
	require.NoError(t, err)
	assert.Equal(t, []string{"alice"}, values)

	filter, err := uid.Equal("alice")
	require.NoError(t, err)
	assert.IsType(t, rfc4511.EqualityMatch{}, filter)
}

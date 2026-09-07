package ldapmodel

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/schema"
)

func TestReplacementIntentAndCopying(t *testing.T) {
	attribute := schema.NewAttribute("mail", schema.StringCodec)
	prior := []arden.Change{arden.Replace("cn", "Alice")}
	var replacement Replacement[string]
	changes, err := replacement.AppendChanges(prior, schema.Attribute[string]{})
	require.NoError(t, err)
	assert.Equal(t, prior, changes)

	values := []string{"alice@example.test", "other@example.test"}
	replacement.Set(values...)
	values[0] = "changed"
	copied := replacement
	replacement.Set("latest@example.test")
	changes, err = copied.AppendChanges(prior, attribute)
	require.NoError(t, err)
	assert.Equal(t, []arden.Change{prior[0], arden.Replace("mail", "alice@example.test", "other@example.test")}, changes)
	changes, err = replacement.AppendChanges(nil, attribute)
	require.NoError(t, err)
	assert.Equal(t, []arden.Change{arden.Replace("mail", "latest@example.test")}, changes)

	replacement.Clear()
	changes, err = replacement.AppendChanges(nil, attribute)
	require.NoError(t, err)
	assert.Equal(t, []arden.Change{arden.Replace("mail")}, changes)
	replacement.Set()
	empty, err := replacement.AppendChanges(nil, attribute)
	require.NoError(t, err)
	assert.Equal(t, changes, empty)

	replacement.Set("")
	changes, err = replacement.AppendChanges(nil, attribute)
	require.NoError(t, err)
	assert.Equal(t, []arden.Change{arden.Replace("mail", "")}, changes)
}

func TestReplacementEncodingFailureIsAtomic(t *testing.T) {
	encodeError := errors.New("cannot encode")
	attribute := schema.NewAttribute("custom", schema.Codec[string]{EncodeFunc: func(value string) ([]byte, error) {
		if value == "bad" {
			return nil, encodeError
		}
		return []byte(value), nil
	}})
	prior := make([]arden.Change, 1, 2)
	prior[0] = arden.Replace("cn", "Alice")
	var replacement Replacement[string]
	replacement.Set("ok", "bad")
	changes, err := replacement.AppendChanges(prior, attribute)
	require.ErrorIs(t, err, encodeError)
	assert.ErrorContains(t, err, "encode replacement for custom value 1")
	assert.Nil(t, changes)
	assert.Equal(t, arden.Replace("cn", "Alice"), prior[0])
	assert.Equal(t, arden.Change{}, prior[:cap(prior)][1])

	_, err = replacement.AppendChanges(prior, schema.NewAttribute[string]("missing", nil))
	require.ErrorContains(t, err, `attribute "missing" has no codec`)
}

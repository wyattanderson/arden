package ldapmodel

import (
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/schema"
)

func TestSingleValueDecodeChecksCardinalityBeforeCallingCodec(t *testing.T) {
	calls := 0
	codecError := errors.New("bad integer")
	attribute := schema.NewAttribute("uidNumber", schema.Codec[int]{DecodeFunc: func(raw []byte) (int, error) {
		calls++
		value, err := strconv.Atoi(string(raw))
		if err != nil {
			return 0, codecError
		}
		return value, nil
	}})
	entry := arden.NewEntry("uid=alice")
	_, err := RequiredOne(attribute, *entry)
	require.ErrorContains(t, err, "has 0 values")
	optional, err := OptionalOne(attribute, *entry)
	require.NoError(t, err)
	assert.Nil(t, optional)
	entry.Set("UIDNUMBER", "bad", "also bad")
	_, err = RequiredOne(attribute, *entry)
	require.ErrorContains(t, err, "has 2 values")
	_, err = OptionalOne(attribute, *entry)
	require.ErrorContains(t, err, "has 2 values")
	assert.Zero(t, calls)
	entry.Set("UidNumber", "1001")
	value, err := RequiredOne(attribute, *entry)
	require.NoError(t, err)
	assert.Equal(t, 1001, value)
	optional, err = OptionalOne(attribute, *entry)
	require.NoError(t, err)
	require.NotNil(t, optional)
	assert.Equal(t, 1001, *optional)
	assert.Equal(t, 2, calls)
	entry.Set("uidNumber", "bad")
	_, err = RequiredOne(attribute, *entry)
	require.ErrorIs(t, err, codecError)
	require.ErrorContains(t, err, "decode uidNumber value 0")
}

package ber_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/wyattanderson/arden/ber"
)

func TestIdentifierValidityAndString(t *testing.T) {
	id := ber.Identifier{Class: ber.ClassApplication, Constructed: true, Number: 25}
	assert.True(t, id.Valid())
	assert.Equal(t, "application/constructed/25", id.String())
	assert.False(t, (ber.Identifier{Class: 4}).Valid())
}

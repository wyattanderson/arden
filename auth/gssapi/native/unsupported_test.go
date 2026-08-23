//go:build gssapi && (!cgo || (!linux && !darwin && !freebsd && !openbsd))

package native

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewReportsUnavailable(t *testing.T) {
	authentication, err := New("identity")
	assert.Nil(t, authentication)
	assert.ErrorIs(t, err, ErrUnavailable)
}

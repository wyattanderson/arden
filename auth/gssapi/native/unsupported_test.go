//go:build gssapi && (!cgo || (!linux && !darwin && !freebsd && !openbsd))

package native

import (
	"errors"
	"testing"
)

func TestNewReportsUnavailable(t *testing.T) {
	authentication, err := New("identity")
	if authentication != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("New = %#v, %v; want nil, ErrUnavailable", authentication, err)
	}
}

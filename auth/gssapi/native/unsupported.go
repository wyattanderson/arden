//go:build gssapi && (!cgo || (!linux && !darwin && !freebsd && !openbsd))

package native

import mechanism "github.com/wyattanderson/arden/auth/gssapi"

// New reports ErrUnavailable when cgo is disabled or the platform has no
// supported go-gssapi-c binding.
func New(string, ...mechanism.Option) (*mechanism.Authentication, error) {
	return nil, ErrUnavailable
}

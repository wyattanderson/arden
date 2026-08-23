//go:build gssapi && cgo && (linux || darwin || freebsd || openbsd)

package native

import (
	// Register the native C GSSAPI provider with go-gssapi.
	_ "github.com/golang-auth/go-gssapi-c"
	gogssapi "github.com/golang-auth/go-gssapi/v3"

	mechanism "github.com/wyattanderson/arden/auth/gssapi"
)

// ProviderName is the registry name used by go-gssapi-c.
const ProviderName = "github.com/golang-auth/go-gssapi-c"

// New constructs TLS-only native GSSAPI authentication. Each connection gets
// a separately owned provider and uses the platform's default initiator
// credentials, allowing ordinary credential-cache and gssproxy selection.
func New(stableID string, options ...mechanism.Option) (*mechanism.Authentication, error) {
	return mechanism.NewWithProviderFactory(stableID, func() (gogssapi.Provider, error) {
		return gogssapi.NewProvider(ProviderName)
	}, options...)
}

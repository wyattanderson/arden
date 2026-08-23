//go:build gssapi

// Package native connects Arden's RFC 4752 mechanism to the platform GSSAPI
// implementation through github.com/golang-auth/go-gssapi-c.
package native

import "errors"

// ErrUnavailable reports that the native provider is unavailable in the
// selected build.
var ErrUnavailable = errors.New("arden/auth/gssapi/native: native GSSAPI is unavailable")

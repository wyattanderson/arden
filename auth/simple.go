package auth

import (
	"bytes"
	"context"
	"errors"

	"github.com/wyattanderson/arden"
)

// SimpleBind configures an LDAPv3 Simple Bind. The constructor copies the
// caller-owned byte values so replacement connections can authenticate
// independently. Per-connection copies are erased when their authenticator is
// closed. Neither credentials nor bindDN enter the endpoint profile or errors.
type SimpleBind struct {
	identity    arden.Identity
	bindDN      []byte
	credentials []byte
}

// NewSimpleBind constructs a TLS-only Simple Bind configuration. stableID is
// nonsecret caller vocabulary used to partition endpoint profiles and pools;
// it must not be a DN, password, token, or credential-derived value.
func NewSimpleBind(stableID string, bindDN, credentials []byte) (*SimpleBind, error) {
	identity := arden.Identity{StableID: stableID}
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	if len(bindDN) == 0 {
		return nil, errors.New("arden/auth: Simple Bind DN is empty; use Anonymous for anonymous authentication")
	}
	if len(credentials) == 0 {
		return nil, errors.New("arden/auth: Simple Bind credentials are empty")
	}
	return &SimpleBind{
		identity:    identity,
		bindDN:      bytes.Clone(bindDN),
		credentials: bytes.Clone(credentials),
	}, nil
}

// NewSimple is a short alias for NewSimpleBind.
func NewSimple(stableID string, bindDN, credentials []byte) (*SimpleBind, error) {
	return NewSimpleBind(stableID, bindDN, credentials)
}

// ValidateEndpoint rejects plaintext before Dialer opens a socket.
func (a *SimpleBind) ValidateEndpoint(endpoint arden.Endpoint) error {
	if a == nil {
		return errors.New("arden/auth: nil Simple Bind configuration")
	}
	if endpoint.Transport != arden.TransportDirectTLS {
		return errors.New("arden/auth: Simple Bind requires direct TLS")
	}
	return nil
}

// Begin prepares a single Simple Bind operation for endpoint.
func (a *SimpleBind) Begin(ctx context.Context, endpoint arden.Endpoint) (arden.Authenticator, error) {
	if ctx == nil {
		return nil, errors.New("arden/auth: nil authentication context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := a.ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	return &bindAuthenticator{
		identity:    a.identity,
		name:        bytes.Clone(a.bindDN),
		credentials: bytes.Clone(a.credentials),
	}, nil
}

var (
	_ arden.Authentication                  = (*SimpleBind)(nil)
	_ arden.AuthenticationEndpointValidator = (*SimpleBind)(nil)
)

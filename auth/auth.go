// Package auth provides cgo-free LDAP connection authentication mechanisms.
// Mechanisms operate only through arden.InitializationSession and never gain
// access to the transport or connection runtime.
package auth

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/wyattanderson/arden"
	"github.com/wyattanderson/arden/ber"
	"github.com/wyattanderson/arden/rfc4511"
)

const anonymousStableID = "anonymous"

// BindError reports only the LDAP result code. The server diagnostic,
// matched DN, credentials, and response controls are deliberately omitted from
// Error so routine setup logging cannot disclose them.
type BindError struct {
	ResultCode rfc4511.ResultCode
}

func (e *BindError) Error() string {
	if e == nil {
		return "arden/auth: <nil Bind error>"
	}
	return fmt.Sprintf("arden/auth: Bind failed with LDAP result code %d", e.ResultCode)
}

// Anonymous performs the RFC 4513 anonymous authentication Bind: LDAPv3, an
// empty name, and an empty simple authentication value. Its zero value is
// ready to use and is permitted on an explicitly selected plaintext endpoint.
type Anonymous struct{}

// Begin prepares a single anonymous Bind operation for endpoint.
func (Anonymous) Begin(ctx context.Context, _ arden.Endpoint) (arden.Authenticator, error) {
	if ctx == nil {
		return nil, errors.New("arden/auth: nil authentication context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &bindAuthenticator{identity: arden.Identity{StableID: anonymousStableID}}, nil
}

type bindAuthenticator struct {
	identity    arden.Identity
	name        []byte
	credentials []byte
	used        bool
	closed      bool
}

func (a *bindAuthenticator) Authenticate(ctx context.Context, session arden.InitializationSession) (arden.Identity, error) {
	if ctx == nil {
		return arden.Identity{}, errors.New("arden/auth: nil authentication context")
	}
	if session == nil {
		return arden.Identity{}, errors.New("arden/auth: nil initialization session")
	}
	if a.closed {
		return arden.Identity{}, errors.New("arden/auth: authenticator is closed")
	}
	if a.used {
		return arden.Identity{}, errors.New("arden/auth: authenticator was already used")
	}
	a.used = true

	request := &rfc4511.BindRequest{
		Version:        3,
		Name:           rfc4511.LDAPDN(a.name),
		Authentication: rfc4511.SimpleAuthentication(a.credentials),
	}
	operation, err := rfc4511.NewBindOperation(request, nil)
	if err != nil {
		return arden.Identity{}, err
	}
	stream, err := session.Do(ctx, operation)
	if err != nil {
		return arden.Identity{}, err
	}
	response, err := stream.Next(ctx)
	if err != nil {
		return arden.Identity{}, err
	}

	var bindResponse rfc4511.BindResponse
	if err := response.UnmarshalProtocol(&bindResponse, ber.DefaultLimits()); err != nil {
		return arden.Identity{}, err
	}
	if bindResponse.Result.ResultCode != rfc4511.ResultSuccess {
		return arden.Identity{}, &BindError{ResultCode: bindResponse.Result.ResultCode}
	}
	// A Bind response pattern is terminal. This read verifies that an unusual
	// session implementation does not append a second response.
	if _, err := stream.Next(ctx); !errors.Is(err, io.EOF) {
		if err == nil {
			return arden.Identity{}, errors.New("arden/auth: Bind returned more than one response")
		}
		return arden.Identity{}, err
	}
	return a.identity, nil
}

func (a *bindAuthenticator) Close() error {
	if a == nil || a.closed {
		return nil
	}
	a.closed = true
	clear(a.name)
	clear(a.credentials)
	a.name = nil
	a.credentials = nil
	return nil
}

var (
	_ arden.Authentication = Anonymous{}
	_ arden.Authenticator  = (*bindAuthenticator)(nil)
)

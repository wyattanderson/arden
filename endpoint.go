package arden

import (
	"context"
	"errors"
)

// EndpointID is a caller-supplied stable identity, distinct from a network
// address. The empty value is invalid.
type EndpointID string

func (id EndpointID) Validate() error {
	if id == "" {
		return errors.New("arden: endpoint ID is empty")
	}
	return nil
}

// TransportMode fixes the transport used for an endpoint at construction
// time. The zero value is verified direct TLS so an omitted mode can never
// silently select plaintext.
type TransportMode uint8

const (
	TransportDirectTLS TransportMode = iota
	TransportPlaintext
)

// Endpoint contains immutable setup facts needed before dialing.
type Endpoint struct {
	ID         EndpointID
	Address    string
	ServerName string
	Transport  TransportMode
}

func (e Endpoint) Validate() error {
	if err := e.ID.Validate(); err != nil {
		return err
	}
	if e.Address == "" {
		return errors.New("arden: endpoint address is empty")
	}
	if e.Transport != TransportDirectTLS && e.Transport != TransportPlaintext {
		return errors.New("arden: endpoint transport mode is invalid")
	}
	if e.Transport == TransportDirectTLS && e.ServerName == "" {
		return errors.New("arden: endpoint TLS server name is empty")
	}
	return nil
}

// Identity is stable, nonsecret authentication metadata. StableID partitions
// profiles and pools; it must never contain credentials or mechanism tokens.
type Identity struct {
	StableID string
}

// InitializationSession provides exclusive, ordinary binary LDAP operations
// during authentication and setup. Implementations own message IDs and do not
// permit the session to escape initialization.
type InitializationSession interface {
	Do(context.Context, Operation) (ResponseStream, error)
}

// Authentication creates per-connection authentication conversations.
// A nil Authentication means no Bind is performed.
type Authentication interface {
	Begin(context.Context, Endpoint) (Authenticator, error)
}

// Authenticator owns one authentication conversation. Close releases all
// mechanism resources and is called on both success and failure.
type Authenticator interface {
	Authenticate(context.Context, InitializationSession) (Identity, error)
	Close() error
}

// CancellationPolicy is the endpoint-wide policy frozen after setup.
type CancellationPolicy uint8

const (
	CancellationConservative CancellationPolicy = iota + 1
	CancellationRFC3909
)

// ConnectionPolicy contains only setup results understood by the core.
type ConnectionPolicy struct {
	Cancellation CancellationPolicy
}

// Initializer discovers a typed, endpoint- and identity-scoped profile after
// authentication. The returned profile and policy are frozen by the pool.
type Initializer[P any] interface {
	Initialize(context.Context, InitializationSession) (P, ConnectionPolicy, error)
}

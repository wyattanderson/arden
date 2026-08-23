// Package gssapi implements the RFC 4752 GSSAPI SASL authentication
// conversation without selecting a native GSS provider.
//
// Applications normally construct this mechanism through the optional
// auth/gssapi/native package. NewWithProviderFactory is exposed for provider
// adapters and tests. The implementation requests Kerberos V5, integrity for
// the security-layer negotiation, and mutual authentication. It always selects
// the RFC 4752 no-security-layer option because the LDAP connection is already
// protected by verified direct TLS.
//
// Context cancellation is checked between provider calls and LDAP Bind rounds.
// A call inside the platform GSS implementation may not itself be interruptible.
package gssapi

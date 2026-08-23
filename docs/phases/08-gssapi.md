# Phase 8: optional native GSSAPI

## Implementation status

Implemented while Phase 7 is temporarily deferred:

- `auth/gssapi` implements the RFC 4752 exchange against an injected
  `github.com/golang-auth/go-gssapi/v3` provider. Unit tests use fake GSS
  handles and scripted LDAP Bind responses, including binary and empty tokens,
  cancellation between rounds, server rejection, handle cleanup, typed errors,
  and authentication-only security-layer selection.
- `auth/gssapi/native`, enabled by the `gssapi` build tag, registers
  `github.com/golang-auth/go-gssapi-c` and uses platform default credentials.
- `cmd/arden-gssapi-smoke` performs a verified LDAPS GSSAPI Bind, requires a
  non-empty authorization identity from RFC 4532 `Who Am I?`, and performs a
  read-only root DSE Search against a caller-supplied FreeIPA endpoint.
- Platform, gssproxy, and troubleshooting documentation is in
  [`docs/gssapi.md`](../gssapi.md).

FreeIPA execution remains an external smoke check. A containerized FreeIPA
environment is intentionally deferred until after that check.

Accepted upstream limitation: `go-gssapi` retains typed standardized GSS
status information and provider diagnostics, but `go-gssapi-c` does not expose
the raw mechanism-specific minor value after formatting it. Arden's safe typed
error exposes the reconstructable major status and wrapped provider cause; a
raw minor field is not provided.

## Goal

Add Kerberos identity proof through the SASL `GSSAPI` mechanism without
changing application operations, connection routing, or the cgo-free core.

This phase starts only after the base RFC 4511 release is stable.

## Scope

- Optional native package using the platform GSSAPI implementation.
- MIT Kerberos and Heimdal where available; macOS support evaluated separately.
- Credential-cache and gssproxy-friendly acquisition through native defaults.
- LDAP service principal naming and mutual authentication.
- RFC 4752 SASL token exchange through the existing authentication session.
- Authentication-only negotiation over direct TLS (LDAPS): select no SASL
  security layer. Explicitly configured plaintext endpoints are rejected.

Do not manage keytab contents, run `kinit`, renew tickets, or implement a
Kerberos protocol stack. Explicit credential handles may be supported when the
native API makes that safe, but the default path should let GSSAPI/gssproxy
choose credentials.

## Architecture requirements

- Core packages never import cgo or native bindings.
- Build tags isolate unavailable platforms cleanly.
- GSS handles are owned, concurrency-safe, and released exactly once.
- Context cancellation is checked between native calls; document that a native
  call itself may not be interruptible.
- Major and minor GSS status values remain available through typed errors while
  default messages avoid secrets.
- GSS tokens are never logged or traced.
- Authentication result metadata is sufficient to partition pools without
  exposing credentials.
- Application and RFC protocol packages cannot tell whether GSSAPI,
  ordinary Bind, or another future mechanism authenticated the connection.

Explicitly reject negotiation of integrity or confidentiality SASL data layers
in this implementation. Supporting wrapped LDAP PDUs would change framing and
buffer semantics and requires a separate design.

## Research before implementation

- RFC 4422, RFC 4752, RFC 2743/2744, and RFC 4121.
- Current 389 DS GSSAPI Bind implementation and tests.
- FreeIPA deployment behavior, DNS canonicalization, and `ldap/FQDN` service
  principals.
- MIT, Heimdal, and gssproxy acquisition/delegation behavior.
- OpenLDAP's GSSAPI client sequence as an interoperability reference.

Resolve native-library differences in the optional package rather than leaking
them into the authentication interface.

## Testing

- A fake SASL mechanism first, proving the core handles all token sequences.
- Successful and failed native authentication against FreeIPA/389 DS.
- Credential cache selection and gssproxy operation without keytab handling by
  the application.
- Expired/missing credentials and unavailable native library.
- Wrong service principal, hostname mismatch, clock skew, and server rejection.
- Context cancellation between rounds and connection loss mid-negotiation.
- Pool creation and replacement connections under one identity.
- Verification that the no-security-layer selection is sent and SASL-wrapped
  LDAP data is never enabled.

## Deliverables

- Optional native GSSAPI package and platform build documentation.
- Integration environment and troubleshooting guide.
- Typed GSS errors with safe formatting.
- gssproxy-oriented example configuration that contains no secret material.
- Compatibility notes for supported native implementations.

## Exit criteria

FreeIPA can authenticate the client through native Kerberos; the same
application operations work unchanged under ordinary Bind and GSSAPI; builds
that do not import the optional package remain cgo-free.

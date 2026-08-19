# Phase 5: authentication and setup

## Goal

Add a cgo-free connection-initialization seam so authentication and optional
capability discovery happen before a connection becomes generally usable.

## Connection state model

Use explicit internal states:

```text
dialing -> TLS -> authenticating -> initializing -> ready -> draining -> closed
```

Bind and other association-changing operations are exclusive to initialization.
Application operations cannot observe or use a partially initialized
connection.

## Authentication contract

Authentication is optional and pluggable. The contract must:

- Accept a context.
- Use a narrow initialization session that owns LDAP Bind framing and message
  IDs.
- Permit ordinary Bind mechanisms without forcing string conversion.
- Permit multi-round SASL mechanisms using opaque token bytes.
- Return stable, nonsecret identity metadata for pool partitioning and traces.
- Own and release mechanism-specific resources.
- Leave the connection in exactly one state: authenticated and ready to
  initialize, or unusable and closed.

Protocol and application code must not know which authentication mechanism was
used. Authentication configuration belongs to dialing/pool construction, not
individual operations.

Implement anonymous and Simple Bind as the initial cgo-free mechanisms. Simple
Bind accepts caller-owned byte credentials, uses them only during connection
initialization, and does not retain them in the endpoint profile. Do not build
GSSAPI here. Never log credentials, Bind values, or SASL tokens.

## Higher-layer initializer

After authentication, an optional initializer may execute ordinary binary
operations through the initialization session. It returns:

- A typed endpoint profile owned by the higher layer.
- A small core policy containing only behavior the core understands.

An eventual capability package can perform a root DSE query and set an RFC 3909
cancellation policy. The LDAP core does not learn how to construct a generic
search to accomplish this.

Initialization policy is frozen for the pool's lifetime. It is scoped by exact
endpoint and authentication identity. If capability freshness matters, the
application rebuilds or explicitly refreshes the pool.

## Requirements

- Initializers cannot publish a connection or retain the initialization
  session.
- A failed initializer closes the connection.
- Initialization has a bounded context and operation budget.
- A profile cannot weaken TLS verification after the handshake.
- Replacement connections either reuse an explicitly frozen profile or run a
  lightweight validation chosen by the pool builder.
- Capability mismatches produce a clear setup error rather than silently
  changing pool behavior.

## Testing

- No authentication, a minimal ordinary Bind, failed Bind, and multi-step mock
  SASL conversations.
- Context cancellation between every authentication round trip.
- Authentication failure never reaches the ready pool.
- Initializer success, failure, timeout, and capability mismatch.
- Two endpoints advertising different capabilities.
- Same endpoint under two identities producing distinct profiles and pools.
- Redaction tests for errors, logs, and trace attributes.

Review RFC 4513, 389 DS Bind handling, OpenLDAP SASL sequencing, and go-ldap's
Bind behavior whenever state transitions are uncertain. Prefer a packet-level
test over adding a broad authentication abstraction.

## Deliverables

- Authentication and initialization contracts.
- Explicit connection state transitions.
- Anonymous and Simple Bind implementations for integration testing and
  ordinary non-Kerberos use.
- Endpoint profile/policy handoff.
- Examples showing that application operations are authentication-agnostic.

## Exit criteria

Connections become visible only after TLS, authentication, and initialization
succeed; ordinary Bind remains possible; native mechanisms can be added later
without changing request or application APIs.

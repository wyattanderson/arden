# Project plan

## Objective

Build a small, modern Go foundation for binary LDAPv3 operations against 389
Directory Server and FreeIPA. The first usable milestone ends with a tested RFC
4511 wire layer, concurrent LDAP connections with direct TLS preferred, a
multiplex-aware pool, and the extension points required for handwritten LDAP
extensions and generated application/schema protocols.

GSSAPI is necessary for the eventual deployment, but it is deliberately after
the pure LDAP foundation. Early designs must preserve its integration seam
without allowing native authentication concerns to dominate the core.

## Working principles

- Keep the core cgo-free and dependency-light.
- Prefer data and small interfaces over frameworks and registries.
- Preserve bytes at the wire boundary.
- Make concurrency, cancellation, ownership, and failure semantics explicit.
- Hand-author the small, stable RFC 4511 wire layer; reserve code generation
  for application/schema APIs where it removes meaningful repetition.
- Use an immutable setup profile for facts discovered before a pool starts.
- Treat each configured server as a distinct endpoint with a stable identity.
- Optimize only after packet-level correctness and interoperability.
- When behavior is unclear, inspect specifications and existing implementations
  before inventing a new interpretation.

## Proposed package boundaries

Names are provisional; responsibilities are not.

| Package | Responsibility |
| --- | --- |
| `ber` | Bounded LDAP BER identifiers, lengths, readers, and append encoders |
| `rfc4511` | Hand-authored RFC 4511 values, filters, results, tags, constants, codecs, and standard operation helpers |
| root package | LDAP dialing with direct TLS by default, message envelopes, operations, routing, lifecycle |
| `pool` | Endpoint-aware multiplexed connections, leases, and shutdown |
| `auth` | Authentication and connection-initialization contracts |
| `otelldap` | Optional OpenTelemetry adapter |
| `auth/gssapi` | Late optional native GSSAPI mechanism |

Avoid splitting packages until a dependency boundary or build constraint makes
the split useful.

## Core operation contract

An operation consists of an encoded protocol operation, optional controls, a
declarative response pattern, cancellation policy, and safe observability
metadata.

A response pattern declares:

- Tags that are valid and nonterminal.
- Tags that are valid and terminal.
- Whether the request intentionally has no response.

Classification returns `continue`, `complete`, or `invalid`. It uses only the
protocol-operation identifier. The classifier does not decode result codes or
payloads. Payload-dependent classification is deferred until a real supported
extension requires it.

Tag-only classification is sufficient for RFC 4511 and the expected extension
style: controls and result values change an operation's meaning, but terminal
framing is still expressed by SearchResultDone, ExtendedResponse, or another
declared protocol-operation tag. Persistent and synchronization searches may
remain open for a long time; they do not require inspecting an entry to decide
that the eventual SearchResultDone is terminal. Payload semantics belong to the
typed consumer after routing.

This contract is used even after the consumer cancels: the connection can
discard responses until the terminal tag arrives and then safely reuse the
message ID. If an Abandon may have succeeded, RFC 4511 suppresses that terminal
response; the target message ID remains tombstoned until the connection closes.
An invalid tag is a connection-level protocol failure.

## Setup-time discovery and immutable profiles

Some higher-level behavior may be learned using the core before a pool becomes
available. Examples include server capabilities, supported controls and
extensions, vendor/version information, and eventual RFC 3909 Cancel support.

The setup model will be:

1. Dial and authenticate a connection to each configured endpoint.
2. Run an optional higher-layer initializer using ordinary binary operations.
3. Produce a typed endpoint profile and core connection policy.
4. Freeze those results for the pool's lifetime.
5. Rebuild or explicitly refresh the pool to change the assumptions.

Discovery occurs after authentication because advertised capabilities may
depend on authorization. Profiles are per endpoint and authentication identity,
not global across a replicated topology. Replacement connections may validate
the frozen profile, but the core will not continuously rediscover it.

RFC 3909 support is a future use of this seam. The initial runtime may define a
cancellation policy but implement only conservative drain behavior, with
Abandon-and-tombstone when an operation must be interrupted server-side.

## Endpoint routing

Each endpoint has a caller-supplied stable ID separate from its network address.
The pool supports three increasingly specific choices:

1. Any eligible endpoint, using ordinary load balancing.
2. An exact endpoint ID, for replica-specific consistency.
3. A connection lease within that endpoint, for session affinity.

Exact endpoint routing is required in the initial pool. Cross-process routing
keys can be added later through a versioned selector, such as rendezvous
hashing, provided every process has the same ordered endpoint configuration and
algorithm version. The core must never silently reroute an endpoint-pinned
mutation to a replica.

## Phases

| Phase | Outcome | Plan |
| --- | --- | --- |
| 1 | Evidence base and frozen contracts | [01](docs/phases/01-research-and-contracts.md) |
| 2 | Safe LDAP BER runtime | [02](docs/phases/02-ber-runtime.md) |
| 3 | Hand-authored RFC 4511 wire layer | [03](docs/phases/03-rfc4511-wire.md) |
| 4 | Concurrent LDAP connection runtime | [04](docs/phases/04-connection-runtime.md) |
| 5 | Authentication and setup seam | [05](docs/phases/05-authentication-and-bootstrap.md) |
| 6 | Endpoint-aware pool and observability | [06](docs/phases/06-pooling-routing-observability.md) |
| 7 | 389 DS/FreeIPA hardening and base release | [07](docs/phases/07-interoperability-and-release.md) |
| 8 | Optional native GSSAPI | [08](docs/phases/08-gssapi.md) |

Each phase should leave the repository buildable and tested. Phase boundaries
are checkpoints, not promises that every package must be created in advance.

## Base release acceptance criteria

The base RFC 4511 milestone is complete after Phase 7 when:

- Direct TLS is the verified default and is cancellable while dialing and
  handshaking. Plaintext requires explicit configuration; StartTLS and
  automatic downgrade are absent.
- The BER runtime is bounded, fuzzed, and handles arbitrary read boundaries.
- Hand-authored RFC 4511 objects round-trip supported messages and preserve
  defined extension points.
- Multiple operations can share a connection without response confusion.
- Standard single-response, streaming-response, no-response, and intermediate-
  response patterns are covered.
- Cancellation cannot deadlock unrelated operations or silently reuse a live
  message ID.
- A pool can select any endpoint, pin an operation to an endpoint, or lease a
  connection.
- No request is automatically replayed after an ambiguous network failure.
- Traces can be attached without exposing payloads or importing OpenTelemetry
  into core.
- Integration tests pass against supported 389 DS and FreeIPA environments.
- GSSAPI-facing interfaces have survived review, but GSSAPI need not yet exist.

## Dependency policy

The BER, RFC 4511, connection, and pool runtime should use the standard library
unless a dependency eliminates substantial, well-understood work. Optional
adapters may have their own dependencies. Tools used only by application code
generation or testing do not become runtime dependencies.

Do not use `encoding/asn1` or a general BER object tree as the public runtime
model. Do not introduce a service locator, dependency injection framework, or
global codec registry.

The base authentication package may provide anonymous and Simple Bind support
for testing and non-Kerberos deployments. Simple Bind credentials are supplied
by the caller as bytes, used only during initialization over direct TLS, and
never retained in endpoint profiles, errors, or observability data.

## Reference implementation policy

External projects are expected research material:

- go-ldap for Go interoperability cases, controls, and message-routing tests.
- OpenLDAP/libldap and python-ldap for mature client behavior and edge cases.
- Independent ASN.1/BER tools for checking focused fixtures when useful; Arden
  does not build or ship an RFC codec generator.
- 389 DS source and `dirsrvtests` for server behavior and regression cases.
- FreeIPA source and tests for topology, replication, and authentication use.

For every borrowed idea:

- Identify the specification rule it exercises when possible.
- Record the source URL and revision in a test comment or research note.
- Prefer independently constructed inputs and expected outputs.
- Do not copy code or fixtures until its license and attribution requirements
  are understood.
- If implementations disagree, test 389 DS directly and document the chosen
  compatibility behavior.

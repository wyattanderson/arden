# Phase 6: pooling, routing, and observability

## Goal

Distribute operations across multiplexed connections while supporting exact
server routing, connection leases, bounded load, and useful instrumentation.

## Endpoint model

Every configured server has:

- A stable caller-supplied endpoint ID.
- Network address and explicit transport mode, with a server name when direct
  TLS is selected.
- Authentication identity/configuration.
- Frozen setup profile and core policy.
- Its own connection set and health state.

Do not collapse FreeIPA replicas into one anonymous address set. Replication
semantics belong to the caller, and exact endpoint selection must survive
connection replacement.

## Routing modes

- `Any`: choose an eligible endpoint and its least-loaded connection.
- `Endpoint(id)`: remain on exactly that endpoint; do not fail over silently.
- `Lease`: retain one connection until released or broken.

An endpoint lease may be useful in addition to a connection lease if callers
need replica affinity without session affinity. Keep the first API minimal and
add it only if exact-route calls become awkward.

Cross-process deterministic routing is deferred. Its eventual selector must be
pluggable and versioned; stable routing requires the same endpoint IDs,
membership, weights, and algorithm version in every process.

## Load and lifecycle

- Select by in-flight work, not merely idle/busy state.
- Configure maximum connections per endpoint and maximum in-flight operations
  per connection.
- Use bounded wait queues and honor caller contexts while acquiring capacity.
- Apply jittered backoff to replacement dials.
- Support idle lifetime, maximum lifetime, graceful drain, and prompt shutdown.
- Never put a failed or partially initialized connection into circulation.
- Never replay an ambiguous operation on another connection or endpoint.

Do not prematurely standardize a numeric in-flight default. Begin with a
conservative internal value, benchmark representative streaming and unary loads
against 389 DS, and document the selected default before the base release. The
limit remains configurable and observable.

## Observability

Define a small core hook with operation lifecycle boundaries. An optional
adapter may create OpenTelemetry spans and metrics.

Safe default fields include:

- Endpoint ID and raw network address.
- Connection ID scoped to the process.
- Operation label and application tag.
- Message ID when explicitly enabled for debugging.
- Queue, dial, TLS when applicable, initialization, first-response, and
  completion durations.
- Request/response byte counts and response count.
- Cancellation, connection retirement, and error class.
- Pool size, in-flight work, and waiters.

Never record BER payloads, DNs, filters, attributes, credentials, SASL tokens,
controls, or server diagnostics by default. Operation labels are request
metadata; they do not affect response classification.

## Testing

- Fair distribution across connections with unequal in-flight loads.
- Exact endpoint pinning under concurrency and connection replacement.
- A pinned endpoint failure does not reroute the operation.
- Lease acquisition, release, broken lease, and shutdown behavior.
- Pool exhaustion and context cancellation while waiting.
- Replacement backoff without synchronized reconnect storms.
- Transport mode remains fixed across replacement connections; TLS failures do
  not trigger plaintext fallback.
- Graceful draining with unary and streaming operations.
- Hook ordering, redaction, and behavior when a hook is slow or panics.
- Benchmarks to select the initial in-flight and queue defaults.

Look at mature database and HTTP pools for lifecycle ideas, but validate every
choice against LDAP's multiplexed message IDs. Inspect 389 DS limits and
behavior under pipelined load before treating a benchmark result as portable.

## Deliverables

- Endpoint-aware pool and selection API.
- Exact endpoint routing and connection lease support.
- Bounded admission, lifecycle, and shutdown.
- Pool statistics snapshot.
- Core trace hooks and optional OpenTelemetry adapter.
- Documented, measured initial defaults.

## Implemented defaults and measurement

Phase 6 uses conservative, bounded defaults of two connections per endpoint,
eight in-flight operations per connection, and 128 admission waiters. Idle
connections above the endpoint's last live connection retire after five
minutes, all connections drain after a 30-minute maximum lifetime, shutdown is
bounded to five seconds, and replacement dialing uses exponential jittered
backoff from 100 milliseconds through 30 seconds. Every value is public in
`pool.Options`; zero selects a default and never means unbounded.

`BenchmarkPoolMultiplexedOperations` measures the same pool and connection runtime
over loopback with both unary and four-response streaming operations. A short
100-operation run on an Apple M2 Max measured the following values; these are
implementation checks, not portable directory-server capacity claims:

| Max in-flight | Unary ns/op | Streaming ns/op |
| ---: | ---: | ---: |
| 1 | 43,292 | 47,416 |
| 4 | 19,775 | 36,763 |
| 8 | 18,544 | 37,595 |
| 16 | 18,441 | 35,016 |

Eight is the initial default because it captures the unary throughput knee
without treating the small additional change at 16 as portable evidence.
Run `go test ./pool -run '^$' -bench BenchmarkPoolMultiplexedOperations -benchmem`
to repeat the local measurement. Phase 7's 389 DS harness remains the required
environment for deployment-specific tuning and validation under real server
limits.

## Exit criteria

Callers can deliberately target one directory server, unrelated operations
share connections safely, overload is bounded, shutdown does not leak work, and
instrumentation is useful without making telemetry part of protocol semantics.

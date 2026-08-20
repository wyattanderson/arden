# Phase 4: connection runtime

## Goal

Build a concurrent LDAPS session that exchanges binary operations, routes every
response correctly, and fails predictably under cancellation and network loss.

## Transport requirements

- Direct TLS from the first byte.
- Context-aware TCP dial and TLS handshake.
- Verified server identity by default; clone caller-provided TLS configuration
  before modification.
- No plaintext, StartTLS, URL scheme parsing, or downgrade.
- One reader for the connection and serialized writes.
- Clean close plus abrupt-failure handling.

## Operation lifecycle

The codec, operation, response-header, classifier, and per-operation
registration contracts are specified in detail in
[Phase 3](03-rfc4511-wire.md). In particular, registration is a pending
message-ID record, not registration of an RFC Go type; the reader never
consults a global codec or classifier registry.

1. Validate the request and response pattern.
2. Reserve a nonzero message ID not used by an outstanding operation.
3. Encode the complete LDAP envelope.
4. Install the pending record before any request bytes can reach the peer.
5. Serialize the complete write and handle definitely-unsent versus ambiguous
   failure.
6. Route received messages by message ID.
7. Apply the immutable response pattern to the protocol-operation tag.
8. Deliver owned messages to the consumer, or discard them while canceled.
9. On terminal response, retire the operation and eventually reuse its ID.

Message ID zero is handled separately as an unsolicited notification. Unknown
nonzero IDs and response-contract violations are connection failures.

## Response delivery and backpressure

- Each operation has a bounded response queue or byte budget.
- A full queue initiates cancellation and drain when its response pattern makes
  draining safe.
- If safe draining is impossible, close the connection.
- Never block the sole reader indefinitely on one consumer.
- A canceled consumer stops receiving data, but the runtime keeps classifying
  and discarding until the terminal response arrives.

Do not invoke arbitrary user code from the reader. Declarative tag lookup is the
only classification logic in that path.

## Context and cancellation

- Dial, TLS, and pre-ready setup use their contexts directly.
- An operation context governs its entire lifetime.
- Never apply one operation's deadline to the shared socket.
- Initial cancellation support may drain to a terminal response. If it sends
  Abandon, it must tombstone the target message ID because a successful
  Abandon suppresses the terminal response.
- Define the policy seam for future RFC 3909 Cancel without implementing
  capability discovery or Cancel immediately.
- Noncancelable and no-response operations follow explicit lifecycle rules.

There is no automatic retry after any request byte may have been written. An
error must distinguish a definitely-unsent request from an ambiguous outcome.

## Errors

Provide distinct errors for:

- Context cancellation and deadline expiry.
- Dial, TLS, read, write, and peer closure.
- BER framing and typed protocol violations.
- Unexpected message ID or application tag.
- Queue/resource-limit exhaustion.
- Ambiguous request outcome.
- Unsolicited Notice of Disconnection.

Do not automatically turn every LDAP result code into a connection error. Most
result interpretation belongs to the RFC or application layer.

## Testing

- Multiple response streams interleaved byte-for-byte and message-for-message.
- Writes from many goroutines.
- Short reads, short writes, and failures at each write offset.
- Message ID exhaustion/wrap behavior using a reduced test range.
- Cancellation before write, during write, during streaming, and racing with a
  terminal response.
- Slow or abandoned consumers and bounded-buffer behavior.
- Unsolicited notifications and malformed/unknown message IDs.
- TLS verification, hostname mismatch, handshake timeout, and close races.
- Leak checks for goroutines and pending operations.

Compare failure and race cases with go-ldap and OpenLDAP tests, then validate
the selected semantics against 389 DS. Preserve regressions as small scripted
peers so most tests do not require a server.

## Deliverables

- LDAPS dialer and connection lifecycle.
- Public request, response pattern, operation, and message APIs.
- Internal reader/router and serialized writer.
- Drain cancellation plus an Abandon-and-tombstone baseline.
- Typed transport/protocol errors.
- Race-tested unit and integration suites.

## Exit criteria

The race detector and fuzz corpus pass; one stalled or canceled operation
cannot stall unrelated operations; malformed routing input retires the
connection; and a caller can implement a custom binary operation without
modifying the core.

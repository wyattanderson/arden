# Phase 1: research and contracts

## Goal

Turn the current design into a small set of precise public contracts and a
repeatable process for resolving LDAP ambiguities. Do not implement networking
or general codecs in this phase.

## Required research

- Pin RFC 4511, its errata, RFC 4513, and RFC 4520 references.
- Inventory RFC 4511 application tags, result codes, message cardinalities,
  extension points, BER restrictions, and connection-closing conditions.
- Trace how go-ldap and OpenLDAP correlate message IDs, deliver streaming
  results, abandon operations, and respond to malformed input.
- Locate the corresponding 389 DS request dispatch, BER failure, Bind, Abandon,
  and connection shutdown paths.
- Review asn1c's parser-to-normalizer-to-generator structure; reuse the staging
  idea, not its generated C runtime.

Maintain a short research index containing links, inspected revisions, the
question being answered, and the observed behavior. Avoid a general knowledge
dump.

## Decisions to finalize

- Package names and allowed dependency directions.
- BER identifier representation.
- Owned response buffers for the initial API.
- Append-style marshaling and bounded-reader decoding interfaces.
- Operation request shape and declarative response pattern.
- Behavior for invalid response tags: retire the connection.
- Message ID allocation and non-reuse rule.
- Endpoint ID and exact-endpoint routing vocabulary.
- Typed errors and which failures satisfy `errors.Is` or `errors.As`.
- Public versus internal limits configuration.

Use concrete RFC operations to validate the classifier contract:

| Request | Continue | Complete | Special behavior |
| --- | --- | --- | --- |
| Bind | none | BindResponse | Connection-exclusive |
| Search | Entry, Reference | SearchResultDone | Streaming |
| Modify/Add/Delete/ModifyDN/Compare | none | Matching response | Single response |
| Extended | IntermediateResponse | ExtendedResponse | Streaming-capable |
| Abandon | none | none | No response |
| Unbind | none | none | Connection closes |

## Requirements

- Classifiers inspect only an application tag.
- Response decoding remains outside connection routing.
- Classifier data is immutable and safe for use after caller cancellation.
- No user callback executes in the socket reader.
- Controls, result codes, and response payloads cannot change terminal framing
  unless a future extension explicitly demonstrates otherwise.
- Unknown protocol operations remain representable through public BER codecs.
- Observability labels are metadata, not classifier behavior.
- Public contracts allow optional authentication without importing cgo.

## Deliverables

- A short package dependency diagram.
- API sketches for BER codecs, request/response patterns, operations, endpoint
  selection, initialization, authentication, and tracing.
- A table mapping every RFC 4511 request tag to its response pattern.
- A protocol/error taxonomy.
- Initial security and resource-limit assumptions.
- Focused design notes only where the README and project plan are insufficient.

## Tests and review

Write compile-only contract examples once types exist, but avoid fake
implementations solely to make examples look complete. Walk these scenarios on
paper before accepting the contracts:

- A search returns entries interleaved with another operation's response.
- A search consumer cancels while a terminal response is already in flight.
- A custom extended operation emits intermediates and then completes.
- A server replies to Modify with a Search response tag.
- An endpoint-pinned operation loses its connection after its request is sent.
- Setup discovers different capabilities on two FreeIPA replicas.

## Exit criteria

The public shapes support all scenarios above without payload inspection,
string conversion, or a privileged generated-code path. Remaining uncertainty
is listed explicitly for implementation experiments.

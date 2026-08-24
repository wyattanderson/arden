# Phase 1 frozen contracts

## Package boundaries

```text
ber
 └── protocol (operations, responses, streams, executor)
      └── rfc4511 (LDAPv3 wire values, codecs, response patterns)
           └── root package (generic client, connection runtime, setup seams, errors, tracing)
                ├── auth (anonymous, Simple Bind, mechanism providers)
                │    └── auth/gssapi (optional cgo implementation)
                ├── pool (endpoint routing, leases, admission)
                └── otelldap (optional tracing adapter)
```

`ber` has no Arden dependency. `protocol` imports only `ber`; `rfc4511`
imports `ber` and `protocol`. The root generic client and connection runtime
compose those packages. Extensions may use `protocol` and `rfc4511` directly,
without importing the root client.
Hand-authored built-ins and external extension values implement the same
`ber.Marshaler`, `ber.Unmarshaler`, and `protocol.ProtocolOperation` contracts.
Built-ins have no internal runtime access or registration privilege.
Optional adapters may add dependencies; the runtime remains
standard-library-only.

## Public shapes

The Phase 1 compile-checked definitions live in `ber/identifier.go`,
`operation.go`, `endpoint.go`, `errors.go`, `trace.go`, and
`pool/selection.go`.

- BER identifiers are `{Class, Constructed, Number uint32}`. The value is
  lossless, comparable, supports high-tag-number form, and does not conflate a
  tag number with its class/form bits. Phase 2 will reject encoded tag numbers
  that exceed configured limits before narrowing to `uint32`.
- Marshaling is append-style: `AppendBER(dst) (dst, error)`. Failure leaves the
  input slice unchanged. The Phase 2 reader contract is a concrete bounded
  cursor over caller-owned bytes: constructing it requires validated limits;
  entering a constructed element returns a child reader limited to that
  element; primitive reads advance only on success; typed `UnmarshalBER`
  methods take that reader and reject trailing bytes except at an explicit RFC
  extension point. The full codec contract—including receiver atomicity,
  retained-byte ownership, and the rule that RFC codecs have no privileged
  runtime access—is specified in [Phase 3](phases/03-rfc4511-wire.md).
- `Operation[T]` contains a protocol operation, ordered controls, immutable
  `ResponsePattern[T]`, cancellation mode, and safe metadata. The pattern
  couples consumer-side typed decoding to a `FramingPattern` whose
  classification uses one BER application identifier and yields continue,
  complete, or invalid. `AnyOperation` erases `T` for executors; the reader
  retains only the framing pattern and never invokes the decoder.
  Pattern publication, local configuration, pending-record registration, and
  reader dispatch are specified in [Phase 3](phases/03-rfc4511-wire.md);
  there is no global codec or classifier registry.
- `Response` owns the complete LDAP message bytes. The consumer may retain or
  mutate them; they never alias the socket reader. It also exposes the complete
  `protocolOp` encoding, raw control elements, and allowed unknown trailing
  LDAPMessage extensions as views into those owned bytes. `UnmarshalProtocol`
  invokes any public `ber.Unmarshaler` after routing in the consumer goroutine.
- `EndpointID` is stable caller vocabulary independent of address.
  `pool.Any()` and `pool.Endpoint(id)` distinguish load-balanced and exact
  routing; exact routing never degrades silently. A Phase 6 lease will bind one
  connection inside the selected endpoint.
- `Authentication.Begin` creates a per-connection `Authenticator`.
  `InitializationSession` offers exclusive LDAP operations without exposing a
  raw socket. `Authenticator.Close` runs on every outcome. Generic
  `Initializer[P]` returns a typed higher-layer profile and a small core policy,
  both frozen for the pool lifetime.
- `Tracer` receives endpoint ID and raw address, connection identity, operation label/tag, timing,
  counts, and error class. Hook code runs outside the socket reader. Payloads,
  DNs, filters, attributes, controls, diagnostics, credentials, and tokens are
  never default fields.

The pool accepts `(context, Selection, AnyOperation)` and returns
a `ResponseStream`; acquiring a lease accepts `(context, Selection)` and
returns an object with the same operation method plus idempotent `Close`.
`SelectionAny` may balance only at acquisition time. An exact selection and an
existing lease can fail, but neither can reroute.

## Ownership and concurrency

- `NewResponsePattern[T]` copies identifier slices and installs the decoder for
  `*T`; `NewNoResponsePattern` supplies `ResponsePattern[NoResponse]`. The
  runtime validates and encodes request values before concurrent use and
  retains only immutable framing data and safe metadata.
- One goroutine reads a connection; writes are serialized. The reader may frame
  an owned message, parse its envelope, look up the ID, and classify the tag.
  It does not decode response payloads or call user code.
- Each operation gets a bounded queue. Cancellation stops delivery but leaves a
  router-owned discard record until terminal framing is observed. An Abandon
  target is tombstoned through connection close because successful Abandon
  suppresses the terminal response.
- Message IDs are allocated from 1 through `MaxMessageID`, never while live or
  tombstoned. Exhaustion waits for capacity or fails by context; zero is never a
  request ID.
- No operation context changes the deadline of a shared socket.

## Error contract

| Failure | Public shape | `errors.Is` guarantees |
| --- | --- | --- |
| Dial/TLS (when enabled)/read/write/peer close | `*TransportError` | `ErrTransport`; underlying context/network error; exactly one of `ErrDefinitelyUnsent` or `ErrAmbiguousOutcome` for a request outcome |
| BER frame/envelope/routing contract | `*ProtocolError` | `ErrProtocol`; connection is retired |
| Configured bound exceeded | `*LimitError` | `ErrResourceLimit` |
| Exact endpoint has no eligible connection | `*RouteError` | `ErrEndpointUnavailable`; no reroute |
| Authentication/initialization/profile validation | `*SetupError` | `ErrSetup`; underlying error |
| RFC 4511 Notice of Disconnection | `*NoticeError` | `ErrNoticeOfDisconnection`; connection is retired |
| Caller cancellation/deadline | wrapped context error | `context.Canceled` or `context.DeadlineExceeded`; any request outcome marker is preserved separately by the transport error |
| LDAP result code | RFC/application result | Not a core connection error by default |

`errors.As` exposes every typed error above. Error strings and trace fields must
not include BER payloads or authentication material.

## Public and internal bounds

The following must be public construction-time configuration before the related
runtime phase ships:

- BER maximum frame bytes, nesting depth, elements per value, integer bytes,
  and high-tag number;
- per-operation queued response messages and bytes;
- dial/transport-setup time and initialization operation budget;
- maximum connections per endpoint, in-flight operations per connection, pool
  waiters, and graceful shutdown duration.

Allocator cursor state, tombstone storage strategy, scratch-buffer sizes,
replacement jitter calculation, and test-only reduced ID ranges remain
internal. A zero public limit will never mean unbounded. Numeric defaults are
deferred until Phase 2/4/6 tests can measure them; every decoder is still
required to receive an explicit validated limit set.

## Security assumptions

- Verified direct TLS from the first byte is the default and recommended
  transport. Plaintext LDAP is available only through explicit
  construction-time configuration. There is no StartTLS path, URL-scheme
  inference, downgrade, or fallback to plaintext after TLS failure.
- TLS configurations are cloned before use. Dial, optional handshake,
  authentication, and initialization are context-bounded.
- Authentication mechanisms declare or enforce their confidentiality needs.
  Simple Bind and the planned authentication-only GSSAPI mode require direct
  TLS; plaintext is not a way to bypass those checks.
- Simple Bind credentials use the string-first configuration API and become
  temporary per-connection bytes only inside an authenticator. SASL tokens
  remain bytes. Neither appears in profiles, errors, or traces.
- Owned response bytes can contain sensitive directory data. Ownership prevents
  races, not disclosure; applications control retention and logging.
- No request is replayed after any request byte may have reached a server.

## Scenario walk-throughs

1. Interleaved Search and Modify replies are separated by message ID. Tags 4
   and 19 continue only the Search; tag 7 completes only Modify.
2. If Search cancellation races tag 5, the router atomically observes either
   completion or canceled/discard state. It never delivers after closure or
   reuses a live ID.
3. A custom Extended operation declares tag 25 continuing and tag 24 terminal;
   the router does not inspect OIDs or payloads.
4. A Modify receiving tag 4 classifies invalid, producing `ProtocolError` and
   retiring the connection.
5. If an endpoint-pinned mutation loses its connection after a possible write,
   it returns `RouteError` plus an ambiguous transport outcome and is not sent
   to another replica.
6. Initializers for two FreeIPA endpoints produce two independently typed
   profiles. Pool construction freezes each profile with its endpoint and
   authentication identity.

## Explicitly deferred questions

- Phase 2 will determine concrete numeric BER defaults and whether interoperability
  requires accepting any noncanonical-but-definite encodings.
- Reported RFC 4511 erratum 5292 about `not` filter tagging requires a
  hand-authored vector plus a 389 DS/FreeIPA experiment in Phase 3; it is not
  adopted now.
- Phase 4 must test whether 389 DS sends any final response in races where an
  Abandon arrives after operation completion. The safe contract does not rely
  on one.
- RFC 3909 Cancel wire construction, discovery, and result handling remain for
  the setup/cancellation seam in Phase 5. `CancelExtended` does not assert that
  an endpoint supports it.
- Queue and multiplexing defaults remain measurement-driven Phase 4/6 work.

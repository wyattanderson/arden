# Phase 3: hand-authored RFC 4511 codecs and generic API

> Implementation note: the original plan placed these codecs in a separate
> package. Before the first external consumer, they were folded into the root
> package and given a string-first generic client API. Raw BER and operation
> contracts remain available as the extension escape hatch.

## Goal

Implement RFC 4511 values, constants, codecs, filters, results, and standard
operation declarations directly in Go. The protocol is small and stable; Arden
will not build an ASN.1 parser or RFC codec generator.

The primary architectural test is that built-in operations travel through the
same public contracts available to an external LDAP extension. They get no
privileged reader, registration table, concrete-type dispatch, marker method,
or reflection descriptor.

Code generation remains a possible later tool for FreeIPA or application
schema APIs. Such code should construct public RFC 4511 values or implement the
same extension contracts; it does not change this phase.

## Sources

- RFC 4511 sections 3–5 and normative Appendix B.
- RFC 4511 Appendix A result codes.
- Published RFC 4511 errata.
- RFC 4520 extensibility rules.
- Focused 389 DS/FreeIPA experiments where the RFC or errata leave a real
  interoperability question.

Keep the source URL and section beside non-obvious codecs and fixtures. There
is no checked-in normalized ASN.1 input, annotation IR, or regeneration step.

## Package boundary

The dependency direction is:

```text
ber
 └── protocol
      └── rfc4511
           └── arden
                └── schema packages
```

The `protocol` package owns transport-neutral operation and response contracts.
The `rfc4511` package composes those contracts with LDAPv3 wire values. The root
package adds the generic client and connection runtime. An extension can import
only `protocol` and `rfc4511`; a schema package normally targets the root client.

The RFC package is split by protocol concepts rather than one file per ASN.1
production:

```text
package rfc4511
    types.go       string-first LDAP text and raw value types
    attribute.go   Attribute and PartialAttribute
    result.go      ResultCode, LDAPResult, Referral
    control.go     Control wire value
    bind.go
    search.go
    filter.go
    modify.go
    add.go
    delete.go
    modifydn.go
    compare.go
    abandon.go
    extended.go
    patterns.go
```

Names may change during implementation, but the dependency boundary may not.

## Public codec contracts

### Marshaling

RFC values and external extension values use:

```go
type Marshaler interface {
    AppendBER(dst []byte) ([]byte, error)
}
```

`AppendBER`:

- appends exactly one complete BER value, including identifier and length;
- emits deterministic LDAP BER rather than preserving a noncanonical source
  encoding;
- may reuse destination capacity;
- leaves the original destination length and contents unchanged on error;
- does not retain the destination or mutate its existing prefix;
- validates required fields, choices, cardinality, defaults, integer ranges,
  identifiers, and RFC structural constraints before returning usable bytes;
- encodes only its receiver, without an LDAP envelope, message ID, controls,
  I/O, context, tracing, or connection side effect.

Hand-authored codecs should encode into temporary child buffers or use BER
helpers with explicit rollback points. They must not depend on reflection,
`encoding/asn1`, or a generic mutable object tree.

### Unmarshaling

RFC values and extensions use the public composition interface:

```go
type Unmarshaler interface {
    UnmarshalBER(r *Reader) error
}
```

`UnmarshalBER`:

- consumes one value of the receiver's expected type from a bounded reader;
- cannot bypass frame, depth, element-count, integer, or tag-number limits;
- validates the identifier, primitive/constructed form, required fields,
  ordering, choice cardinality, defaults, and RFC constraints;
- rejects unread contents unless the exact ASN.1 extension point requires
  preserving unknown trailing components;
- preserves complete raw encodings of allowed unknown choices and extension
  fields in source order;
- preserves unknown extensible enum values numerically;
- decodes into temporary state and assigns the receiver only after success, so
  the receiver remains unchanged on error;
- does not promise to roll back the reader cursor after an error; callers
  discard that reader;
- copies byte slices retained by the decoded object, so the object does not
  alias mutable `Response.Bytes`;
- performs no I/O, registration, tracing, or connection work.

The lower-level `ber.Reader` continues to return borrowed views. Ownership is a
typed-codec rule. A future explicitly named view decoder may opt into borrowing
without weakening `UnmarshalBER`.

### Same API for RFC and extensions

The following is a release requirement:

- RFC and extension values implement the same `ber.Marshaler` and
  `ber.Unmarshaler` interfaces.
- RFC requests and extension requests implement the same
  `protocol.ProtocolOperation` interface.
- Filter is an unsealed public interface because its ASN.1 CHOICE is
  extensible.
- The connection runtime never switches on an RFC concrete Go type.
- No global codec, request-tag, response-tag, or filter registry exists.
- A third-party package can define a custom application operation, context
  filter alternative, control, or extended-operation payload without changing
  Arden.

## Request and operation contract

The request value and complete exchange declaration remain separate:

```go
type ProtocolOperation interface {
    ber.Marshaler
    ProtocolIdentifier() ber.Identifier
}

type Operation[T any] struct {
    Protocol     ProtocolOperation
    Controls     []ber.Marshaler
    Responses    ResponsePattern[T]
    Cancellation CancellationMode
    Metadata     OperationMetadata
}

type AnyOperation interface {
    Untyped() UntypedOperation
}
```

The protocol value emits only `LDAPMessage.protocolOp`. The root runtime assigns
the message ID and wraps the value and ordered controls in the envelope.
`ProtocolIdentifier` must agree with the identifier actually encoded by
`AppendBER`; Phase 4 validates that agreement before writing.

An RFC helper assembles an `Operation[T]` with the standard typed response pattern,
a conservative cancellation default, cloned controls, and a safe label. It
must not hide endpoint capabilities, perform I/O, or add generic string-based
directory behavior.

## Response decoding boundary

The socket reader parses only enough of an owned LDAP message to obtain:

```go
type ResponseHeader struct {
    MessageID  MessageID
    ProtocolID ber.Identifier
}
```

The public response carries the full owned envelope plus views of the pieces
extension and RFC code need:

```go
type Response struct {
    MessageID  MessageID
    ProtocolID ber.Identifier
    Bytes      []byte
    Protocol   []byte
    Controls   []ber.Element
    Extensions []ber.Element
}
```

`Protocol` is the complete BER encoding of `protocolOp`. Each control element
is a complete BER Control value. `Extensions` contains complete, validated
unknown trailing LDAPMessage fields in source order. All three are views into
`Bytes`, which is owned by the response and never aliases the socket reader.
The consumer may retain the response; typed unmarshaling copies retained value
bytes.

The raw public convenience path is:

```go
func (r Response) UnmarshalProtocol(
    dst ber.Unmarshaler,
    limits ber.Limits,
) error
```

It creates a bounded reader over `Protocol`, invokes the caller-selected
decoder, and rejects trailing bytes. `ResponsePattern[T].Decode` builds on this
path, returns a newly allocated `*T`, and returns nil on error. The explicit
limits make fake streams and external packages testable without a hidden
connection-owned decoder.

The reader/router does not select or invoke either decoder. `Operation[T]` is
erased through `AnyOperation`, and the runtime retains only its
`FramingPattern`. `UnmarshalProtocol` and `ResponsePattern[T].Decode` run only
in the consumer goroutine after routing. Custom response types use exactly the
same methods as RFC response types.

## Declarative response classification

Response routing remains independent of typed decoding:

```go
type ResponseSpec struct {
    Continue   []ber.Identifier
    Complete   []ber.Identifier
    NoResponse bool
}

func NewResponsePattern[T any](ResponseSpec) (ResponsePattern[T], error)
func NewNoResponsePattern() ResponsePattern[NoResponse]
func (ResponsePattern[T]) Classify(ber.Identifier) Classification
func (ResponsePattern[T]) Decode(Response, ber.Limits) (*T, error)
func (ResponsePattern[T]) Framing() FramingPattern
```

Classification returns `continue`, `complete`, or `invalid` using only the
response application identifier. The pattern is immutable, copies constructor
inputs, has an invalid zero value, and rejects non-application identifiers,
duplicates, overlap, missing terminal identifiers, and response identifiers on
a no-response pattern.

Result codes, response OIDs, controls, and payloads never decide terminal
framing. A failed AddResponse is still terminal. A SearchResultDone carrying a
limit error is still terminal. Payload-dependent classification remains out of
scope until a concrete supported extension proves tag-only framing
insufficient.

### Pattern publication and configuration

The `rfc4511` package publishes functions such as `AddResponsePattern()` and
`SearchResponsePattern()`. They return immutable values backed by
package-private, prevalidated data. The package does not export mutable tag
slices and does not register patterns from `init`.

Custom operations call `NewResponsePattern[T]` directly. Two operations with the
same request tag may carry different patterns if an extension changes the
legal response tags. Configuration is local to the submitted `Operation[T]`.
Abandon, Unbind, and custom no-response operations use the standard
`NoResponse` type and `NewNoResponsePattern`.

### Registration and dispatch

Registration means installing a pending message-ID record, not registering a
Go type:

1. Validate the operation and pattern.
2. Reserve a nonzero, non-live, non-tombstoned message ID.
3. Encode and validate the complete request.
4. Install a pending record containing the immutable pattern, cancellation
   mode, bounded response queue, and lifecycle state.
5. Serialize the write.

The pending record exists before bytes can reach the peer. A definitely-unsent
failure can remove it; an ambiguous write failure retires the connection and
is never replayed automatically.

Reader dispatch is:

```text
read and frame one owned LDAPMessage
              │
              ▼
parse messageID, protocolOp, and raw controls
              │
              ├── messageID == 0
              │      └── validate and dispatch unsolicited notification
              │
              └── find pending record
                        │
                        ├── absent ──► protocol error; retire connection
                        │
                        ▼
                 pattern.Classify(protocolOp)
                        │
                        ├── invalid ──► protocol error; retire connection
                        │
                        ├── continue
                        │      ├── active consumer ──► enqueue response
                        │      └── canceled consumer ► discard; keep record
                        │
                        └── complete
                               ├── active consumer ──► enqueue terminal
                               └── canceled consumer ► discard terminal
                                          │
                                          ▼
                                 complete record; release ID
```

Cancellation changes delivery state, not classification state. The runtime
continues classifying while draining. If Abandon may have succeeded, the
terminal response may never arrive and the target message ID remains
tombstoned until connection close.

## Byte-oriented common values

Hand-author distinct types even where ASN.1 encodes all of them as OCTET
STRING:

```go
type LDAPString []byte
type LDAPOID []byte
type LDAPDN []byte
type RelativeLDAPDN []byte
type URI []byte
type AttributeDescription []byte
type AttributeValue []byte
type AssertionValue []byte
```

Wire codecs validate only their specified wire grammar and structure. They do
not normalize DNs, parse filter strings, discover schema, infer attribute
syntax, or convert attribute values through Go strings.

`Attribute` and `PartialAttribute` are separate concrete values:

```go
type PartialAttribute struct {
    Type   AttributeDescription
    Values []AttributeValue
}

type Attribute struct {
    Type   AttributeDescription
    Values []AttributeValue // at least one
}
```

The RFC layer enforces the nonempty `Attribute` rule. It cannot generically
decide schema equivalence between values or whether an attribute is
NO-USER-MODIFICATION; schema-aware application code owns those checks.

## Add vertical slice

Implement Add early as the unary-operation proof:

```go
type AddRequest struct {
    Entry      LDAPDN
    Attributes []Attribute
}

func (*AddRequest) ProtocolIdentifier() ber.Identifier // application/C/8
func (*AddRequest) AppendBER([]byte) ([]byte, error)
func (*AddRequest) UnmarshalBER(*ber.Reader) error

type AddResponse struct {
    Result LDAPResult
}

func (*AddResponse) AppendBER([]byte) ([]byte, error)
func (*AddResponse) UnmarshalBER(*ber.Reader) error // application/C/9
```

The request layout is:

```text
[APPLICATION 8] constructed
├── OCTET STRING                 entry
└── SEQUENCE                     AttributeList
    └── SEQUENCE                 Attribute
        ├── OCTET STRING         attribute description
        └── SET OF OCTET STRING  one or more values
```

The standard pattern has no continuing tags and application/C/9 as its sole
terminal tag. The standard helper uses conservative drain cancellation: caller
cancellation stops delivery but cannot imply that an already-sent mutation was
rolled back.

Tests cover empty attribute values, multiple attributes, binary values,
application-tag replacement of SEQUENCE, unsuccessful terminal LDAP results,
controls, receiver/destination atomicity, and unknown extensible result codes.

## Search vertical slice

Implement Search as the streaming and extensible-CHOICE proof:

```go
type SearchRequest struct {
    BaseObject   LDAPDN
    Scope        SearchScope
    DerefAliases DerefAliases
    SizeLimit    uint32
    TimeLimit    time.Duration
    TypesOnly    bool
    Filter       Filter
    Attributes   []AttributeSelector
}
```

Size limits and positive time limits validate against RFC 4511 `maxInt`.
`TimeLimit` is converted to whole seconds for the wire; callers are responsible
for fractional and negative duration semantics.

The extensible Filter CHOICE is public and unsealed:

```go
type Filter interface {
    ber.Marshaler
    FilterIdentifier() ber.Identifier
}
```

Hand-author And, Or, Not, Equality Match, Substrings, Greater or Equal, Less or
Equal, Present, Approximate Match, and Extensible Match. Standard codecs enforce
their cardinality and optional/default rules. An external filter alternative
implements the same interface.

Special cases receive direct fixtures:

- Present is primitive context tag 7 containing attribute-description bytes,
  without an inner OCTET STRING tag.
- Equality Match is constructed context tag 3 containing the two
  AttributeValueAssertion fields.
- And and Or require at least one complete child filter.
- Not contains exactly one complete child Filter and follows the RFC's tagged
  CHOICE rule; reported erratum 5292 is tested against 389 DS/FreeIPA before
  any compatibility exception is adopted.
- Substrings require at least one part, at most one initial and final part, and
  the required initial/any/final ordering.

Responses are:

```go
type SearchResultEntry struct {
    ObjectName LDAPDN
    Attributes []PartialAttribute
}

type SearchResultReference struct {
    URIs []URI // at least one
}

type SearchResultDone struct {
    Result LDAPResult
}
```

The standard `ResponsePattern[SearchResult]` declares application/C/4 and
application/C/19 continuing, and application/C/5 terminal. Entries and
references may interleave. `SearchResult.UnmarshalBER` performs the local RFC
CHOICE dispatch after routing; `SearchResult.Value` exposes
`SearchResultEntry`, `SearchResultReference`, or `SearchResultDone` through a
type switch. The socket reader never does this decoding.

Search defaults to Abandon-style cancellation until an endpoint policy selects
RFC 3909 Cancel. Queue overflow uses the same cancellation/drain path and never
blocks the sole socket reader indefinitely.

## Remaining RFC 4511 implementation

After the Add and Search vertical slices prove the public contracts, implement:

1. Common `LDAPResult`, referrals, controls, enums, and application identifiers.
2. Bind and Unbind for Phase 5 authentication/bootstrap.
3. Modify, Delete, Modify DN, and Compare.
4. Abandon and the no-response lifecycle.
5. ExtendedRequest, ExtendedResponse, and IntermediateResponse.
6. Unknown allowed extension components and round-trip preservation.

The RFC package may provide typed iterators and operation constructors, but no
generic string-based Search/Add/Modify/Delete client methods.

## Testing

- Table-driven application tag, enum, and result-code inventory tests.
- Positive and negative fixtures for every concrete type family.
- Marshal failure leaves destination bytes unchanged.
- Unmarshal failure leaves the receiver unchanged.
- Exact consumption and extension-tail preservation.
- Owned retained bytes after typed decoding.
- Unknown extensible enum and CHOICE preservation.
- Hand-authored custom operation/filter/control fixtures compiled outside the
  RFC package, proving there is no privileged path.
- Add unary response and Search interleaving/terminal classifier tests.
- Fuzz every RFC decoder independently from the BER reader.
- Selected differential encodings against an independent BER tool, OpenLDAP,
  go-ldap, packet captures, and 389 DS behavior.

When implementations disagree, reduce the input to a small fixture, consult
the RFC and errata, test 389 DS/FreeIPA, and record the compatibility decision
beside the regression.

## Deliverables

- Public `ber.Unmarshaler` composition interface.
- Response protocol/control views and public protocol unmarshaling path.
- Hand-authored `rfc4511` common values and LDAPResult.
- Add and Search vertical slices with operation helpers and typed response
  decoding examples.
- Remaining RFC 4511 operations, filters, constants, and standard patterns.
- Custom external operation/filter fixture proving API parity.
- Package documentation for adding a control, filter, or extended operation.

## Completion notes

Phase 3 is implemented with hand-authored codecs. Package `rfc4511` supplies
public BER values for every LDAPv3 application operation, while `protocol`
owns generic response envelopes. Search filter and result-CHOICE dispatch are
local to typed decoding; the root reader only routes by `Response.ProtocolID`
and the immutable `FramingPattern` erased from the submitted operation.

External controls, filter alternatives, and protocol operations use the same
`ber.Marshaler`, `ber.Unmarshaler`, `rfc4511.Filter`, and
`protocol.ProtocolOperation` contracts as RFC values. There is no registration path. Unknown extensible
enum values, CHOICE alternatives, and trailing fields are retained as typed
raw values where their schemas permit preservation.

## Exit criteria

All RFC 4511 application operations can be represented, encoded, decoded, and
paired with immutable response patterns without generated RFC code. The
string-first generic layer drives those values without hiding them. Add and
Search pass unary, streaming, cancellation, unknown
extension, ownership, and malformed-input tests. The root runtime contains no
RFC concrete-type switch or registry, and an external extension uses the same
codec, response, classifier, and dispatch APIs as the built-in operations.

# Phase 2: LDAP BER runtime

## Goal

Implement the smallest safe BER substrate needed by RFC 4511 and future LDAP
extensions. This is not a general ASN.1 library.

## Scope

- Identifier encoding and decoding, including class, primitive/constructed bit,
  and high-tag-number form if RFC extensions can legally require it.
- Definite short and long-form lengths.
- Bounded readers for nested elements.
- Append encoders for Boolean, Integer/Enumerated, Octet String, Null, Sequence,
  Set, and application/context-specific values.
- Incremental top-level frame acquisition across arbitrary `net.Conn` reads.
- Raw element views or owned values for unknown fields.
- Precise offsets and causes in decode errors.

RFC 4511 restrictions are mandatory: definite lengths only, primitive OCTET
STRING values, and the specified true Boolean representation when encoding.

## Key decisions

- Encode deterministically; do not preserve noncanonical encodings when a value
  is decoded and re-encoded.
- Decode with explicit byte, depth, element-count, and integer-size limits.
- Return owned top-level message bytes in the first implementation.
- Do not expose a mutable, generic `Packet` tree as the primary API.
- Separate framing errors from schema/type errors.
- Reject trailing bytes where a generated type requires complete consumption;
  preserve trailing sequence components where RFC extensibility requires it.

## Implementation instructions

1. Implement identifiers and lengths with table-driven boundary tests.
2. Implement a bounded element reader that creates child readers rather than
   trusting nested lengths.
3. Implement primitive codecs without reflection.
4. Implement constructed-value append helpers that correctly backfill lengths.
5. Implement the streaming LDAP-message framer separately from typed decoding.
6. Add configurable limits before integrating with a socket.
7. Fuzz every decoder entry point and retain minimized regressions.

Prefer simple slices and indexes. Avoid an interface per ASN.1 primitive,
reflection tags, arenas, pooling, or unsafe code until measurements establish a
need.

## Testing

- Boundary values for tag numbers, lengths, signed integers, and `maxInt`.
- Every split point of representative frames across simulated reads.
- Truncation at every byte position.
- Indefinite lengths, overflowing lengths, excessive nesting, oversized frames,
  and invalid primitive/constructed forms.
- Encode/decode properties for supported primitives.
- Fuzzing with strict allocation and time budgets.
- Differential vectors generated independently with asn1c or another BER tool.

Inspect asn1c and mature LDAP libraries when BER behavior is unclear. Do not
adopt behavior that conflicts with RFC 4511 merely because a permissive decoder
accepts it. Test disputed encodings against 389 DS and document the result.

## Deliverables

- `ber` package with package documentation and resource-limit configuration.
- Unit, property, and fuzz tests.
- A corpus of small, attributed BER fixtures.
- Benchmarks for framing and representative message shapes, used to detect
  gross regressions rather than chase zero allocations.

## Exit criteria

The runtime can safely frame and parse valid LDAP messages from arbitrary read
boundaries, rejects hostile lengths without excessive allocation, and exposes
everything required by generated codecs without LDAP-specific object trees.


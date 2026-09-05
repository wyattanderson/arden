# Byte ownership audit

The September 2026 audit reviewed all 32 direct `bytes.Clone` calls: 22 in
production and 10 in tests. It removed 15 production calls and six test calls.
The remaining seven production calls establish independent decoded storage,
protect validated opaque data, or implement an explicitly requested copy.

Mutable request and entry values share byte storage. Copying in convenience
helpers did not make those objects immutable: callers already have direct
access to their exported slices. Callers who reuse a scratch buffer while
retaining a request, filter, or entry must explicitly copy that buffer. Inputs
must not be mutated concurrently with encoding or other reads.

## Removed copies

| Location | Calls | Assessment and resulting behavior |
| --- | ---: | --- |
| `ber.Primitive`, `WithContents`, `Encoded` | 3 | Packet construction retains inputs; `Encode` already writes a new output buffer. These copies duplicated every binary value on the request path and copied string conversions a second time. Keep inputs stable during encoding. `AppendTo` requires a destination that does not overlap retained inputs. |
| `ber.integerBytes` | 2 | Each branch creates its own local array. Returning a slice keeps that array alive through Go's escape analysis; cloning it adds no ownership protection. |
| `rfc4511.cloneAttributeValues` (now `attributeValues`) | 1 | Binary change helpers expose mutable `Attribute.Values` anyway. Retain each value's backing bytes; the outer slice is still newly allocated for type conversion. |
| `rfc4511.EqualBytes` | 1 | Retain the assertion bytes, matching direct construction of `EqualityMatch`. A caller retaining a filter must copy a scratch buffer before reusing it. |
| Entry `cloneAttributeValues` (now `attributeValues`) | 1 | `SetBytes` shares the supplied bytes, consistent with the exported `Attributes`. Text `Set` already allocates bytes during string conversion. |
| `Entry.RawValues` | 1 | Return shared value bytes in a new outer slice. `RawValue` now looks up only the first value instead of copying every value. Text access still converts to independent strings. |
| `schema.BytesCodec.EncodeFunc`, `DecodeFunc` | 2 | Byte-to-byte conversion has no transformation or private state to protect. Both directions pass through the input, including through typed attribute setters, getters, and filters. |
| `pagedResultsCookie` | 1 | The cookie views an already decoded control. `Entries.Next` encodes the next page synchronously before exposing that page's controls; no buffer reuse or mutation intervenes. |
| GSSAPI configuration construction and `Begin` | 2 | Authorization ID originates as a string. Store and share that immutable string, copying its contents only into the outgoing security-layer selection. Closing a conversation drops its string reference. |
| GSSAPI `exchangeBind` | 1 | Callers retain the token throughout the synchronous exchange and clear it afterward on both success and failure. Copying and clearing a second token adds no lifetime protection. |
| GSSAPI test `completedFakeContext`, `bindResponse` | 2 | The offer is passed to the fake context; response credentials are immediately encoded into a fresh message. Neither needs a preliminary snapshot. |
| GSSAPI fake `Continue`, `Unwrap`, `Wrap` outputs | 3 | Each scripted output is handed to authentication once. Transfer those buffers directly, allowing tests to verify actual clearing instead of clearing an unobserved copy. |
| Connection short-write test | 1 | Parse the transport buffer while holding its mutex. `ParseResponse` already supplies the required independent response storage. |

## Retained copies

| Location | Calls | Concrete reason |
| --- | ---: | --- |
| `ber.Decoder.Primitive` | 1 | Byte values must survive input reuse or clearing. GSSAPI `exchangeBind` clears `Response.Bytes` before returning the decoded server token, which must remain intact for the next GSS call. Decoding individual values also avoids retaining entire LDAP messages for small attributes. The generic decoder also retains this clone for strings to avoid runtime reflection. RFC text decoding knows its destination is a string and converts the reader's bytes directly, without an intermediate byte copy. |
| `ber.Element.Clone` | 1 | The caller explicitly requests detached storage from a borrowed reader view. Ordinary retention alone does not need a clone; input reuse or mutation does. |
| `ParseResponse` | 1 | This public boundary detaches the full response from a caller's potentially reusable input buffer. Envelope views remain consistent with the decoded header. The socket path already transfers fresh `Framer.Next` buffers through `parseOwnedResponse` without copying. |
| `rfc4511.unknownField` | 1 | Preserve validated unknown BER after the source buffer is reused or cleared, matching the ownership of other typed decoded fields. |
| `UnknownField.Bytes`, `UnknownFilter.Raw`, `UnknownAuthentication.Raw` | 3 | These types have private bytes and separately stored validated identifiers. Returning writable internal bytes would allow mutation of tags, lengths, or nested contents without updating the identifier or repeating validation, corrupting later re-encoding. |
| GSSAPI fake `Continue`, `Unwrap`, `Wrap` input recordings | 3 | Production explicitly clears these buffers. The tests must snapshot them to assert what the provider actually received. |
| GSSAPI `cloneBindOperation` test helper | 1 | Snapshot submitted credentials before the owning authentication code clears them, so later assertions inspect what was sent. |

## Validation

Ownership regression tests cover shared entry/schema storage, independent text
snapshots, packet output independence, named string and byte decoding after
input clearing, token clearing, and authorization-ID reuse across conversations.
The existing decoder ownership and response-envelope tests remain intact.

The full root-module race suite and the nested FreeIPA module pass. FreeIPA was
tested using a temporary Go workspace pointing at this checkout, rather than
its pinned published Arden dependency. Allocation benchmarks cover entry text
lookup, packet encoding, and LDAP text decoding.

Measured with Go 1.27.0 on darwin/arm64, comparing the original `HEAD` source
with this change using identical benchmark bodies (three runs each):

| Benchmark | Allocations before → after | Bytes allocated before → after |
| --- | ---: | ---: |
| First text value from a three-value entry | 5 → 1 | 144 → 16 |
| BER sequence containing an integer and 1 KiB byte value | 5 → 4 | 2,376 → 1,360 |
| LDAP DN text decoding | 5 → 3 | 216 → 152 |

## Reflection policy

The [depguard configuration](https://golangci-lint.run/docs/linters/configuration/#depguard)
in `.golangci.yaml` prohibits importing `reflect` in non-test files for
performance reasons. The generic BER decoder keeps its clone instead of
inspecting its type parameter at runtime. RFC text decoding uses its known
string constraint to avoid both reflection and an intermediate copy.

Two existing imports have explicit, import-line `nolint:depguard` exemptions:

- Pool connection setup compares arbitrary profiles, including non-comparable
  types, with `reflect.DeepEqual` when no `ValidateProfile` callback is supplied.
  Removing it would require changing the profile contract or requiring a
  validator. It does not run for each LDAP operation.
- GSSAPI authentication setup detects typed-nil values inside provider, name,
  context, and mechanism interfaces before calling their methods. An ordinary
  interface nil comparison cannot preserve this check. The reflection is
  confined to authentication setup, outside normal LDAP request processing.

Temporary linter probes confirmed that a production `reflect` import is
rejected and the same import in a `_test.go` file is accepted. Existing test
reflection in the RFC fuzz harness remains allowed.

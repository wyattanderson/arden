# Phase 1 research index

This index records only evidence used to freeze Arden's initial contracts. RFC
documents are immutable; source repositories are linked at the inspected commit
rather than a moving branch. The RFC 4511 errata page was checked on
2026-08-19 because errata status can change.

## Normative material

| Source | Pin | Question and result |
| --- | --- | --- |
| [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511.txt) | June 2006; SHA-256 `49c6aab64bd9835420f7fc83e9cc53fe7aea46de882daa4f99fafe20273b06fd` | Defines the LDAPMessage envelope, message-ID correlation/non-reuse, all base application tags, operation cardinalities, extensibility, BER restrictions, and fatal parse behavior. |
| [RFC 4511 errata](https://www.rfc-editor.org/errata/rfc4511) | retrieved 2026-08-19 | Seven verified editorial errata (7216–7222), reported technical erratum 5292, held editorial erratum 8679, and rejected technical erratum 75 were reviewed. Erratum 5292's proposed explicit `not` filter tagging is not normative; Phase 3 must retain the RFC encoding and test actual server interoperability before adopting a compatibility exception. |
| [RFC 4513](https://www.rfc-editor.org/rfc/rfc4513.txt) | June 2006; SHA-256 `2215320fd3d1ae3efc456f331bd0e71a6cfda915ac964130d1565146bf732f6a` | Authentication is association setup, Simple Bind credentials require confidentiality protection, and SASL may be multi-round. Arden therefore authenticates only after verified direct TLS and keeps Bind exclusive to initialization. |
| [RFC 4520](https://www.rfc-editor.org/rfc/rfc4520.txt) | June 2006; SHA-256 `32408c99eba9ac5728ebfbaa208ee2d9f737a47064bc1f6f51d79466b0900b57` | Defines extension rules for LDAP ASN.1 choices, enumerations, and trailing sequence components. Unknown enum values and allowed extension components must remain representable. |

## Implementation evidence

| Source and revision | Question inspected | Observed behavior and Arden decision |
| --- | --- | --- |
| [go-ldap `conn.go` at `56dc6fe`](https://github.com/go-ldap/ldap/blob/56dc6fe26c57c7577780605dfbe6de980658cf64/v3/conn.go#L535) and [async response handling](https://github.com/go-ldap/ldap/blob/56dc6fe26c57c7577780605dfbe6de980658cf64/v3/response.go#L85) | How are message IDs allocated, responses routed, streams delivered, and cancellation handled? | A central goroutine allocates monotonically increasing IDs and maps replies to per-request channels. The async search goroutine decodes stream items and exits on context cancellation; finishing removes its routing entry, so late packets are only logged as unexpected. Arden retains central correlation but uses bounded owned-message queues, tag-only routing, and drain/tombstone semantics so cancellation cannot orphan a live ID. |
| [OpenLDAP `result.c` at `1041618`](https://github.com/openldap/openldap/blob/1041618e1c1df23cb0525d5a455e5596bb74c199/libraries/libldap/result.c#L130) and [`abandon.c`](https://github.com/openldap/openldap/blob/1041618e1c1df23cb0525d5a455e5596bb74c199/libraries/libldap/abandon.c#L121) | How are interleaved streams and abandoned results handled? | Received messages are kept in chains keyed by message ID; search entries, references, and intermediates are nonterminal. Abandon records the target ID and discards later responses until a non-stream result clears it. Arden adopts per-ID correlation and discard state, but conservatively does not reuse an Abandon target ID because RFC 4511 permits a successful Abandon to suppress the terminal response entirely. |
| [389 DS `connection.c` at `fb58b11`](https://github.com/389ds/389-ds-base/blob/fb58b11665b9cf12ff1ec815f948fddb858b450f/ldap/servers/slapd/connection.c#L579), [`abandon.c`](https://github.com/389ds/389-ds-base/blob/fb58b11665b9cf12ff1ec815f948fddb858b450f/ldap/servers/slapd/abandon.c#L68), and [`bind.c`](https://github.com/389ds/389-ds-base/blob/fb58b11665b9cf12ff1ec815f948fddb858b450f/ldap/servers/slapd/bind.c#L140) | Where are dispatch, malformed BER, Bind, Abandon, and shutdown handled? | The connection dispatcher switches on the request tag. The BER reader applies a maximum incoming size and closes on bad envelope/message-ID/tag parsing. Abandon locates a live operation by message ID, marks it abandoned when possible, and never replies. These paths support treating framing/routing violations as connection-fatal and Abandon completion as unobservable. Bind is dispatched as association-changing setup, supporting an exclusive initialization session. |

Inspected revisions:

- go-ldap: `56dc6fe26c57c7577780605dfbe6de980658cf64` (2026-08-10)
- OpenLDAP GitHub mirror: `1041618e1c1df23cb0525d5a455e5596bb74c199` (2026-08-18)
- 389 Directory Server: `fb58b11665b9cf12ff1ec815f948fddb858b450f` (2026-08-19)

## Resulting constraints

- Correlation requires a nonzero request ID unique among all work the server
  might still service. A final response permits reuse; sending Abandon alone
  does not.
- Search entries/references and solicited intermediate responses are stream
  items. Their payload and result codes do not decide terminal framing.
- Unknown request IDs, invalid response tags, and malformed envelopes retire
  the connection. Continuing would make later bytes or ownership ambiguous.
- Response queues contain owned bytes and are bounded. The sole socket reader
  performs envelope parsing, ID lookup, and identifier classification only.
- Bind and initialization are connection-exclusive. Authentication mechanisms
  receive an initialization session rather than a raw socket.

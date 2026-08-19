# RFC 4511 protocol inventory

This inventory is derived from RFC 4511 sections 3–5 and Appendix B. “C” means
constructed and “P” means primitive in the application identifier.

## Application tags and response patterns

| Tag | Identifier | Protocol operation | Direction | Cardinality / request pattern |
| ---: | --- | --- | --- | --- |
| 0 | application/C/0 | BindRequest | client → server | Exactly one BindResponse per Bind step; connection-exclusive. |
| 1 | application/C/1 | BindResponse | server → client | Terminal for BindRequest, including `saslBindInProgress`; another Bind step is a new request. |
| 2 | application/P/2 | UnbindRequest | client → server | No LDAP response; both peers close the session. |
| 3 | application/C/3 | SearchRequest | client → server | Zero or more tag 4/19 messages, then exactly one tag 5 unless successfully abandoned or the session ends. |
| 4 | application/C/4 | SearchResultEntry | server → client | Nonterminal for SearchRequest. |
| 5 | application/C/5 | SearchResultDone | server → client | Terminal for SearchRequest. |
| 6 | application/C/6 | ModifyRequest | client → server | Exactly one tag 7 response. |
| 7 | application/C/7 | ModifyResponse | server → client | Terminal for ModifyRequest. |
| 8 | application/C/8 | AddRequest | client → server | Exactly one tag 9 response. |
| 9 | application/C/9 | AddResponse | server → client | Terminal for AddRequest. |
| 10 | application/P/10 | DelRequest | client → server | Exactly one tag 11 response. |
| 11 | application/C/11 | DelResponse | server → client | Terminal for DelRequest. |
| 12 | application/C/12 | ModifyDNRequest | client → server | Exactly one tag 13 response. |
| 13 | application/C/13 | ModifyDNResponse | server → client | Terminal for ModifyDNRequest. |
| 14 | application/C/14 | CompareRequest | client → server | Exactly one tag 15 response. |
| 15 | application/C/15 | CompareResponse | server → client | Terminal for CompareRequest; compare true/false is payload semantics. |
| 16 | application/P/16 | AbandonRequest | client → server | No response. Target may still produce already-in-flight messages or a terminal result if not abandoned. |
| 19 | application/C/19 | SearchResultReference | server → client | Nonterminal for SearchRequest. |
| 23 | application/C/23 | ExtendedRequest | client → server | Zero or more solicited tag 25 messages, then exactly one tag 24. |
| 24 | application/C/24 | ExtendedResponse | server → client | Terminal for ExtendedRequest; also carries unsolicited notifications with message ID zero. |
| 25 | application/C/25 | IntermediateResponse | server → client | Nonterminal only when solicited by an extended operation or control. |

The frozen base patterns are therefore:

| Request | Continue | Complete | Lifecycle |
| --- | --- | --- | --- |
| Bind (0) | — | BindResponse (1) | Exclusive |
| Unbind (2) | — | — | No response; close |
| Search (3) | SearchResultEntry (4), SearchResultReference (19) | SearchResultDone (5) | Streaming |
| Modify (6) | — | ModifyResponse (7) | Unary |
| Add (8) | — | AddResponse (9) | Unary |
| Delete (10) | — | DelResponse (11) | Unary |
| Modify DN (12) | — | ModifyDNResponse (13) | Unary |
| Compare (14) | — | CompareResponse (15) | Unary |
| Abandon (16) | — | — | No response |
| Extended (23) | IntermediateResponse (25) | ExtendedResponse (24) | Streaming-capable |

A control that solicits IntermediateResponse for an existing operation must
construct a different immutable pattern that adds tag 25 to that request's
continue set. Controls never modify a pattern after submission.

## LDAP result codes

The enumeration is extensible. Unknown assigned values remain integers and are
not transport errors.

| Value | Name | Value | Name |
| ---: | --- | ---: | --- |
| 0 | success | 1 | operationsError |
| 2 | protocolError | 3 | timeLimitExceeded |
| 4 | sizeLimitExceeded | 5 | compareFalse |
| 6 | compareTrue | 7 | authMethodNotSupported |
| 8 | strongerAuthRequired | 10 | referral |
| 11 | adminLimitExceeded | 12 | unavailableCriticalExtension |
| 13 | confidentialityRequired | 14 | saslBindInProgress |
| 16 | noSuchAttribute | 17 | undefinedAttributeType |
| 18 | inappropriateMatching | 19 | constraintViolation |
| 20 | attributeOrValueExists | 21 | invalidAttributeSyntax |
| 32 | noSuchObject | 33 | aliasProblem |
| 34 | invalidDNSyntax | 36 | aliasDereferencingProblem |
| 48 | inappropriateAuthentication | 49 | invalidCredentials |
| 50 | insufficientAccessRights | 51 | busy |
| 52 | unavailable | 53 | unwillingToPerform |
| 54 | loopDetect | 64 | namingViolation |
| 65 | objectClassViolation | 66 | notAllowedOnNonLeaf |
| 67 | notAllowedOnRDN | 68 | entryAlreadyExists |
| 69 | objectClassModsProhibited | 71 | affectsMultipleDSAs |
| 80 | other |  |  |

Values 9, 35, and 70 are reserved; 22–31, 37–47, 55–63, and 72–79 are unused
in RFC 4511. The non-error values are 0, 5, 6, 10, and 14. Only the typed
consumer interprets these values; response routing does not.

## Extension points

- `LDAPMessage.protocolOp`, `AuthenticationChoice`, `Filter`, result code,
  search scope, and modify operation enumerations are extensible.
- Unrecognized trailing SEQUENCE components are ignored unless a specification
  says otherwise; decoders preserve allowed unknown components for round trips.
- Controls, extended operations, unsolicited notifications, and intermediate
  responses carry assigned OIDs with extension-defined OCTET STRING payloads.
- Unknown protocol operations remain representable by `ber.Identifier` plus a
  handwritten `arden.ProtocolOperation`; they are not accepted as responses
  unless explicitly included in a response pattern.

## BER and envelope restrictions

- Only definite lengths are valid.
- OCTET STRING is primitive only.
- Encoded BOOLEAN true is exactly `FF`.
- Default-valued fields are omitted.
- Message IDs are integers from 0 through 2,147,483,647. Requests use nonzero
  IDs unique among operations the server may still be servicing; zero is for
  unsolicited notifications.
- The top level is one LDAPMessage SEQUENCE. A response repeats the request's
  message ID.

## Connection-closing conditions

RFC 4511 requires immediate session termination when the server cannot parse
the LDAPMessage sequence, message ID, request tag, encoding structure, or
length; a protocol-error Notice of Disconnection should be sent when possible.
A peer may close abruptly when further communication would be harmful.
UnbindRequest and Notice of Disconnection gracefully terminate the session.

For a client, malformed framing, an invalid envelope, an unknown nonzero
response ID, or a response identifier outside the frozen pattern makes routing
ambiguous. Arden retires the entire connection. A normal LDAP result code does
not. On any connection loss, an operation is definitely unsent only if no
request byte could have reached the server; otherwise its outcome is ambiguous
and it is never replayed automatically.

# arden

Arden is an experimental, binary-first LDAPv3 client for Go. Its initial target
is RFC 4511 over direct TLS, interoperating with 389 Directory Server and
FreeIPA.

The project is intentionally narrower than a general LDAP SDK. The core will
provide BER codecs, LDAP message transport, concurrent operation routing,
contexts, tracing hooks, and multiplex-aware pooling. Search, modification, DN
and filter text APIs, schema-aware values, and application-specific operations
belong in generated or handwritten packages above the core.

The design goal is ordinary, idiomatic Go: small interfaces, explicit resource
ownership, useful errors, no reflection-heavy object model, and no hidden
network retries.

## Status

Design only. No implementation has started.

See [PROJECT_PLAN.md](PROJECT_PLAN.md) and the individual plans in
[docs/phases](docs/phases).

## Compatibility target

- Go's supported toolchain at implementation time.
- LDAPv3 as defined by RFC 4511 and its errata.
- Direct TLS from the first byte; no plaintext LDAP or StartTLS.
- 389 Directory Server and FreeIPA.
- A cgo-free core.
- Pluggable authentication. Ordinary Bind mechanisms remain possible; native
  GSSAPI/Kerberos support is a later, optional package.

Compatibility with arbitrary LDAP servers is welcome when it comes naturally,
but it is not a release requirement.

## Architectural outline

```text
typed/generated application package
              |
       RFC 4511 wire types
              |
 request + response pattern + controls
              |
  connection / routing / pool runtime
              |
         TLS connection
```

The core exchanges BER objects, not generic string-based directory operations.
It assigns message IDs, wraps protocol operations in `LDAPMessage`, dispatches
responses, and retires an operation when its declarative response pattern says
the terminal response has arrived.

## Locked design decisions

- Wire values are byte-oriented. Text conversion and syntax interpretation are
  higher-layer responsibilities.
- LDAP gets a small purpose-built BER runtime, not a general ASN.1 framework.
- RFC codecs and constants are generated from pinned specification inputs.
- Generated and handwritten values use the same public codec contracts.
- Response classification is declarative and tag-based: continue, complete, or
  invalid. Payload-dependent classification is excluded until a real extension
  proves it necessary.
- A framing error or response-contract violation retires the whole connection.
- Context cancellation cancels and drains an operation when safe; it never sets
  a per-operation deadline on a shared socket.
- Pools distribute concurrent operations across multiplexed connections. A
  lease provides connection affinity; an endpoint ID provides server affinity.
- There is no transparent retry after request bytes may have reached a server.
- Authentication is completed before a connection becomes available to
  application code and is otherwise transparent to protocol packages.
- GSSAPI will negotiate authentication only over LDAPS. TLS provides the data
  security layer.
- Observability is supported through small hooks; OpenTelemetry is an optional
  adapter rather than a core dependency.

## Non-goals

- Generic `Search`, `Add`, `Modify`, `Delete`, or filter-string APIs in core.
- LDIF, LDAP URLs, schema administration, or a universal DN library.
- Plain LDAP, StartTLS, or automatic TLS downgrade.
- A complete ASN.1 compiler.
- Automatic credential acquisition, `kinit`, keytab management, or live rebind.
- Transparent failover of operations with ambiguous outcomes.
- Reproducing every historical LDAP client quirk.

## How design questions are resolved

When the RFC is unclear, incomplete, or surprising, do not design from taste
alone. Investigate in this order:

1. The RFC text, published errata, referenced RFCs, and IANA registries.
2. 389 DS source and tests, then FreeIPA integration behavior.
3. Mature client implementations such as OpenLDAP/libldap, go-ldap, and
   python-ldap, plus ASN.1 tools such as asn1c where generation is involved.
4. A minimal packet-level experiment against the supported server.

Record the evidence and the resulting decision in the relevant phase document,
test, or a short design note. Other implementations are behavioral references,
not APIs to copy. Preserve attribution and check licenses before adapting test
vectors or code.

## Reference material

- [RFC 4511: LDAPv3 protocol](https://www.rfc-editor.org/rfc/rfc4511)
- [RFC 4513: LDAP authentication and security](https://www.rfc-editor.org/rfc/rfc4513)
- [RFC 3909: LDAP Cancel](https://www.rfc-editor.org/rfc/rfc3909)
- [go-ldap](https://github.com/go-ldap/ldap)
- [python-ldap](https://github.com/python-ldap/python-ldap) and
  [OpenLDAP](https://git.openldap.org/openldap/openldap)
- [asn1c](https://github.com/vlm/asn1c)
- [389 Directory Server](https://github.com/389ds/389-ds-base)
- [FreeIPA](https://github.com/freeipa/freeipa)


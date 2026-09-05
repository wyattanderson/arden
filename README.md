# arden

Arden is an experimental LDAPv3 client for Go. Its initial target
is RFC 4511 with direct TLS preferred, interoperating with 389 Directory Server
and FreeIPA.

Arden provides string-first generic LDAP operations, schema-neutral entries,
safe filter constructors, automatic paging, hand-authored RFC 4511 codecs,
concurrent operation routing, tracing, and multiplex-aware pooling. Raw BER,
operation, response, and control contracts remain public for deep extensions.
Schema-specific values and models belong in generated or handwritten packages
above the generic client.

The design goal is ordinary, idiomatic Go: small interfaces, explicit resource
ownership, useful errors, no reflection-heavy object model, and no hidden
network retries.

## Status

Phases 1 through 6 are implemented. Phase 7 is currently deferred, and the
optional Phase 8 GSSAPI implementation is available pending an external
FreeIPA smoke check. The evidence index, RFC 4511 protocol
inventory, transport-independent contracts, error taxonomy, and
compile-checked protocol contracts are implemented. The `ber` package provides bounded
definite-length BER parsing and encoding, strict LDAP primitive handling, and
incremental owned frame acquisition. The `protocol` package defines generic
operation and response contracts, and `rfc4511` provides every standard LDAPv3
wire operation and immutable typed response pattern. The root package provides the
generic client, entries, filters, direct-TLS-by-default dialing,
explicit plaintext selection,
concurrent request routing, bounded response delivery, drain and Abandon
cancellation, unsolicited notifications, and typed lifecycle failures.
The `auth` package provides anonymous and TLS-only Simple Bind mechanisms.
`Dialer` completes authentication before returning, while `Bootstrap` also
runs a typed higher-layer initializer and freezes its identity and core policy
handoff before the connection becomes visible.
The `pool` package adds least-loaded multiplexing, exact endpoint routing,
exclusive connection leases, bounded admission, jittered replacement,
lifetime draining, graceful shutdown, and statistics. `Dialer.Logger` emits
safe debug-level `log/slog` records, core lifecycle hooks are available through
`Dialer.Tracer`, and `otelldap` is the optional OpenTelemetry adapter. The
`auth/gssapi` package implements a mockable RFC 4752 exchange, while the
build-tagged `auth/gssapi/native` adapter uses the platform GSSAPI through
`github.com/golang-auth/go-gssapi` and selects authentication-only SASL over
LDAPS.

See [PROJECT_PLAN.md](PROJECT_PLAN.md) and the individual plans in
[docs/phases](docs/phases). Phase 1 outputs are summarized in
[docs/contracts.md](docs/contracts.md), [docs/protocol-inventory.md](docs/protocol-inventory.md),
and [docs/research-index.md](docs/research-index.md).

## Authentication and bootstrap

Authentication is construction-time configuration. Application operations do
not carry credentials or select a mechanism:

```go
simple, err := auth.NewSimpleBind(
	"service-account-a",            // stable, nonsecret pool identity
	"uid=service,dc=example",
	password,
)
if err != nil {
	return err
}

conn, err := (&arden.Dialer{Authentication: simple}).Dial(ctx, arden.Endpoint{
	ID:         "ipa-west",
	Address:    "ipa-west.example:636",
	ServerName: "ipa-west.example",
})
if err != nil {
	return err
}
defer conn.Close()

client := arden.NewClient(conn)

entry := arden.NewEntry("uid=alice,ou=people,dc=example")
entry.Set("objectClass", "top", "person", "inetOrgPerson")
entry.Set("uid", "alice")
entry.Set("cn", "Alice Example")
entry.Set("sn", "Example")
err = client.Add(ctx, entry)
```

Use `auth.Anonymous{}` for an ordinary anonymous Bind, or leave
`Dialer.Authentication` nil to perform no Bind. Higher layers that need root
DSE or other setup discovery use `arden.Bootstrap[P]`; its initializer runs
exclusively after authentication and returns the typed endpoint profile before
the connection is published.

Native Kerberos authentication is opt-in and uses the platform's default
credential acquisition:

```go
authentication, err := native.New("service-account-a")
if err != nil {
	return err
}

conn, err := (&arden.Dialer{Authentication: authentication}).Dial(ctx, arden.Endpoint{
	ID:         "ipa-west",
	Address:    "ipa-west.example:636",
	ServerName: "ipa-west.example",
})
```

Import `github.com/wyattanderson/arden/auth/gssapi/native` and build with the
`gssapi` tag. The platform derives the target principal
`ldap/ipa-west.example` from the `ldap@ipa-west.example` host-based GSS name.
Integrity and confidentiality SASL data layers are rejected; TLS protects
subsequent LDAP operations. See [docs/gssapi.md](docs/gssapi.md) for platform
prerequisites, gssproxy configuration, troubleshooting, and the read-only
FreeIPA smoke command.

## Generic operations and typed models

RFC operation constructors encode their response type. `Client.ExecuteSingle`
infers that type, returns a newly allocated response, decodes controls, and
requires a successful LDAP result by default:

```go
operation, err := rfc4511.NewAddOperation(&rfc4511.AddRequest{
	Entry:      "uid=alice,ou=people,dc=example",
	Attributes: attributes,
}, nil)
if err != nil {
	return err
}

response, controls, err := client.ExecuteSingle(ctx, operation)
// response has type *rfc4511.AddResponse and is nil on transport or decode errors.
```

`AcceptResultCodes` replaces the default accepted set for operations such as
Compare. A rejected LDAP result returns the decoded response and controls with
`*arden.ResultError`; transport and decode failures return a nil response.
`Client.ExecuteStream` uses the same submission, decoding, and control path for
operations with multiple responses and returns an owned `DecodedStream[T]`.
`Client.Execute` remains a concise alias for `Client.ExecuteSingle`.
Streaming Search responses decode as `rfc4511.SearchResult`; its
`Value` method exposes `SearchResultEntry`, `SearchResultReference`, or
`SearchResultDone` through a type switch. Abandon and Unbind use the standard
`protocol.NoResponse` response type.

Search returns an iterator and follows RFC 2696 cookies when `PageSize` is set.
`NewAttributeSelectors` copies and pre-encodes the selection once; keep the result
for reuse across searches. The zero value requests all user attributes.

```go
client := arden.NewClient(conn)
rows, err := client.Search(ctx, arden.SearchRequest{
	BaseDN:     "ou=people,dc=example",
	Scope:      arden.ScopeSubtree,
	Filter:     arden.Equal("departmentNumber", "engineering"),
	Attributes: arden.NewAttributeSelectors("uid", "cn", "jpegPhoto"),
	PageSize:   100,
})
if err != nil {
	return err
}
defer rows.Close()

for rows.Next() {
	entry := rows.Entry()
	fmt.Println(entry.DN, entry.Value("cn"))
	photo := entry.RawValue("jpegPhoto") // explicit binary escape hatch
	_ = photo
}
if err := rows.Err(); err != nil {
	return err
}
```

`schema.Attribute[T]` is the reflection-free seam for generated models. A
generator can publish typed descriptors and ordinary model methods while using
the same entries, filters, and client underneath:

```go
var UID = schema.NewAttribute("uid", schema.StringCodec)

filter, err := UID.Equal("alice")
values, err := UID.Values(entry)
```

`ldapmodel` builds on those descriptors with a reusable generic `DAO[T]`,
typed criteria and patches, materialized `All`/`One`/`First` result paths, and
an explicitly closed streaming path. Schema-specific packages provide the
model projection and decoder without generating a DAO type for every model.

Custom protocol work stays equally direct. The `rfc4532` package is a reference
extension implemented only against the public `arden.Executor` contract:

```go
authorizationID, err := rfc4532.WhoAmI(ctx, conn)
```

## 389 Directory Server integration smoke test

With Docker running, execute:

```sh
go test -tags=integration -run '^Test389DS' -count=1 ./integration
```

The test starts and cleans up an ephemeral 389 Directory Server container with
Testcontainers on a random localhost LDAPS port, obtains its generated test CA
certificate, and runs through Arden's public setup API. It performs a verified,
TLS-only Simple Bind as Directory Manager during `Dial`, then exercises the
generic root DSE, add, paged search, modify, filtered search, and delete APIs
before closing the connection with Unbind.

Set `ARDEN_389DS_IMAGE` to test another image reference. The normal
`go test ./...` suite does not start Docker or include this integration test.

## Compatibility target

- Go's supported toolchain at implementation time.
- LDAPv3 as defined by RFC 4511 and its errata.
- Verified direct TLS from the first byte is the default and recommended
  transport. Plaintext LDAP requires explicit opt-in; StartTLS and automatic
  downgrade are not supported.
- 389 Directory Server and FreeIPA.
- A cgo-free core.
- Pluggable authentication. Ordinary Bind mechanisms and optional native
  GSSAPI/Kerberos authentication remain transparent to application operations.

Compatibility with arbitrary LDAP servers is welcome when it comes naturally,
but it is not a release requirement.

## Architectural outline

```text
typed or schema-generated application package
              |
 generic LDAP entries, filters, and operations
              |
 hand-authored RFC 4511 codecs + extension contracts
              |
  connection / routing / pool runtime
              |
 network connection (direct TLS by default)
```

The public client uses strings for LDAP text and ordinary values, while binary
attribute, control, and extension values retain raw byte access. The runtime
assigns message IDs, wraps protocol operations in `LDAPMessage`, dispatches
responses, and retires operations through declarative response patterns.

## Locked design decisions

- LDAP text is string-first. Arbitrary attribute values and extension payloads
  retain explicit byte access.
- LDAP gets a small purpose-built BER runtime, not a general ASN.1 framework.
- RFC 4511 codecs, constants, and response patterns are hand-authored and
  reviewed against the pinned specification and errata.
- Built-in values and external extensions use the same public codec and
  operation contracts; built-ins have no privileged runtime path.
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
- Credential-bearing authentication that relies on transport confidentiality,
  including Simple Bind, is not permitted on a plaintext connection.
- GSSAPI will negotiate authentication only over LDAPS. TLS provides the data
  security layer.
- Observability is supported through small hooks; OpenTelemetry is an optional
  adapter rather than a core dependency.

## Non-goals

- LDIF, LDAP URLs, schema administration, or a universal DN library.
- StartTLS, transport inference from LDAP URLs, or automatic TLS downgrade.
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
   python-ldap, plus independent BER tools for checking disputed encodings.
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
- [389 Directory Server](https://github.com/389ds/389-ds-base)
- [FreeIPA](https://github.com/freeipa/freeipa)

# Native GSSAPI authentication

Arden's optional native adapter authenticates an LDAPS connection with the
Kerberos V5 SASL `GSSAPI` mechanism from RFC 4752. TLS continues to protect all
LDAP application traffic: the SASL exchange explicitly selects bit `1`, the
authentication-only option, and rejects servers that offer only integrity or
confidentiality data layers. Arden never changes LDAP PDU framing after the
Bind.

The implementation has two layers:

- `auth/gssapi` contains the cgo-free RFC 4752 conversation and accepts a
  `go-gssapi` provider factory. Its tests use only fake providers and scripted
  LDAP responses.
- `auth/gssapi/native` is enabled by the `gssapi` build tag and registers
  `github.com/golang-auth/go-gssapi-c`, which links to the platform GSSAPI
  implementation.

The root, BER, RFC 4511, ordinary authentication, and pool packages do not
import either native bindings or cgo. Builds that do not select the optional
package remain cgo-free.

## Runtime behavior

`native.New` does not accept a keytab, password, credential cache name, or an
explicit credential handle. Each connection gets a new provider and calls
`GSS_Init_sec_context` with the provider's default initiator credential. This
allows the platform to select an ordinary credential cache or gssproxy without
credential-management code in Arden.

The GSS target is derived from the verified endpoint TLS name as
`ldap@<Endpoint.ServerName>` and imported as `GSS_C_NT_HOSTBASED_SERVICE`.
Arden does not perform DNS canonicalization. The corresponding Kerberos
principal normally has the form `ldap/FQDN@REALM`.

The context requests the Kerberos V5 mechanism, mutual authentication, and
integrity. Integrity is required to wrap the RFC 4752 security-layer offer and
selection even though no SASL data layer is installed. Context cancellation is
checked before and after every provider call and between every LDAP Bind round.
A call currently executing inside the platform GSS library may not itself be
interruptible.

GSS names, security contexts, and providers are per-connection, serialized by
the authenticator, and released once on every success or failure path. GSS and
SASL tokens are never placed in error strings, operation labels, logger fields,
or trace fields.

## Building

The native adapter supports the operating-system combinations supported by
`go-gssapi-c`: Linux with MIT Kerberos or Heimdal, macOS with Apple Kerberos or
a Homebrew implementation, FreeBSD, and OpenBSD. It requires cgo.

Linux commonly needs `pkg-config` plus either the MIT development package
(`libkrb5-dev` on Debian/Ubuntu, `krb5-devel` on Fedora/RHEL) or the equivalent
Heimdal development package:

```sh
go build -tags=gssapi ./cmd/arden-gssapi-smoke
```

macOS uses Apple Kerberos by default and needs no additional package. To select
a Homebrew MIT Kerberos installation instead:

```sh
PKG_CONFIG_PATH=/opt/homebrew/opt/krb5/lib/pkgconfig \
  go build -tags='gssapi usepkgconfig' ./cmd/arden-gssapi-smoke
```

Use `/opt/homebrew/opt/heimdal/lib/pkgconfig` to select Homebrew Heimdal.
FreeBSD 15 and ports-based GSS implementations may likewise require the
`usepkgconfig` build tag. OpenBSD uses its installed Heimdal implementation.

With `CGO_ENABLED=0`, the native constructor reports that native GSSAPI is
unavailable when the package is explicitly selected. The ordinary suite needs
neither cgo nor platform Kerberos headers:

```sh
CGO_ENABLED=0 go test ./...
```

## Read-only FreeIPA smoke check

The smoke command performs verified direct TLS, the native GSSAPI Bind, an RFC
4532 `Who Am I?` extended operation, and a base-scope root DSE Search requesting
only `supportedLDAPVersion` and `supportedSASLMechanisms`. It requires `Who Am
I?` to return a non-empty authorization identity, so a successful Bind that the
server nevertheless treats as anonymous does not pass the smoke check. It does
not modify directory data.

First make the desired default credentials available to the platform GSSAPI,
then run:

```sh
go run -tags=gssapi ./cmd/arden-gssapi-smoke \
  -address ipa.example.test:636 \
  -server-name ipa.example.test \
  -ca-file /path/to/ipa-ca.pem
```

On success, the command prints the server-reported authorization identity.
`-server-name` is used for both TLS verification and the `ldap@hostname` GSS
target. `-ca-file` is optional when the FreeIPA CA is already trusted by the
system. `-identity` changes only Arden's nonsecret pool-partition identity; it
does not select a Kerberos principal. `-timeout` defaults to 30 seconds.

For a non-default credential cache, configure the platform before starting the
process, for example with `KRB5CCNAME`. Arden does not run `kinit`, acquire from
a keytab, renew tickets, or alter cache contents.

## gssproxy example

This initiation-only example refers to an already managed credential cache and
contains no key material. Adapt the service account, executable, and cache path
to the deployment:

```ini
# /etc/gssproxy/80-arden-ldap.conf
[service/arden-ldap-client]
  mechs = krb5
  cred_store = ccache:FILE:/run/arden/krb5cc
  cred_usage = initiate
  euid = arden
  program = /usr/local/bin/arden-gssapi-smoke
```

Reload gssproxy and start the process with `GSS_USE_PROXY=yes`. The GSSAPI
interposer selects the service and credentials; the Arden API remains
unchanged. This configuration deliberately does not tell Arden about a keytab
or cache path.

## Errors and troubleshooting

`*gssapi.Error` safely reports the failed GSS operation. It wraps the original
`go-gssapi` error for `errors.Is` and `errors.As`, while omitting the provider's
text from default formatting because native messages can include principal
names and credential-cache paths. The standardized GSS major status is exposed
when the upstream provider retains it. `go-gssapi` does not expose the raw
mechanism-specific minor value, so Arden does not report one.

`*gssapi.NegotiationError` reports token-shape, context-policy, round-limit,
and security-layer-policy failures without retaining token bytes. LDAP server
rejections use `*auth.BindError`, which exposes only the LDAP result code.

Common checks:

- Missing or expired credentials: inspect the selected cache with the platform
  Kerberos tools. Arden should surface `go-gssapi`'s `ErrNoCred` or
  `ErrCredentialsExpired` through `errors.Is`.
- Wrong service principal: confirm that the KDC and FreeIPA server have
  `ldap/FQDN@REALM` and that `-server-name` is that FQDN, not an IP address or
  unrelated alias.
- TLS hostname mismatch: keep `-address` as the routable socket address, but
  set `-server-name` to the certificate and Kerberos service hostname.
- Clock skew: synchronize the client, KDC, and FreeIPA server clocks.
- Server rejection: verify the root DSE advertises `GSSAPI` in
  `supportedSASLMechanisms`, advertises `1.3.6.1.4.1.4203.1.11.3` in
  `supportedExtension`, and inspect server-side SASL mapping policy.
- gssproxy: confirm `GSS_USE_PROXY=yes`, the effective UID and executable match
  a service stanza, and the process can reach the configured proxy socket.
- Native build failure: verify cgo, the platform development headers, and the
  `pkg-config` selection. Do not add the `gssapi` tag to cgo-free builds.

MIT Kerberos and Heimdal can produce different diagnostic strings and cache
selection behavior. Arden relies only on `go-gssapi` interfaces and default
credential acquisition; implementation-specific differences stay behind the
native provider.

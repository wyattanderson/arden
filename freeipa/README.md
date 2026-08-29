# FreeIPA client experiment

This directory is a separate Go module. Its local `go.work` resolves
`github.com/wyattanderson/arden` to the parent checkout, so edits to Arden are
used immediately by local tests and by the client image build.

The Compose stack starts an official FreeIPA server, a one-shot Arden client,
and a Caddy edge proxy. FreeIPA and the client are attached only to an internal
Docker network, which prevents outbound access. FreeIPA has the fixed address
`172.30.0.10`, hosts the authoritative forward and reverse DNS zones for the
network, and is the DNS server used by both the client and proxy. Caddy is also
attached to a separate host-facing bridge so it can publish the web UI without
giving FreeIPA or the client a route out of the internal network.

The client obtains a Kerberos ticket, opens verified direct TLS to port 636,
performs a SASL GSSAPI Bind, and executes the RFC 4532 Who Am I? operation.
FreeIPA runs systemd, so its service uses the host cgroup namespace and the
writable cgroup mount recommended by the official container documentation.

## Run it

FreeIPA's first initialization can take several minutes:

```sh
cd freeipa
docker compose build client
docker compose up --detach --wait freeipa edge
docker compose run --rm client
```

The successful client output looks like:

```text
Who Am I? dn: uid=admin,cn=users,cn=accounts,dc=arden,dc=test
```

While the stack is running, the FreeIPA web UI is available through Caddy at
<http://localhost:8389>. Only that loopback address is published to the Docker
host. Caddy connects to FreeIPA over HTTPS and verifies its certificate against
the CA created in the shared FreeIPA data volume.

The default password is intentionally only a local-development convenience.
Override it before the first start when desired:

```sh
export FREEIPA_PASSWORD='a-development-only-password'
docker compose up --detach --wait freeipa edge
docker compose run --rm client
```

FreeIPA keeps its initialized state in the `freeipa-data` volume. A later
password environment change does not change that persisted admin password. To
discard the lab directory and initialize it again:

```sh
docker compose down --volumes
```

The server and edge proxy remain running in the background. Rerun only the
client as often as needed with:

```sh
docker compose run --rm client
```

## Use a keytab instead

The entrypoint also supports a production-shaped credential handoff. Mount a
keytab readable by uid 10001, set `KRB5_KEYTAB` to its in-container path, set
`KRB5_PRINCIPAL` to that keytab's principal, and remove `KRB5_PASSWORD` from the
client service. Arden itself neither reads the keytab nor runs `kinit`; it uses
the default credential cache created by the container entrypoint.

## Local module commands

Run these from this directory so `go.work` selects both modules:

```sh
go test ./...
go test -tags=gssapi ./...
```

## Generated-model design sketch

[`posixaccount`](posixaccount/DESIGN.md) is a hand-written, tested sketch of
eventual generated model output over the reusable generic `ldapmodel` DAO. It
covers fluent indexed queries, materialized and streaming result paths, fixed
entry projection, schema cardinality validation, and explicit patch-based
updates. It intentionally does not add a generator or generator input format
yet.

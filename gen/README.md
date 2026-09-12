# LDAP schema and model generation

Arden's generator consumes one YAML definition and emits schema LDIF plus ordinary
Go model packages. The complete client example is [testdata/client.yaml](testdata/client.yaml).
It models `ipaOidcIdpClient`, including external FreeIPA attributes, the allocated
OID suffixes, query indexes, and application naming/type overrides.

From the Arden checkout:

```sh
go run ./cmd/gen -config gen/testdata/client.yaml \
  -out gen/internal -schema gen/testdata/client.generated.ldif
go run ./cmd/gen -config gen/testdata/client.yaml \
  -out gen/internal -schema gen/testdata/client.generated.ldif -check
go test ./gen ./ldapmodel ./cmd/gen
```

From a consuming module that depends on a generator-capable Arden revision:

```sh
go run github.com/wyattanderson/arden/cmd/gen \
  -config freeipa/schema.yaml -out internal/directory \
  -schema freeipa/schema/60ipa-oidc-idp.ldif
```

The output root receives `<package>/<lowercase model>_gen.go` for each model.
Either `-out` or `-schema` can be omitted. Paths are relative to the working
directory. `-check` reports missing/stale files without writing. Generation
refuses to replace handwritten files: when adopting existing schema LDIF,
compare the generated candidate with the existing definitions before replacing
it once. Subsequent runs recognize the generated header. Each file is replaced
atomically; a filesystem error can still leave a set of outputs partly updated,
so rerun generation and `-check` before committing. Removed models' old files are
not automatically deleted.

`gen.Parse([]byte)` and `gen.Generate(Config)` provide the same behavior in Go.
Generate returns `Result{Schema, Models}` without filesystem or network access.
Generated packages depend on Arden's runtime, not on the generator or YAML parser.

## Input and inference

Version 1 accepts camelCase keys only and rejects unknown fields, duplicate YAML
keys, anchors/aliases/merge keys, and multiple documents. The YAML is configuration;
it does not execute templates or fetch remote schemas.

- `schema.oidBases.attributes` and `.objectClasses` expand a single numeric
  `oid` suffix. A dotted OID is absolute. Allocations are explicit, permanent,
  and unrelated to declaration order. Names are checked case-insensitively;
  OIDs cannot be reused across owned attributes and classes.
- `schema.attributes` carries LDAP names, descriptions, `sup`, `syntax`, matching
  rules (`equality`, `ordering`, `substr`), and `singleValue`. Missing cardinality
  inherits from `sup`, otherwise it is multivalued. Attribute inheritance cycles
  and unresolved references are errors.
- `schema.objectClasses` carries `sup`, `kind` (`structural`, `auxiliary`, or
  `abstract`), `must`, and `may`. Membership is inherited; MUST wins when a
  selected class requires an attribute another class permits.
- `schema.external.attributes` supplies syntax and an explicit `singleValue`
  for existing server attributes; optional matching rules support indexed query
  declarations. These definitions are never emitted. External object classes
  are terminal references, such as `top`; their memberships are not discovered.
  Declare any needed application attributes explicitly in owned class membership.
- `schema.origin` becomes `X-ORIGIN`. Descriptions and origin strings are escaped
  for schema syntax; output is a single `cn=schema` LDIF record. Matching rules
  remain explicit: a syntax's Go representation does not determine comparison
  semantics. This is not a full server-schema compatibility validator.

Models specify `name`, `package`, `objectClasses`, and `namingAttribute` (the LDAP
attribute name). `constructor` defaults to the plural model name; `scope` defaults
to `children`, with `base` and `subtree` also supported. Base DNs remain runtime
arguments. All resolved classes are used for search filtering and creation.

Each MUST/MAY attribute becomes a typed descriptor and, by default, a projected
field. `objectClass` is managed by the runtime and excluded from descriptors.
`attributePrefix` strips an exact leading LDAP prefix; the first remaining letter
is capitalized. Multivalued attribute names are pluralized using simple English
suffix rules. Irregular words and preferred initialisms use a `name` override;
collisions fail generation. Output order is deterministic, sorted by LDAP name.

| Schema membership | singleValue | read | Field |
| --- | --- | --- | --- |
| MUST | true | requiredOne | T |
| MAY | true | optionalOne | *T |
| MUST | false | requiredMany | []T, at least one value |
| MAY | false | optionalMany | []T, zero or more values |

`overrides` is keyed by LDAP attribute name. Each entry may set `name`, `type`,
`codec`, or `read`. An explicit name is final and is not pluralized. `read: none`
keeps the descriptor for writes while omitting the field, projection selector,
and decoder. Overrides do not change LDAP schema; they express an application
contract that can be stricter or more tolerant than schema-derived defaults.

| Syntax alias (numeric OID also accepted) | Default Go type |
| --- | --- |
| directoryString, ia5String, numericString | string |
| boolean | bool |
| integer | int64 |
| octetString | []byte |
| dn | arden.LDAPDN |
| generalizedTime | time.Time |

Each syntax chooses its codec along with its type. For example, Directory String
requires nonempty valid UTF-8, Boolean accepts the LDAP `TRUE`/`FALSE` literals,
and Numeric String preserves leading zeros and spaces. Integer decoding rejects
overflow rather than truncating. `uint32` and `uint64` are available type
overrides; LDAP Integer itself is unbounded. DN codecs preserve UTF-8 text and
leave full DN validation/normalization to the server or application. Generalized
time supports UTC offsets and fractional hours/minutes/seconds, rejecting leap
seconds and precision not representable in nanoseconds. A custom codec can cover
representations outside these bounds.

For unknown syntaxes or custom Go types, provide `type` and `codec`. Types may
be named types, pointers, or slices; codecs are named values implementing
`ldapmodel.ValueCodec[T]`. Same-package symbols need no import. Qualified symbols
use the model's `imports` map, for example `imports: {custom: example.org/app/values}`,
`type: custom.Identifier`, and `codec: custom.IdentifierCodec`. Incompatible
type/codec pairs fail the consuming package's Go build. A `type` override to
another built-in type chooses that type's codec; `codec` can override it explicitly.

## Storage and custom behavior

The generated API is the same typed seam as the POSIX prototype:

```go
clients := ldapmodel.NewDAO(client, clientmodel.Clients(baseDN)).WithContext(ctx)
record, err := clients.Where(clientmodel.ClientIDIs("grafana")).One()

a := clientmodel.ClientAttributes
err = clients.Add(uuid,
    ldapmodel.Set(a.ClientID, "grafana"),
    ldapmodel.Set(a.Enabled, true),
    ldapmodel.Set(a.RedirectURIs, "https://grafana.example/callback"),
)
err = clients.Modify(record.DN, ldapmodel.Replace(a.Enabled, false))
```

`indexes.equality` declares deployed indexes and generates `<Field>Is` predicates.
It does not install indexes, enforce uniqueness, or change migrations. Predicate
encoding errors surface from terminal query methods before network access. No
panic or implicit arbitrary-filter API is generated. For fallible codecs this
also applies to typed assignments/changes. The shared DAO provides One, First,
All, and Stream lifecycle behavior. Delete uses `arden.Client.Delete` with the
entry DN. Administrative listing can be an explicit handwritten criterion.

Keep custom files next to generated files, or wrap the generated package:

1. Add methods on the generated type in a handwritten file in the same package.
2. Set `validate: validateClient` to call a handwritten `func(Client) error`
   after decoding. This applies to direct decoding and every DAO result path;
   errors are wrapped with entry identity and preserve `errors.Is`.
3. Validate creation/update intent in a handwritten repository before calling
   Add/Modify. The decode hook is not a mutation hook. Partial changes do not
   contain enough information to validate the resulting object without a read.

The [client validation example](internal/clientmodel/validation.go) adds a positive
maximum-authentication-age rule without editing generated output. The IdP keeps
its registration validation, secret hashing, immutable UUID allocation, and
public JSON response type in its handwritten `oidcclient` repository. Generated
records contain raw storage fields: do not expose them directly as HTTP/JSON
responses. Optional binary fields are `*[]byte`, and decoded binary values share
entry storage; the IdP adapter clones the secret verifier and redacts it from JSON.

## IdP handoff and migration boundary

In `ipa-oidc-idp`, `freeipa/schema.yaml` owns all existing schema definitions and
selects the Client model. `freeipa/schema/60ipa-oidc-idp.ldif` and
`internal/directory/clientmodel/client_gen.go` are generated. Use the consuming
repository's generation directive and drift test; commit the YAML and generated
outputs together. While developing across repositories, use a Go workspace
containing both the IdP and this Arden checkout. Before a release, pin an Arden
revision containing the generator/runtime changes; the IdP's earlier dependency
revision is insufficient.

Existing OIDs and object-class memberships must stay compatible with deployed
data. Generating desired schema is separate from planning upgrades: retain
append-only migrations, explicit data backfills, index provisioning, RBAC, and
the final model-version marker. Schema removals or incompatible changes are not
automatically converted into migrations. Server installation and replica testing
remain necessary before deploying a schema change.

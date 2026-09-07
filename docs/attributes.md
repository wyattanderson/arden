# Attribute collections and model I/O

`rfc4511.Attributes` is the shared representation for `SearchResultEntry`,
`AddRequest`, and `arden.Entry`. The root package aliases the type as
`arden.Attributes`. It holds attributes in insertion/wire order and indexes them
by a prepared `AttributeKey`.

## Lookup and mutation

```go
entry := arden.NewEntry("uid=alice,dc=example")
entry.Set("homeDirectory", "/home/alice")

attribute, present := entry.Attributes.Lookup("HOMEDIRECTORY")
// present is true; attribute.Type retains "homeDirectory".
// attribute.Values is the stored []rfc4511.AttributeValue, without a copy.

entry.Set("HoMeDiReCtOrY", "/srv/alice") // replaces the existing attribute
entry.Attributes.Delete("homedirectory")

for attribute := range entry.Attributes.All() {
    // Each attribute includes Type, Values, and Extensions.
    _ = attribute
}
```

Keys use `strings.ToLower`, sort options, and remove repeated options. Consequently
`cn;lang-en;lang-de` and `CN;LANG-DE;LANG-EN` have equal keys. Lookup uses the
complete description: `cn` is distinct from `cn;lang-en`. Schema aliases, numeric
OID/name equivalence, and attribute subtyping require schema knowledge and are
not resolved here. Construction assumes valid descriptions, consistent with the
existing packet-construction contract.

`Lookup` distinguishes an absent attribute from a present attribute with no
values, as returned by types-only searches. `Set` replaces equivalent
descriptions in place, retaining the new spelling and supplied values and
extensions. `Delete` preserves the remaining order. `All` returns
`iter.Seq[Attribute]`; callers must not structurally mutate during iteration.

Decoding creates the index as attributes arrive, rejects duplicate normalized
descriptions, and commits the collection only after the complete sequence
succeeds. Operation-specific value-count constraints are left to the caller or
server. No schema value matching or deduplication is performed.

The index is eager. If profiling shows that many decoded entries are never
inspected, it could become lazy behind this API. Such a change must retain the
concurrent-read contract; a first lookup cannot introduce unsynchronized writes.

## Ownership

The zero value is ready for use. Copies of an initialized collection share one
private backing object containing both the ordered slice and index. Appending
through one copy cannot leave another copy with a stale slice header. Copies of
a still-zero collection initialize independently, as with copying a nil map
before allocating it.

`Lookup` and `All` return attribute structs by value. Changing a returned `Type`
cannot corrupt the index. Their value and extension slices share storage:
replacing elements or modifying value bytes changes the collection. Assigning a
different slice to the returned struct does not replace the stored slice; call
`Set` to commit a replacement. `NewAttributes` copies the outer attribute slice
so later caller edits to attribute names cannot corrupt its index.

`Attributes.Clone` explicitly copies all mutable backing storage, including
value bytes. Immutable `UnknownField` payloads can remain shared. Concurrent
reads are supported while the collection and its shared values remain unchanged.

## Typed reads

`ldapmodel.NewAttribute[User]` binds a value codec to the model type and prepares
an immutable name and key together:

```go
homeDirectory := ldapmodel.NewAttribute[User]("homeDirectory", ldapmodel.StringCodec)
name := homeDirectory.Name()
key := homeDirectory.Key()

attribute, present := entry.Attributes.LookupKey(key)
value, err := ldapmodel.RequiredOne(homeDirectory, *entry)
```

`LookupKey` does not normalize or allocate. `RequiredOne` and `OptionalOne` check
raw cardinality before invoking `Attribute.Decode` on the single stored value.
Invalid cardinality therefore takes precedence over value-decoding errors.
There is no temporary raw or typed values slice. Multi-value `Attribute.Values`
allocates only its final `[]T`, plus whatever its codec requires.

## Typed writes and Add encoding

```go
entry := arden.NewEntry("uid=alice,dc=example")
entry.Set("objectClass", "top", "person", "posixAccount")
if err := homeDirectory.Set(entry, "/home/alice"); err != nil {
    return err
}
return client.Add(ctx, entry)
```

The write path is:

1. A typed `Attribute.Set` allocates the final `[]rfc4511.AttributeValue` and
   fills it with codec output. It commits only after all values encode
   successfully. There is no intermediate `[][]byte`, and codec bytes are shared.
2. The collection indexes the description once on insertion. Ordinary text
   `Entry.Set` likewise builds its final value slice directly. `Entry.SetBytes`
   converts the caller's outer `[][]byte` to the wire value slice while sharing
   byte storage. Call `Attributes.Set` with an existing `Attribute` to share its
   outer value slice as well.
3. `Client.Add` passes the collection directly into `AddRequest`. No attributes,
   values, or value bytes are copied by this conversion.
4. BER packet construction traverses the stored attributes directly and reserves
   child capacity for known batches. Attribute and Add packet construction group
   fixed children into one batch, avoiding intermediate child-slice growth.
5. BER serialization writes the final output. There is no cached entry encoding
   to invalidate when callers modify shared values. Text description/DN conversion
   and codec-required allocations remain; this is not an allocation-free encoder.

Keep an entry and its shared values unchanged until `Client.Add` returns. Decode
still owns retained bytes independently of the source BER input buffer.

The model-level `ldapmodel.Set(attribute, values...)` returns an opaque
`Assignment[M]` using the same encoder as `Attribute.Set`.
`DAO[M].Add(name, assignments...)` automatically supplies the model's naming
attribute and base object classes, checks every assignment, and inserts their encoded attributes directly
into the entry collection. This retains the final wire-value slices and codec
bytes without additional copies. Repeated assignments replace earlier values;
empty value lists, encoding errors, and class or naming overrides send no request.
Keep shared bytes unchanged until `DAO.Add` returns.

The naming codec encodes the raw string name once. Its UTF-8 output becomes both
the stored naming value and the escaped RDN value, following
[RFC 4514 section 2.4](https://www.rfc-editor.org/rfc/rfc4514.html#section-2.4).
Add creates an immediate child of the model's base DN; an empty base creates a
single-RDN DN. The naming descriptor must use a short LDAP attribute name without
options. Case and option variants of that name cannot be assigned during Add.
General schema alias/OID equivalence remains unresolved, as with attribute keys.

## Migration

- `ldapmodel.NewModel` now takes a base-class `[]string` in place of its filter
  argument. It copies the classes, requires all of them in search filters, and
  supplies them during Add. Declare a nonempty list. Model attributes used for
  creation do not have to appear in its read projection.
- Pass a naming `Attribute[M, string]` after the base classes in `NewModel`.
  Replace `dao.Add(fullDN, Set(naming, name), ...)` with `dao.Add(name, ...)`;
  the model constructs the DN and supplies the naming attribute. Names must not
  be pre-escaped. `Client.Add` still accepts entries with explicit DNs, and
  `DAO.Modify` still takes an existing entry's DN.
- `Attributes: []Attribute{...}` becomes `Attributes: NewAttributes(...)`.
- `len(entry.Attributes)` becomes `entry.Attributes.Len()`.
- `range entry.Attributes` becomes `range entry.Attributes.All()`.
- `entry.RawValues(name)` is removed; use `entry.Attributes.Lookup(name)` and
  the returned attribute's `Values`. This shares the outer values slice too.
- Typed descriptors and codecs have moved from `schema` into `ldapmodel`.
  `Attribute[T]` becomes `Attribute[Model, T]`; use
  `ldapmodel.NewAttribute[Model](name, codec)` to bind the model type and prepare
  the immutable name and key together. Access the name with `Name()`.
- Replace `UserPatch` and `DAO.Update` with `DAO.Modify(dn, changes...)`, using
  `ldapmodel.Add`, `Delete`, and `Replace` with typed attributes. Changes execute
  in caller order; repeated operations on an attribute are retained.
- Copy an entry's collection with `Clone` when independent mutation is needed.

## Verification

Tests cover normalization, option ordering, shared copies through collection
growth and deletion, clone independence, types-only attributes, duplicate
rejection, atomic decode and typed encode failures, unknown fields, source-byte
ownership, scalar cardinality, and sharing through search conversion and
`Client.Add`. Root tests pass with the race detector; FreeIPA tests exercise the
refactored descriptors against this checkout through its Go workspace.

The FreeIPA benchmarks cover model decoding with eight attributes and with 32
unused attributes preceding them, BER unmarshal plus direct model decoding,
`Client.Get` plus model decoding using an in-memory response stream, and typed
model fields through entry construction and AddRequest serialization. The
encoding benchmark excludes network/executor overhead; `Client.Add` sharing is
verified separately by a storage-identity test.

September 7, 2026 measurements on Go 1.27.0, darwin/arm64, Apple M2 Max:
identical benchmark source on the original checkout and refactored checkout,
three runs each. Times below are medians; allocation counts are stable across
runs. Timings are illustrative microbenchmarks, not network performance claims.

| Path | Time before → after | Bytes/op before → after | Allocations/op before → after |
| --- | ---: | ---: | ---: |
| DecodeUser, eight attributes | 438 → 234 ns | 392 → 136 | 22 → 9 |
| DecodeUser, 32 unused attributes first | 1,139 → 249 ns | 392 → 136 | 22 → 9 |
| Unmarshal + direct model decoding | 4,559 → 4,846 ns | 7,712 → 7,944 | 156 → 153 |
| Client.Get + DecodeUser | 5,921 → 6,008 ns | 10,608 → 10,248 | 191 → 187 |
| Model → entry → AddRequest encoding | 3,595 → 3,434 ns | 6,016 → 4,448 | 74 → 58 |

Prepared collection lookup separately measured zero allocations. The eager index
adds work and memory during unmarshalling, while direct model decoding removes
scans and temporary containers. The full client path also removes its previous
attribute-slice copy: it allocates less and takes approximately the same time
for this small entry. Larger descriptions, different field positions, and
repeated reads can change the balance.

Run the model benchmarks from `freeipa` with:

```sh
go test ./posixaccount -run '^$' \
  -bench 'Benchmark(DecodeUser|UnmarshalDecodeUser|ClientGetDecodeUser|ModelEntryAddEncoding)$' \
  -benchmem -count=3
```

Root lint is clean. FreeIPA lint retains six findings also present on the
original checkout: import formatting in `posixaccount/example_test.go`, the
`clear` helper name in `posixaccount/patch.go`, and a missing package comment
plus three unused declarations in `cmd/whoami/config.go`.

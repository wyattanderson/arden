# Generated POSIX account API sketch

`posixaccount` is hand-written golden output for discussing an eventual model
generator. It is not a generator input format and no file claims to be
generated yet.

The intended caller-level shape is:

```go
users := ldapmodel.NewDAO(
    client,
    posixaccount.Users("cn=users,cn=accounts,dc=arden,dc=test"),
).WithContext(ctx)

alice, err := users.Where(posixaccount.AccountNameIs("alice")).One()

accounts, err := users.Where(
    posixaccount.UIDNumberIs(1200),
    posixaccount.GIDNumberIs(1200),
).All() // fully materialized; no Close required

stream, closeStream, err := users.Where(
    posixaccount.GIDNumberIs(1200),
).Stream()
defer closeStream()
for stream.Next() {
    account := stream.Value()
    // use account
}
err = stream.Err()

var patch posixaccount.UserPatch
patch.SetLoginShell("/bin/zsh")
patch.ClearGECOS()
patch.ReplaceEmailAddresses("alice@example.test")
err = users.Update(alice.DN, patch)
```

## Contracts being tested

- `ldapmodel.DAO[T]` is generic infrastructure. Generated packages publish a
  `Model[T]`, criteria, decoder, and patch rather than a type-specific DAO.
- A DAO borrows an `*arden.Client` and does not own or close its connection or
  pool. `WithContext` returns a request-scoped copy in the style of GORM.
- A model is a fixed projection, not a live object. Required single-valued
  attributes are Go values, optional single-valued attributes are pointers,
  and multi-valued attributes are slices.
- Decoding validates schema cardinality instead of silently taking the first
  value. It keeps the entry DN in errors and does not include attribute values.
- `Where(...).One()` replaces generated lookup methods. It uses a size limit of
  two; zero, one, and multiple matches are distinct outcomes.
- Search requires at least one typed `Criterion[User]`. The generated query
  vocabulary is the place where application metadata declares usable indexes;
  the DAO does not accept an arbitrary generic LDAP filter.
- `All`, `One`, and `First` always close the underlying LDAP search before they
  return. `Stream` is the opt-in lifecycle path and returns its close function
  separately so ownership is visible at the call site.
- Updates are explicit patches. A patch sends one Modify, never performs an
  implicit read or retry, and rejects an empty change set.
- `DAO[T].Update[P Patch[T]]` uses Go 1.27 generic methods, so a concrete patch
  type is inferred while its model type must still match the DAO.
- Required fields can be replaced but not cleared. Optional fields can be set
  or cleared. Multi-valued fields are replaced as a set in this first sketch.
- `uid` is absent from `UserPatch`: an account rename can affect the RDN and
  needs a separate contract around ModifyDN.

## Provisional choices

- `uid`, `uidNumber`, and `gidNumber` are the example indexed equality
  criteria. Before generation, index declarations need an explicit source of
  truth: generator configuration, a captured 389 DS index configuration, or a
  deployment profile. LDAP schema alone does not say which attributes a server
  indexes.
- The model currently selects a fixed projection and a fixed page size of 100.
  Projection variants and search options should be added only after a real
  caller needs them.
- POSIX numeric identifiers use `uint32`. This is an application mapping, not a
  general representation of LDAP's unbounded Integer syntax.
- The small generated decode and patch helpers may eventually move into
  `schema` if a second model proves that doing so removes meaningful repeated
  code.
- Optimistic concurrency is not present. A future version assertion or other
  assertion control should be explicit on `Update`, rather than hidden inside
  the DAO.

## Questions to answer with the next model

1. Should generated packages expose typed attribute descriptors as one
   `UserAttributes` namespace, as individual package variables, or only keep
   them internal?
2. Should search predicates support only conjunction, or is a generated
   expression type for controlled AND/OR grouping worth the extra API?
3. Should update keep taking a DN, or should a small immutable `Ref[T]` carry
   identity and an optional concurrency token?
4. Do callers need partial projections, and if so should the result type encode
   which fields were loaded rather than putting pointers on every field?

# Generated POSIX account API sketch

`posixaccount` is hand-written golden output for discussing an eventual model
generator. It is not a generator input format and no file claims to be
generated yet.

## Generated code and library boundary

[`user.go`](user.go) is the complete, single-file prototype of generated output.
It contains only model declarations and wiring: `User`, attribute-to-codec
mappings, the projection, base object classes and naming attribute, decoding cardinalities,
indexed predicates, and model-specific typed attribute descriptors.
Tests and usage examples remain in separate `_test.go` files.

Reusable implementation belongs to Arden:

- `ldapmodel` owns `Attribute[M, T]`, value codecs (including `Uint32Codec`),
  equality encoding, cardinality helpers, typed assignments and changes, and the generic DAO
  and result-set lifecycle. `Attribute.MustEqual` supports predicates whose
  codecs cannot fail to encode; fallible codecs use `Attribute.Equal`.

For another model, a generator emits different attribute mappings, predicates,
and a decoder in the same shape as `user.go`; it does not emit codecs, change
encoding, patch types, or field-specific mutation methods.

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

err = users.Modify(alice.DN,
    ldapmodel.Replace(posixaccount.UserAttributes.LoginShell, "/bin/zsh"),
    ldapmodel.Delete(posixaccount.UserAttributes.GECOS),
    ldapmodel.Add(posixaccount.UserAttributes.EmailAddresses, "other@example.test"),
    ldapmodel.Delete(posixaccount.UserAttributes.EmailAddresses, "old@example.test"),
    ldapmodel.Replace(posixaccount.UserAttributes.UIDNumber, 1201),
)

a := posixaccount.UserAttributes
err = users.Add("bob",
    ldapmodel.Set(a.CommonName, "Bob Example"),
    ldapmodel.Set(a.Surname, "Example"),
    ldapmodel.Set(a.UIDNumber, 1201),
    ldapmodel.Set(a.GIDNumber, 1200),
    ldapmodel.Set(a.HomeDirectory, "/home/bob"),
    ldapmodel.Set(a.EmailAddresses, "bob@example.test"),
)
```

## Contracts being tested

- `ldapmodel.DAO[T]` is generic infrastructure. Generated packages publish a
  `Model[T]`, criteria, decoder, and attributes rather than a type-specific DAO.
- A DAO borrows an `*arden.Client` and does not own or close its connection or
  pool. `WithContext` returns a request-scoped copy in the style of GORM.
- A model is a fixed projection, not a live object. Required single-valued
  attributes are Go values, optional single-valued attributes are pointers,
  and multi-valued attributes are slices.
- The model declares base object classes, copied by `NewModel`. Searches AND
  together an `objectClass` equality for each class with caller criteria; Add
  supplies the same classes automatically. Entries with additional classes can
  still match. This user model declares `top`, `person`, `organizationalPerson`,
  `inetOrgPerson`, and `posixAccount`.
- The model declares `UserAttributes.AccountName` as its naming attribute.
  `Add("alice", ...)` creates `uid=alice,<baseDN>` and supplies `uid` automatically.
  The naming codec runs once, and its output is shared with the initial attribute
  and escaped for the RDN using RFC 4514. Pass an unescaped name, never a DN.
  The base is both the search base and the parent for new entries; Add always
  creates an immediate child. Modify still takes an existing entry's explicit DN.
  Use `Client.Add` for creation elsewhere in the tree.
- Naming is a single `Attribute[User, string]` with a short LDAP attribute name
  and a codec that produces UTF-8. Add rejects missing or invalid naming metadata,
  encoding errors, and attempts to assign the naming attribute, including case
  and option variants. Schema alias/OID equivalence is not resolved by attribute
  keys. No multi-valued RDN or alternate-parent API is provided.
- Attributes can extend beyond the read projection. `UserAttributes.Surname`
  maps to `sn` for creation and modification but adds no field to `User` and
  does not change its search attribute selection or decoder.
- `Set` returns an opaque `Assignment[M]`; `DAO[M].Add` accepts assignments for
  that model, with mixed value types. Assignments and modification changes
  cannot be interchanged. No generated creation struct or entry builder is needed.
- Assignments use the same encoder as `Attribute.Set`, encoding immediately
  into the final wire-value slice and retaining codec-produced bytes. Errors
  surface from Add before any request, including errors in overwritten assignments.
  Keep shared bytes unchanged until Add returns; the caller's outer values slice
  is not retained.
- Repeated assignments replace previous values for equivalent normalized
  descriptions, preserving the first insertion position, as `Attributes.Set`
  does. Omit an assignment to omit an attribute. Empty value lists are rejected;
  an explicit numeric zero or empty string remains a supplied value.
- Add sends one LDAP Add and returns its error, with no read-back or retry.
  Invalid assignments, missing base classes, and attempts to assign `objectClass`
  (including its OID or optioned forms) send no request. Required attributes and
  schema cardinality remain server-validated, including Add with no assignments.
  Optional object classes are not supported yet.
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
- `Attribute[M, T]` carries both model and value types. `Add`, `Delete`, and
  `Replace` infer both from the descriptor and accept only values of T. They
  return opaque `Change[M]` values, so `DAO[M].Modify` accepts mixed value types
  while rejecting changes belonging to another model at compile time.
- Changes encode immediately and retain any encoding error until `Modify`.
  All changes are checked before sending one request. Empty change sets,
  zero changes, missing attribute names, and encoding errors send no request.
- Changes retain codec-produced bytes. String values are encoded into fresh
  bytes; `BytesCodec` shares the supplied bytes, which callers must keep
  unchanged until `Modify` returns. The caller's outer values slice is not
  retained. There is no implicit read or retry.
- Modify preserves every operation in caller order, including repeated
  operations on the same attribute. It does not coalesce replacements or sort
  changes into generated field order.
- `Delete` with no values deletes the entire attribute; `Replace` with no
  values also removes it. The mutation API leaves requiredness, cardinality,
  and operation validity to the LDAP server. It does not restrict `AccountName`,
  but changing an RDN still requires an explicit ModifyDN operation.
- The variadic API uses generic functions and needs no separate patch or
  changeset builder. Callers can accumulate a `[]ldapmodel.Change[User]` and
  pass it to `Modify` with `changes...`.

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
- Optimistic concurrency is not present. A future version assertion or other
  assertion control should be explicit on `Modify`, rather than hidden inside
  the DAO.

## Questions to answer with the next model

1. Should generated packages expose typed attribute descriptors as one
   `UserAttributes` namespace, as individual package variables, or only keep
   them internal?
2. Should search predicates support only conjunction, or is a generated
   expression type for controlled AND/OR grouping worth the extra API?
3. Should Modify keep taking a DN, or should a small immutable `Ref[T]` carry
   identity and an optional concurrency token?
4. Do callers need partial projections, and if so should the result type encode
   which fields were loaded rather than putting pointers on every field?

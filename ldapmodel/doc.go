// Package ldapmodel provides generic data-access contracts for generated or
// handwritten LDAP models.
//
// Model packages describe projections, indexed criteria, decoders, and typed
// patches. This package supplies the reusable DAO, fluent result set, cardinality
// helpers, replacement state and encoding, and stream lifecycle; model packages
// do not need their own DAO types. Package schema supplies attribute descriptors,
// value codecs, and typed filter encoding.
package ldapmodel

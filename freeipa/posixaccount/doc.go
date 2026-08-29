// Package posixaccount is a hand-written design sketch for code that may
// eventually be generated from LDAP schema and application metadata.
//
// The package deliberately contains four generated concerns:
//
//   - User is the application-facing projection of one LDAP entry.
//   - UserAttributes contains the typed LDAP attribute descriptors.
//   - Typed criteria expose only searches known by application metadata to be
//     backed by an index.
//   - UserPatch exposes legal Modify operations without treating a loaded User
//     as an object whose fields are implicitly dirty.
//
// Package ldapmodel supplies the reusable generic DAO and result-set lifecycle;
// there is no generated User-specific DAO.
//
// This package is executable design material, not generated output. Keeping it
// hand-written for now lets the public shapes settle before a generator input
// format or template becomes part of the project.
package posixaccount

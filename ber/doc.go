// Package ber implements a small, bounded BER runtime for LDAP. It supports
// only definite lengths, gives typed codecs a cursor over caller-owned bytes,
// and frames complete top-level values from a stream. It is intentionally not
// a generic ASN.1 object-tree library.
package ber

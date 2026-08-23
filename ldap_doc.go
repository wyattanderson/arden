// Package arden provides an LDAPv3 client with string-first directory
// operations, concurrent response routing, and public extension contracts.
// Ordinary callers construct a Client over a connection or pool lease. Binary
// attributes use Entry.SetBytes and RawValues.
//
// The protocol package defines transport-neutral execution contracts; rfc4511
// provides LDAPv3 wire models and bounded BER codecs. Extensions can compose
// those packages and execute operations through protocol.Executor.
package arden

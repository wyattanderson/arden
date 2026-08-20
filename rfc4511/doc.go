// Package rfc4511 provides hand-authored, byte-oriented LDAPv3 wire values,
// codecs, constants, filters, results, and standard operation declarations.
//
// The package is intentionally not a generic LDAP client API. Its values use
// the same public BER and operation contracts available to external LDAP
// extensions, and connection I/O remains in the parent arden package.
//
// To add a control, implement ber.Marshaler to append one complete Control
// BER value and pass it in arden.Operation.Controls. To add a filter, implement
// Filter with a context-specific identifier and one complete encoding. To add
// an extended operation, implement arden.ProtocolOperation and declare its
// response identifiers with arden.NewResponsePattern. No registration is
// required or available. A routed arden.Response is decoded in application
// code with Response.UnmarshalProtocol and the extension's own
// ber.Unmarshaler.
package rfc4511

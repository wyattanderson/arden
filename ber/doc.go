// Package ber implements a small BER runtime for LDAP. Encoding uses packets
// and constructed envelopes. Decoder provides scoped, first-error typed reads,
// alternate identifiers, and embedded components over a bounded Reader. Reader
// exposes borrowed input views; Decoder's octet reads return owned values.
// The framer reads complete top-level values from a stream. Only definite
// lengths are supported.
package ber

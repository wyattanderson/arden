// Package ber implements a small BER runtime for LDAP. Encoding uses packets
// and constructed envelopes; decoding provides a bounded cursor over
// caller-owned bytes and frames complete top-level values from a stream. Only
// definite lengths are supported.
package ber

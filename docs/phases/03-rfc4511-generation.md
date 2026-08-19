# Phase 3: RFC 4511 generation

## Goal

Generate readable Go wire types and constants from pinned RFC material while
keeping semantic exceptions explicit and reviewable.

## Inputs

- RFC 4511 Appendix B ASN.1 module.
- RFC 4511 Appendix A result codes.
- Published RFC 4511 errata.
- A small handwritten annotation file for Go names, open types, response
  patterns, constraints not expressible by the supported ASN.1 subset, and
  source locations.

Store normalized source inputs and hashes in the repository. Generation must
not access the network, and consumers must not run the generator to build the
library.

## Generator stages

Follow a deliberately visible pipeline similar to mature ASN.1 compilers:

1. Extract or read the pinned ASN.1 source.
2. Parse the LDAP-specific ASN.1 subset into an AST.
3. Resolve names and normalize implicit tags, choices, sequences, defaults,
   constraints, and extensibility.
4. Merge reviewed annotations.
5. Validate the intermediate representation.
6. Generate formatted Go and fixture metadata.

Each stage should have a printable or testable representation. Do not silently
repair unsupported ASN.1 constructs.

## Generated output

- Distinct wire types for protocol concepts even when several encode as OCTET
  STRING.
- Application tag and result-code constants with stable Go names.
- Marshal and unmarshal methods using the public BER contracts.
- Choice representations that preserve unknown extensible alternatives.
- Unknown trailing sequence components where required.
- Standard declarative response patterns and safe operation labels.
- String methods only for enum/debug names; wire values remain bytes.
- Source comments identifying RFC and section.

Generated request objects do not perform I/O and do not acquire transport
policy. Helpers may pair an object with its standard response pattern without
making the object itself connection-aware.

## Testing

- Golden generated source and deterministic regeneration.
- One positive and multiple negative vectors for every generated type family.
- Full RFC request/response tag and result-code inventory tests.
- Round trips for all standard operation envelopes.
- Unknown enum, choice, control, and trailing-extension preservation.
- Cross-check selected encodings with asn1c, go-ldap, OpenLDAP tooling, and
  packet captures from 389 DS.
- Fuzz generated decoders independently from the generic BER reader.

When another implementation disagrees with the generator, reduce the case to a
small BER fixture, check the RFC and errata, inspect 389 DS, and record the
chosen behavior beside the regression test.

## Deliverables

- Pinned specification inputs and provenance.
- ASN.1 subset parser, normalization IR, annotations, and generator.
- Generated RFC 4511 wire package.
- Reproducibility check suitable for CI.
- Documented procedure for adding another RFC-defined control or extension.

## Exit criteria

A clean checkout builds without generation. Regeneration is deterministic.
Every RFC 4511 protocol operation can be represented, encoded, decoded, and
associated with a response pattern without a generic string API.


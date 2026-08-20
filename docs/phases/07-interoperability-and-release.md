# Phase 7: interoperability and base release

## Goal

Turn the RFC 4511 foundation into a dependable personal-library release against
389 Directory Server and FreeIPA without expanding it into a general LDAP SDK.

## Test environments

- A lightweight scripted TLS peer for deterministic protocol failures.
- A supported 389 DS container or local instance for routine integration.
- A FreeIPA environment for topology and real compatibility tests.
- Optional OpenLDAP tools as an independent client/codec oracle.

Pin environment versions in CI configuration or test documentation. Keep most
tests hermetic and fast; server suites should exercise interoperability rather
than duplicate every unit test.

## External test research

Review, with revision links:

- go-ldap tests for controls, malformed responses, timeouts, and concurrent
  message handling.
- python-ldap and OpenLDAP tests for reconnect, result delivery, TLS, and
  protocol edge cases.
- Independent BER fixtures for constraints and malformed encodings.
- 389 DS `dirsrvtests` and server source for Bind, Abandon, controls, referrals,
  limits, disconnects, and pipelining.
- FreeIPA tests for replica-specific operations and server selection.

Convert findings into small behavior-focused cases. Do not wholesale import a
suite. Record provenance and licensing for every adapted fixture.

## Compatibility matrix

Exercise at least:

- TLS verification and certificate rotation behavior.
- Anonymous/minimal ordinary authentication needed by tests.
- Unary operations through hand-authored RFC wire objects.
- Search-shaped streaming responses, referrals, and intermediates.
- Controls with absent, empty, unknown, and critical values.
- Large binary attribute values and configured size limits.
- Drain races and Abandon-and-tombstone behavior.
- Notice of Disconnection and abrupt server restart.
- Concurrent operations across one and several connections.
- Exact endpoint routing in a replicated topology.

RFC 3909 Cancel remains optional. If research shows clear 389 DS support and a
real need, write a separate scoped plan using the setup profile seam. Do not
delay the base release for it.

## Review requirements

- Run unit, race, fuzz regression, and integration checks.
- Audit goroutine, buffer, and connection ownership.
- Audit errors and observability output for credential/data leakage.
- Confirm every default resource limit is documented.
- Confirm connection ambiguity never triggers an implicit retry.
- Confirm the public API contains no generic string-based directory operation.
- Confirm examples use the hand-authored RFC layer or typed binary application
  layers above core.
- Remove speculative interfaces that have no caller or test.

## Deliverables

- Reproducible 389 DS integration environment.
- Documented FreeIPA test procedure.
- Compatibility matrix with known deviations.
- Examples for a custom unary operation, streaming operation, endpoint pinning,
  and tracing.
- Base module release notes and API stability statement.

## Exit criteria

The acceptance criteria in `PROJECT_PLAN.md` pass, known compatibility choices
are documented with evidence, and the base library is useful without GSSAPI or
generic LDAP CRUD helpers.

# Rust Core Unit Tests

Use this directory for the smallest deterministic tests around the Rust core's current logic.

Priority targets:

- blob header parsing
- canonical CBOR validation
- fixed-length byte-string decoding
- signature verification
- time-window authorization

Recommended first files:

- `test_policy_blob.md` or Rust unit tests for parser cases
- `test_canonical_cbor.md` or Rust unit tests for canonical/non-canonical fixtures
- `test_authz.md` or Rust unit tests for time-window boundary behavior

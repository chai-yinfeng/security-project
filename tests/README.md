# Tests

- `unit/rust_core/`: Rust-side correctness tests for blob parsing, canonical CBOR, signature verification, and authorization logic
- `integration/pipeline/`: end-to-end checks for issuance, embedding, host/core linking, and demo execution
- `security/tamper/`: negative tests for malformed blobs, policy tampering, rebinding attempts, and measurement drift

## Minimal Test Set For Current Demo Stage

The minimum useful test set for the current implementation is:

- blob parser accepts the current `SLC1 + version + len + cbor + signature` format and rejects malformed length or magic
- canonical CBOR validation accepts the issuer-produced form and rejects reordered or differently encoded equivalents
- signature verification succeeds with the generated issuer key and fails on modified policy bytes
- runtime measurement is stable across patch-and-resign for the current executable model
- host entry denies on verification failure and reaches the protected path on a valid demo binary
- profile-then-issue flow produces a target-specific runnable binary
- malformed target profiles are rejected during issue
- payload capability denies when the runtime device key differs from the key used during issuance
- signed-but-invalid protected payload ciphertext fails at runtime
- loader/debugger/code-signature runtime constraints deny expected negative paths

## Broader Coverage Goal

The fuller plan should cover both:

- embedded-policy and executable-image integrity checks
- authorization behavior after successful verification

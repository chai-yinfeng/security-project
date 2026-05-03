# Tamper And Negative Tests

Use this directory for negative-path tests against the current implementation.

Priority targets:

- wrong magic
- wrong blob version
- wrong declared CBOR length
- non-canonical CBOR map ordering
- signature mismatch
- device binding mismatch
- executable binding mismatch
- expired policy
- measured `__TEXT` content tampering after re-signing
- runtime-constraint violation
- debugger/instrumentation simulation

Keep these tests aligned with the shipped Mach-O section design. The tests intentionally rebuild the shared artifact serially; do not run these shell scripts in parallel unless the build pipeline is first parameterized with per-test artifact directories.

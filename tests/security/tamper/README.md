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

Keep these tests aligned with the current demo implementation rather than the future Mach-O section design.

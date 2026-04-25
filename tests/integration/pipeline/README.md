# Pipeline Integration Tests

Use this directory for end-to-end tests around the current demo pipeline.

Priority targets:

- issuer script generates a valid blob
- public-key sync reaches the Rust build
- build script produces a runnable demo binary
- final binary reaches the protected path on the issuing machine
- modified blob or modified executable causes denial

Recommended first checks:

- one shell-level smoke test for `scripts/build_pipeline.sh`
- one tamper-after-build negative test

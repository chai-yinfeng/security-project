<img width="1800" height="1100" alt="License Architecture" src="https://github.com/user-attachments/assets/e9b762ca-9ae4-4dc4-887b-8d4ca6cd3ceb" /># Architecture

## Design Summary

The baseline system uses a Rust license core linked as a static library into a C toy host application. The host application must call the license core before entering the protected application path. The license core parses a canonical CBOR license, verifies an Ed25519 signature with an embedded public trust anchor, evaluates policy, and returns a minimal allow/deny decision through a C ABI.

The prototype is intentionally portable and software-first. TPM, TEE, OS keychain, measured boot, and code-signing support are documented as enhanced deployment options rather than first-version dependencies.

## High-Level Flow

```text
Untrusted license file
        |
        v
C host application entry wrapper
        |
        v
Rust C ABI boundary
        |
        v
Rust license core
  - canonical CBOR parser
  - Ed25519 verifier
  - policy engine
  - fail-closed decision logic
        |
        v
ALLOW or DENY
        |
        +--> DENY: exit before protected code
        |
        +--> ALLOW: enter protected application path
```




## Component Responsibilities

### C Toy Host

- simulates an application that is compiled together with the license checker
- receives the license path and product id
- calls the Rust license core through a stable C ABI
- exits on deny
- enters `protected_main()` only after allow
- contains no license parsing, signature verification, or policy logic

### Rust FFI Boundary

- exposes a minimal C ABI to the host
- treats null pointers, invalid UTF-8, unreadable files, and oversized inputs as deny
- does not let Rust panics unwind into C
- does not expose internal parser or crypto errors through the production decision API
- avoids cross-language heap ownership in the first prototype

Initial C-facing API:

```c
typedef enum {
    LICENSE_DENY = 0,
    LICENSE_ALLOW = 1
} license_decision_t;

license_decision_t license_check_file(
    const char *license_path,
    const char *product_id
);
```

Optional later API:

```c
license_decision_t license_check_bytes(
    const unsigned char *license_buf,
    unsigned long license_len,
    const char *product_id
);
```

### Rust License Core

- decodes and validates canonical CBOR
- rejects malformed, ambiguous, duplicated, missing, oversized, or non-canonical fields
- verifies Ed25519 signatures using `ed25519-dalek`
- checks product id, feature flags, issue time, expiration time, license id, and version
- returns a short-lived allow/deny result
- provides richer internal errors only for tests and diagnostics

## License Format

The baseline license format is canonical CBOR. Canonical encoding is required so that the signed payload has one unambiguous byte representation.

Minimum fields:

- `format_version`
- `license_id`
- `product_id`
- `features`
- `issued_at`
- `expires_at`
- `signature_algorithm`
- `signature`

Rules:

- `signature_algorithm` is Ed25519 for the baseline.
- the Ed25519 signature covers the canonical CBOR payload excluding the `signature` field
- duplicate fields are rejected
- missing required fields are rejected
- unknown critical fields are rejected
- unsupported `format_version` values are rejected
- field sizes are bounded
- time fields use a single documented representation

Optional future fields:

- `device_binding`
- `customer_id`
- `license_tier`
- `max_application_version`
- `revocation_epoch`
- issuer metadata

Device binding is explicitly not part of the first prototype because local device identifiers are weak without additional platform support.

## Build and Linking Model

The baseline build uses Cargo for the Rust license core and a Makefile for the top-level build and C host integration.

Planned layout:

```text
src/license_core/     Rust crate built as a static library
src/app_integration/  C toy host application
include/              C ABI header
scripts/              build, test, and license-generation helpers
tests/                Rust and integration tests
eval/                 evaluation harnesses and benchmarks
```

The Rust library is statically linked into the C host for the baseline because the assignment describes a checker compiled together with an application. Dynamic linking is treated as an optional extension and additional attack surface.

## Error and Logging Policy

- production-facing API returns only allow or deny
- internal detailed errors are allowed in Rust unit tests
- logs must not include private issuer material, raw signatures beyond short identifiers, or unnecessary license payload details
- all unexpected states return deny
- debug bypasses and environment-variable allow paths are forbidden in release builds

## Software Attack Defenses

- Rust handles parser, verification, and policy logic
- C host is kept thin and calls a narrow decision API
- canonical CBOR avoids ambiguous serialization
- Ed25519 public-key signatures avoid storing issuer secrets on the client
- fail-closed behavior is mandatory for every error
- field sizes and string lengths are bounded
- compiler hardening and sanitizer builds are used for C integration code
- tests cover malformed input, tampering, expired licenses, wrong product ids, and FFI misuse

## Microarchitectural Security Principles

### Avoid Client-Side High-Value Secrets

The client stores only the Ed25519 public key. The private signing key never appears in the protected application or license checker. This reduces the impact of timing, cache, or speculative leakage from the client.

### Avoid Secret-Dependent Behavior

The checker should not use license-controlled or secret values as array indices, pointers, or table selectors. Cryptographic verification is delegated to a reviewed library.

### Reduce Authorization Transient Risk

The host should not touch protected data before the allow decision. Architecture-specific speculation barriers at the authorization boundary may be evaluated as an optional mitigation.

### Treat Rowhammer as Platform-Dependent

The baseline prototype will not attempt real Rowhammer exploitation. Instead, it will use fault-injection simulation and analysis to evaluate whether corrupted license bytes or corrupted decision state fail closed. Platform-level Rowhammer mitigations such as ECC, TRR, OS isolation, and memory allocation policy are documented as assumptions or enhanced deployment requirements.

## Enhanced Deployment Options

- OS code signing to make binary patching harder
- measured boot or TPM-backed attestation to bind execution to an expected binary
- TEE-based checker isolation
- OS keychain or platform keystore for deployment-specific secrets
- remote license validation for revocation or high-value products
- architecture-specific speculation fences at the decision boundary

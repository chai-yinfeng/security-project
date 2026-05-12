# Final Checkpoint

This document records the current final implementation state, how to build it, what is covered by tests, and which attack classes are outside the intended boundary.

## Current Build Flows

There are two supported build/issue flows.

### Local Demo Flow

Command:

```bash
./scripts/build_pipeline.sh
```

This flow builds and issues for the current machine. It uses:

- local `IOPlatformUUID`
- local macOS Keychain device secret
- or `COMS6424_DEVICE_KEY_HEX` when deterministic automation is needed

The script remains compatible with the current Keychain/profile changes because `scripts/issue_license.py` still supports the local path when `--device-profile` is omitted.

### Target Profile Flow

Commands:

```bash
# Target machine
./scripts/profile_device.py --out artifacts/device_profiles/alice.json

# Issuer machine
./scripts/issue_for_device.sh artifacts/device_profiles/alice.json alice_demo
```

This is the intended flow for issuing a complete binary to another user. The profile contains:

- `profile_schema_version`
- `product_id`
- `platform`
- `device_id`
- `device_fingerprint_hash`
- `device_payload_key_material`

It does not contain the raw Keychain secret. The issuer uses `device_payload_key_material` to encrypt the protected payload for that target, then ships the finished Mach-O executable in `artifacts/final/`.

## Implemented Features

### Mach-O Embedded Policy

- The signed license is embedded in the Mach-O `__TEXT,__license` section.
- `scripts/issue_license.py` locates and patches that section.
- Runtime code reads the current executable and extracts the embedded section instead of relying on a separate license blob.

### Signed Canonical Policy

- Policy blobs use `SLC1 + version + policy_len + canonical_cbor + Ed25519 signature`.
- Rust decodes CBOR, validates schema shape, re-encodes canonical CBOR, and rejects non-canonical encodings.
- The public issuer key is synchronized into Rust during issuance.

### Runtime Binding

Runtime verification binds the policy to:

- platform: macOS
- architecture: Apple Silicon ARM64
- device fingerprint hash
- selected-section executable measurement
- signed validity window
- runtime constraints

### Executable Measurement

The executable binding uses selected Mach-O sections rather than whole-file hashing. Measured sections include stable code and read-only regions such as:

- `__TEXT,__text`
- `__TEXT,__stubs`
- `__TEXT,__cstring`
- `__TEXT,__const`
- unwind/exception metadata when present
- selected `__DATA_CONST` sections

The license section and code-signature data are intentionally excluded so the binary can be patched with a license and then re-signed.

### Runtime Constraints

The signed policy can require:

- debugger denial via macOS traced-process flag plus deterministic test hook
- DYLD loader environment denial
- valid code signature via `codesign --verify --strict`

### Keychain-Backed Device Key

The device UUID is treated as public binding material, not a secret. Payload capability derivation uses:

- macOS Keychain per-product 256-bit random secret
- `IOPlatformUUID`
- `product_id`

Tests can use `COMS6424_DEVICE_KEY_HEX` for deterministic automation.

### Protected Payload Capability

After license verification, Rust derives a session capability and decrypts three protected payload blocks. The payload uses:

- HKDF-SHA256 for key derivation
- ChaCha20-Poly1305 for encryption and authentication
- associated data binding product id, license id, executable hash, block id, schema version, payload schema version, and chain hash
- plaintext-dependent chaining:

```text
K1 = HKDF(session_key, block1 || initial_chain)
P1 = AEAD_DEC(K1, C1, AD1)

K2 = HKDF(session_key, block2 || H(P1 chain state))
P2 = AEAD_DEC(K2, C2, AD2)

K3 = HKDF(session_key, block3 || H(P2 chain state))
P3 = AEAD_DEC(K3, C3, AD3)
```

This means patching a boolean branch is insufficient: the protected path needs key material produced by successful verification.

## How To Test

### Core Unit Tests

```bash
cargo test --manifest-path src/rust_core/Cargo.toml
```

Covers:

- signed blob parsing
- canonical CBOR validation
- signature verification
- platform/device/executable binding
- time-window authorization
- runtime constraints
- Mach-O section parsing
- selected-section measurement
- FFI fail-closed behavior
- capability plaintext-dependent chaining
- AEAD associated-data rebinding

### Python Syntax Check

```bash
PYTHONPYCACHEPREFIX=/private/tmp/coms6424_pycache \
  python3 -m py_compile scripts/issue_license.py scripts/profile_device.py
```

### Positive Pipeline Tests

```bash
tests/integration/pipeline/smoke_test.sh
tests/integration/pipeline/profile_issue_smoke_test.sh
```

Covers:

- local build and issue path
- target profile generation
- profile-based full binary issuance
- protected payload execution

### Profile Rejection Test

```bash
tests/integration/pipeline/malformed_profile_smoke_test.sh
```

Covers:

- invalid profile schema rejection during issuance

### Tamper And Negative Tests

```bash
tests/security/tamper/blob_corruption_smoke.sh
tests/security/tamper/device_mismatch_smoke.sh
tests/security/tamper/device_key_mismatch_smoke.sh
tests/security/tamper/expired_policy_smoke.sh
tests/security/tamper/debugger_constraint_smoke.sh
tests/security/tamper/dyld_constraint_smoke.sh
tests/security/tamper/measured_section_tamper_smoke.sh
tests/security/tamper/payload_ciphertext_tamper_smoke.sh
tests/security/tamper/code_signature_constraint_smoke.sh
```

Covers:

- embedded policy corruption
- wrong device fingerprint
- wrong runtime device key
- expired policy
- debugger simulation
- DYLD environment injection simulation
- measured `__TEXT,__text` tamper after re-signing
- validly signed policy with tampered protected payload ciphertext
- invalid code signature denial. macOS may reject the binary before Rust runs, so this test asserts non-zero failure rather than requiring `license denied`.

The shell smoke tests share generated files under `artifacts/`; run them serially.

## Coverage Summary

Implemented and directly tested:

- blob parsing and malformed blob rejection
- canonical policy encoding
- signature acceptance/rejection
- platform binding
- device fingerprint binding
- device key material binding
- executable selected-section binding
- time-window authorization
- debugger/DYLD/code-signature runtime constraints
- Mach-O license section patching
- target profile issuance
- payload AEAD authentication
- payload plaintext-dependent chaining
- C/Rust FFI fail-closed behavior

Implemented with partial or indirect coverage:

- real Keychain path: manually validated, while automated tests use `COMS6424_DEVICE_KEY_HEX`
- `scripts/issue_license.py` and `scripts/profile_device.py`: covered by smoke tests and syntax checks, but not full Python unit tests
- profile validation: schema rejection is covered; additional malformed cases such as wrong `product_id`, bad hex length, and wrong platform can be added
- code-signature failure: covered as non-zero process failure; exact output depends on whether macOS rejects before user-space Rust runs

Not implemented:

- offline clock rollback resistance with sealed last-seen-time
- remote time attestation
- Secure Enclave asymmetric enrollment
- runtime self-healing or destructive tamper response
- native code page encryption/decryption

## Boundary Outside Current Design

The implementation is a strong user-space offline license protection demo, not a defense against a fully privileged local adversary.

Out of boundary:

- root compromise
- kernel extension or hypervisor control
- SIP-disabled system manipulation
- arbitrary memory dumping after authorized execution
- debugger/instrumentation with enough privilege to bypass detection
- patching all verification and payload-use sites with full binary rewriting
- fault injection
- cache/timing/speculative microarchitectural side channels
- power/EM side channels
- cloning or extracting the Keychain secret from a fully compromised user account
- wall-clock rollback by a privileged attacker, because sealed offline time is not implemented

The intended boundary is to raise the cost of:

- copying the binary to another machine
- replacing or corrupting the embedded policy
- patching measured code or read-only data
- bypassing a simple C-side boolean branch
- reusing a license with a mismatched device key
- statically recovering protected payload strings/rules without successful capability derivation

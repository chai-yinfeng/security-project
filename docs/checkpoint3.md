# Checkpoint 3 Status

## Goal

This checkpoint records the hardening pass that moved the project from a working demo toward the intended Mach-O-bound design. The focus was to remove obvious bypass points, bind the license to stable executable structure, enforce signed runtime constraints, and expand negative-path testing.

## Delivered Scope

The current implementation now provides:

- a Mach-O `__TEXT,__license` carrier for the embedded signed policy
- runtime policy discovery through Mach-O section metadata rather than byte-pattern search
- issuer-side section patching through Mach-O metadata rather than detached blob replacement
- selected-section executable measurement with the `COMS6424_EXECUTABLE_IMAGE_V2` domain
- signed runtime constraints for debugger, DYLD environment, and code-signature state
- a Rust-owned `licensed_entry()` production path so the C host no longer owns the allow/deny branch
- expanded tamper tests for license corruption, hardware mismatch, expiration, measured section tampering, and runtime constraints

## Entry Boundary Change

Checkpoint 2 still had this shape:

```text
C main -> license_check() -> C protected_main()
```

That made the C branch an obvious attack target. The current shape is:

```text
C main -> licensed_entry() -> Rust verification -> Rust protected action
```

The old `license_check()` ABI remains available for compatibility and unit-level checks, but the production host path now calls `licensed_entry()`. This means a simple patch of the C-side check branch is no longer enough to enter the protected path.

## Mach-O License Carrier

The embedded policy is linked into:

```text
__TEXT,__license
```

The Rust core reads the current executable from disk, parses `LC_SEGMENT_64` section records, locates `__TEXT,__license`, and decodes the blob from that exact file range. The issuer uses the same physical section model when patching the final license into the binary.

This replaces the older implementation that searched for the license blob bytes inside the executable and replaced the first matching sequence.

## Policy Schema

The signed CBOR policy now includes:

- `schema_version`
- `product_id`
- `license_id`
- `issued_at_unix`
- `not_before_unix`
- `not_after_unix`
- `platform`
- `device_fingerprint_hash`
- `executable_hash`
- `protected_payload`
- `runtime_constraints`
- `flags`

`runtime_constraints` currently contains:

- `deny_debugger_attached`
- `deny_dyld_environment`
- `require_valid_code_signature`

These fields are covered by the Ed25519 signature because the signature remains over the canonical CBOR policy bytes.

## Capability-Protected Payload

The protected path is no longer a single hard-coded print. The issuer now encrypts three signed policy payload blocks:

- stage 1 feedback: capability acceptance
- stage 2 sealed rule material for a protected computation
- stage 3 final output template

After all license checks pass, Rust derives a mutable `Capability` from the product id, license id, Keychain-backed device key material, and executable hash. The protected payload consumes that capability block by block. Each block key is HKDF-SHA256-derived from the session key and the current plaintext-dependent chain hash, then decrypted with ChaCha20-Poly1305.

The chain is intentionally ordered:

- block 1 uses the initial chain hash derived from product id, license id, and executable hash
- block 2 uses a chain hash that commits to block 1 plaintext
- block 3 uses a chain hash that commits to block 2 plaintext

Associated data binds every AEAD operation to the product id, license id, executable hash, block id, payload schema version, and current chain hash. This means a patched boolean branch is not enough, and a later block cannot be decrypted by skipping or replacing earlier protected plaintext.

Device payload key material is no longer derived directly from `IOPlatformUUID`. The UUID remains a public node-locking fingerprint, while the payload capability uses a per-product 256-bit random secret stored in macOS Keychain. Tests can set `COMS6424_DEVICE_KEY_HEX` for deterministic automation, but the normal issue/runtime path reads or creates the Keychain secret.

## Executable Measurement

The executable binding is no longer a whole-file approximation with explicit license and signature exclusions. It is now an aggregate selected-section measurement.

Measured sections currently include stable protected regions such as:

- `__TEXT,__text`
- `__TEXT,__stubs`
- `__TEXT,__cstring`
- `__TEXT,__const`
- `__TEXT,__gcc_except_tab`
- `__TEXT,__unwind_info`
- `__TEXT,__eh_frame`
- selected `__DATA_CONST` sections when present

The hash includes each section's segment name, section name, byte length, and bytes. This catches protected code and read-only data tampering after re-signing while avoiding unstable signing/linker metadata.

The license section is intentionally not measured because it is patched after the final executable hash is issued.

## Runtime Constraints

Runtime enforcement now checks more than the time window:

- platform and architecture
- device binding
- selected-section executable binding
- signed time window
- disallowed DYLD loader environment
- required valid code signature
- debugger constraint through the native macOS traced process flag plus a deterministic automation hook

`codesign --verify --strict` is run against the current executable when the signed policy requires a valid code signature. The build and tamper tests re-sign binaries after patching so this constraint validates the expected post-signing artifact.

## Test Coverage

The current verification set includes:

- Rust unit tests for blob parsing, canonical policy encoding, signature verification, platform/device/executable binding, runtime constraints, Mach-O section parsing, and selected-section measurement
- Rust unit tests for plaintext-dependent payload block ordering and AEAD associated-data rebinding
- end-to-end pipeline smoke test
- license section corruption test
- device mismatch test
- device key mismatch test
- expired policy test
- measured `__TEXT` content tamper test after re-signing
- debugger/runtime-constraint simulation test

The shell smoke tests share `artifacts/bin/license_demo`, so they should be run serially unless the pipeline is later parameterized with isolated artifact directories.

## Residual Risk

This pass removes the obvious C-side check-branch bypass and binds the signed license to protected Mach-O regions. The remaining realistic risks are now in the expected hardening category rather than basic demo gaps:

- a sufficiently capable attacker can still patch Rust verification itself, though the protected payload now requires capability-derived AEAD keys rather than only a boolean result
- debugger detection is implemented, but anti-debugging should still be treated as a cost-increasing signal rather than a cryptographic guarantee
- aggregate `executable_hash` is enough for enforcement but does not identify which section changed; per-section signed hashes would improve diagnostics
- shell tests are not artifact-isolated yet
- Keychain protects against file-copy and UUID-spoof replay, but root/user compromise can still extract or abuse the local secret

## Current Outcome

The project now implements the core design requirements: a self-contained Mach-O executable, embedded signed policy, hardware binding, executable binding, time authorization, runtime constraints, section-based patching, and negative-path testing. The implementation is no longer dependent on a detached license blob or a trivial C-side authorization branch.

# Checkpoint 2 Status

## Goal

This document records the current implementation status after the first end-to-end demo pipeline was brought up. It is intended to help the testing team align on what is already stable enough to test, what is only a temporary implementation choice, and what is still missing.

## Current Delivered Scope

The repository now has a working demo path for a single self-checking macOS ARM64 executable with these implemented pieces:

- C host entry calls a single production ABI: `license_check()`
- Rust core returns `ALLOW` or `DENY` and fails closed on internal errors
- Python issuer generates a signed license blob and the matching Rust public-key file
- policy claims are encoded as canonical CBOR and checked again by the Rust core
- runtime collects current time, platform, architecture, device fingerprint hash, and executable measurement
- verification currently checks signature, platform, device binding, executable binding, and time window
- a build script can generate the demo binary, patch the final license blob into it, re-sign it, and run it successfully

## What Is Actually Running Today

The current pipeline is:

1. Generate a placeholder signed policy with a zero executable hash.
2. Build the Rust static library.
3. Link the host binary.
4. Ad-hoc sign the binary.
5. Measure the binary using the current executable-measurement rule.
6. Re-issue the final signed policy with that executable hash.
7. Patch the final policy blob into the binary.
8. Re-sign the binary.
9. Run the binary and allow entry into the protected path only if verification succeeds.

Current entry points and files:

- build pipeline: [scripts/build_pipeline.sh](/Users/black_magic/Desktop/Coding_projects/Columbia_COMS_E6424_Hardware_Security/final_project/scripts/build_pipeline.sh:1)
- issuer: [scripts/issue_license.py](/Users/black_magic/Desktop/Coding_projects/Columbia_COMS_E6424_Hardware_Security/final_project/scripts/issue_license.py:1)
- ABI entry: [src/rust_core/src/ffi.rs](/Users/black_magic/Desktop/Coding_projects/Columbia_COMS_E6424_Hardware_Security/final_project/src/rust_core/src/ffi.rs:16)
- host gate: [src/host_entry/main.c](/Users/black_magic/Desktop/Coding_projects/Columbia_COMS_E6424_Hardware_Security/final_project/src/host_entry/main.c:1)

## Current Policy / Blob Format

The current blob format is fixed for the demo:

- 4 bytes magic: `SLC1`
- 2 bytes version: `1`
- 4 bytes big-endian policy length
- canonical CBOR policy bytes
- 64-byte Ed25519 signature over the policy CBOR bytes

The current policy claims are:

- `schema_version`
- `product_id`
- `license_id`
- `issued_at_unix`
- `not_before_unix`
- `not_after_unix`
- `platform`
- `device_fingerprint_hash`
- `executable_hash`
- `flags`

## Current Executable Measurement Rule

The current executable binding is intentionally a demo-oriented approximation.

Measured input:

- the current Mach-O file on disk

Excluded regions:

- the embedded policy blob itself
- the `LC_CODE_SIGNATURE` load command
- the code-signature payload pointed to by that load command

This exclusion rule is implemented on both the issuer side and the runtime side. That is why the current patch-and-resign flow is able to converge.

## Temporary Implementation Choices

These are currently intentional shortcuts and should not be mistaken for the final design:

- embedded policy reading uses `include_bytes!` instead of real Mach-O section discovery
- executable binding uses whole-file measurement with explicit exclusions instead of selected Mach-O regions
- execution-environment constraints are currently limited to `platform.os` and `platform.arch`
- the build pipeline is script-driven and optimized for a stable demo rather than final packaging polish

## Stable Enough For Test Development

The testing team can start writing against these behaviors now:

- `license_check()` is the production ABI
- malformed blob headers should fail closed
- non-canonical policy CBOR should fail closed
- policy signature mismatch should fail closed
- device mismatch should fail closed
- executable measurement mismatch should fail closed
- expired or not-yet-valid policy should fail closed
- a correctly issued and patched demo binary should enter the protected path

## Recommended Minimum Test Set

For the current milestone, the minimum useful test set is:

1. Blob parsing:
   validate correct decoding of magic, version, length, and signature boundaries
2. Canonical CBOR:
   accept the issuer-produced encoding and reject equivalent-but-non-canonical encodings
3. Signature verification:
   accept valid signatures and reject any single-byte policy modification
4. Runtime measurement stability:
   confirm the current measurement logic survives patch-and-resign for the demo binary
5. End-to-end pipeline:
   run the build script and confirm the final executable reaches the protected path

## Work Still Pending

The next implementation steps that will affect tests are:

- replace `include_bytes!` with Mach-O section lookup
- tighten executable measurement from whole-file hashing to selected Mach-O regions
- expand execution-environment constraints beyond platform and architecture
- add more explicit negative-path hooks or fixtures for deterministic test generation
- add formal Rust and integration test targets so the test team does not have to rely only on shell reproduction

## Guidance For The Testing Team

When writing tests now, treat the following as stable:

- the blob header format
- the current CBOR schema
- Ed25519 signature verification behavior
- the fail-closed `ALLOW` / `DENY` contract

When writing tests, treat the following as likely to change:

- where the blob is located in the Mach-O image
- the exact executable measurement algorithm
- any future metadata-table fields in the blob

## Current Outcome

The repository is now at the point where the demo path is operational. The right testing posture is no longer “wait for the system to exist,” but “lock down the currently working path while keeping some test cases flexible around the known temporary implementation choices.”

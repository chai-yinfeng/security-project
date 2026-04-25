# Package Format

## Summary

The project uses a **logical embedded policy/blob format** inside the final Mach-O executable. This document defines the logical structure of that embedded blob for verification and testing purposes.

Production deployment is:

- one Mach-O executable
- one embedded signed policy/blob inside the executable's read-only image

This is not an external runtime package-loader format.

## Physical vs Logical Representation

### Physical Representation

- the final delivery artifact is a Mach-O executable for macOS ARM64
- the signed policy/blob is embedded into the executable image

### Logical Representation

- the embedded policy/blob has a defined internal structure
- the Rust core reads and validates that structure at runtime

This distinction lets the team reason about format structure without implying a detached runtime package file.

## Expected Mach-O Structure
```
final_app_macho
├── __TEXT
│   ├── __text
│   │   ├── C host main / entry wrapper
│   │   ├── Rust license_check()
│   │   └── protected application code
│   ├── __const
│   │   ├── embedded license blob
│   │   ├── Ed25519 public key
│   │   ├── expected checker/payload measurement metadata
│   │   └── static strings
│   └── __cstring
│
├── __DATA_CONST
│   ├── GOT / const pointer tables
│   └── read-mostly runtime metadata
│
├── __DATA
│   ├── mutable globals
│   └── runtime state
│
└── __LINKEDIT
    ├── symbol/linking metadata
    └── code signature
```

## Current Implemented Blob Layout

The current implementation uses a compact signed blob with this exact byte layout:

```text
offset  size  field
0       4     magic = "SLC1"
4       2     blob_format_version = 1 (big-endian)
6       4     policy_cbor_length (big-endian)
10      N     canonical CBOR policy claims
10 + N  64    Ed25519 signature over the policy CBOR bytes
```

Current implementation notes:

- there is no metadata table yet
- the signature covers the canonical CBOR policy bytes only
- structural validation currently enforces exact total length matching
- the implementation is intentionally minimal to keep the demo pipeline stable

## Logical Future Layout

The longer-term embedded blob can still evolve toward these logical regions:

- policy/blob header
- metadata table or segment table if retained
- signed manifest or policy claims
- optional future auxiliary fields

The semantic model stays useful, but the current parser should be documented as the source of truth for the demo.

## Header Fields

The current header exposes these fields:

- `magic`
- `blob_format_version`
- `blob_length`

Required semantics:

- `magic` identifies the embedded blob format
- `blob_format_version` selects layout and parsing rules
- `blob_length` bounds the blob extent
- there is currently no metadata table in the shipped blob format

## Required Policy Claims

The current canonical CBOR policy includes these fields:

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

Additional future claims may be added later, but missing, malformed, duplicated, or unsupported required claims must be rejected.

## Device Binding Semantics

The system is node-locked. Device binding is established through a **composite hardware fingerprint**.

The composite fingerprint should be:

- based on a small set of stable Apple Silicon/macOS identifiers
- queried again at runtime
- treated as a binding identifier rather than a secret

The docs should not claim that the fingerprint is secret. Leakage of the fingerprint alone must not be sufficient to authorize execution.

## Protected Executable Binding

The signed policy must bind not only to hardware and time but also to the protected executable image.

This binding is currently represented as:

- `executable_hash`

Future documentation may rename this concept at the design level, but `executable_hash` is the current source-of-truth field name.

Its purpose is to detect:

- tampering with the embedded policy/blob
- rebinding the same policy to a different executable image
- unauthorized recomposition of policy and program image

## Execution-Environment Constraints

The signed policy may also carry minimal execution-environment constraints, such as:

- expected platform
- expected architecture
- explicitly disallowed runtime states chosen by design

These constraints support baseline runtime checks beyond hardware identity and wall-clock time.

Current implementation note:

- `platform.os` and `platform.arch` are implemented today
- richer execution-environment constraints are deferred

## Structural Validation Requirements

The embedded blob reader and decoder must reject:

- wrong magic
- unsupported format version
- malformed or inconsistent lengths and offsets
- non-canonical policy CBOR
- malformed required fields

Future metadata-related validation can be added when the metadata table exists.

## Verification Coverage Requirements

Verification must cover more than the claims text alone.

At minimum, integrity coverage must include:

- signed policy claims
- device-binding claims
- protected executable image identity
- relevant embedded metadata needed to interpret the blob correctly when that metadata exists

This requirement exists because the system must defend not only against policy tampering, but also against rebinding, relocation, and blob recomposition within the executable image.

## Current Measurement Rule

The current executable binding is a demo-oriented whole-file measurement with explicit exclusions.

The measured bytes are:

- the current Mach-O executable image

The excluded bytes are:

- the embedded signed policy/blob itself
- the `LC_CODE_SIGNATURE` load command
- the code signature payload referenced by that load command

This exclusion rule is implemented on both the issuer side and the runtime side so that the current pipeline is stable after patching and re-signing.

Planned next step:

- replace this whole-file approximation with selected Mach-O region measurement

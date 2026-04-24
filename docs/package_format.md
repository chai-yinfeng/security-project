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

## Logical Embedded Blob Layout

The embedded blob should be described in terms of these logical regions:

- policy/blob header
- metadata table or segment table if retained
- signed manifest or policy claims
- optional future auxiliary fields

An implementation may choose exact byte-level encoding later, but the semantic layout should remain stable.

## Header Fields

The logical header should expose at least:

- `magic`
- `blob_format_version`
- `blob_length`
- `metadata_offset`
- `metadata_length`
- `reserved_or_flags`

Required semantics:

- `magic` identifies the embedded blob format
- `blob_format_version` selects layout and parsing rules
- `blob_length` bounds the blob extent
- `metadata_offset` and `metadata_length` locate any metadata region
- `reserved_or_flags` must be handled in a forward-compatible way

## Metadata / Segment Fields

If a metadata table or segment table is retained, it should expose at least:

- `entry_kind`
- `entry_offset`
- `entry_length`
- `entry_flags`

Possible logical entry kinds include:

- `POLICY_CLAIMS`
- `IMAGE_BINDING`
- `AUX_METADATA`
- `DEBUG_INFO`

The exact entry set may remain implementation-defined, but the docs must preserve the idea that relevant embedded metadata can be covered by verification.

## Required Policy Claims

The signed policy should include at least:

- `policy_version`
- `package_product_id`
- `device_fingerprint_type`
- `device_fingerprint_value_or_digest`
- `issued_at`
- `expires_at`
- `protected_image_digest_or_identity`
- `execenv_constraints`
- `signature_algorithm`
- `signature`

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

This binding should be represented as:

- `protected_image_digest_or_identity`

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

## Structural Validation Requirements

The embedded blob reader and decoder must reject:

- wrong magic
- unsupported format version
- malformed or inconsistent lengths and offsets
- malformed metadata layout
- duplicated or conflicting required fields
- unsupported reserved or flag usage

## Verification Coverage Requirements

Verification must cover more than the claims text alone.

At minimum, integrity coverage must include:

- signed policy claims
- device-binding claims
- protected executable image identity
- relevant embedded metadata needed to interpret the blob correctly

This requirement exists because the system must defend not only against policy tampering, but also against rebinding, relocation, and blob recomposition within the executable image.

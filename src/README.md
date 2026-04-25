# Source Layout

- `rust_core/`: placeholder for Rust-side trusted logic ownership notes
- `host_entry/`: placeholder for C host-entry ownership notes

The final implementation may reorganize source directories after the team freezes module boundaries. Until then, keep the trusted self-checking surface small and auditable.

## Current System View

The authoritative runtime design is a **single self-checking Mach-O executable** on macOS ARM64. The source tree should therefore be understood as two cooperating sides:

- `host_entry/`
  - the C host entry side
  - receives control when the executable starts
  - calls into the Rust core before protected execution
- `rust_core/`
  - the Rust-side trusted boundary
  - reads the embedded policy/blob
  - queries the live runtime environment
  - verifies binding and authorization conditions
  - returns `ALLOW` or `DENY`

## Layer Split Across `src/`

At the highest level, the runtime path is:

```text
C Host Entry
    -> FFI Boundary
    -> Embedded Policy Reader
    -> Policy Decoder
    -> Runtime Environment Query
    -> Verification / Binding
    -> Authorization
    -> ALLOW / DENY
```

Directory ownership should follow that split:

- `host_entry/`
  - host entry control flow
  - protected-path gate
  - no policy parsing or verification logic
- `rust_core/`
  - all trusted runtime logic after the host-to-core transition

## Source-Level Design Rules

- The host side should stay thin and should never duplicate Rust-side verification logic.
- The FFI boundary should stay minimal and fail closed.
- The Rust core should separate decoding, environment collection, verification, and authorization rather than mixing them into one step.
- The narrow production decision surface should remain `ALLOW` or `DENY`.

## Naming Note

The preferred source layout is now:

- `src/rust_core/`
- `src/host_entry/`

Older names such as `license_core/` and `app_integration/` have been retired in favor of the current layout above.

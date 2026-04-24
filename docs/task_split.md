# Task Split

This document records the proposed team split for the proposal-aligned self-checking Mach-O design. It is intended to define responsibility boundaries before implementation begins.

## Shared Design Decisions

- The production artifact is one self-checking Mach-O executable on macOS ARM64.
- The executable contains an embedded signed policy/blob rather than relying on an external runtime license file.
- The embedded policy/blob format, trust boundary, and attack assumptions must be agreed in documentation before implementation details are assigned.
- `docs/package_format.md` and `docs/interface_contract.md` should be treated as the primary format and interface references.
- Internal function structure, crate selection, parser details, and verification implementation remain open for the implementers.

## Recommended Work Split

### Rust Core Owner

Primary responsibility:

- define the trusted boundary inside the Rust core
- implement embedded-policy reading, policy decoding, runtime environment query, verification, authorization, and the C ABI boundary
- define internal error types and fail-closed behavior
- review any interface assumptions needed by the C host entry layer

Deliverables:

- Rust core design notes
- module boundaries and internal interfaces
- implementation plan for embedded-policy reading, environment query, verification, authorization, and FFI
- unit-test plan for tampering, relocation, and authorization decisions

### C Host Owner

Primary responsibility:

- define the host-side control flow
- ensure the protected path is entered only after an allow decision
- integrate the final Rust ABI without embedding policy parsing or verification logic on the C side

Deliverables:

- host entry flow
- protected path wrapper design
- integration assumptions for calling the Rust core

### Profiler and Issuance Owner

Primary responsibility:

- define how the target Mac is profiled
- define the composite hardware-fingerprint collection strategy
- define the offline policy generation and signing workflow
- define the embedding step that places the signed policy/blob into the executable image

Deliverables:

- profiler design notes
- issuance and signing workflow notes
- embedding workflow notes

### Evaluation Owner

Primary responsibility:

- define the attack and evaluation plan after the interfaces are fixed
- prepare relocation, tampering, timing, and runtime-environment experiments
- make sure every final claim maps to a reproducible artifact

Deliverables:

- evaluation checklist
- runtime test plan
- result collection plan

### Documentation and Report Owner

Primary responsibility:

- keep architecture, threat model, and implementation sections aligned with actual design decisions
- maintain the final artifact checklist and report consistency
- record open questions and unresolved tradeoffs during implementation

Deliverables:

- synchronized design documents
- final report outline
- submission checklist ownership

## Immediate Next Step

Before assigning implementation tasks, the team should agree on:

- embedded policy/blob fields and metadata semantics
- the composite hardware-fingerprint direction
- the exact Rust core responsibility boundary
- the narrowest possible C ABI

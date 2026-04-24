# Project Plan

## Milestone 1: Freeze the Proposal-Aligned Contract

- finalize the self-checking Mach-O architecture
- finalize the logical embedded policy/blob layout
- finalize the production host-to-core ABI
- finalize platform scope as macOS on Apple Silicon (ARM64)
- finalize the composite hardware-fingerprint direction

## Milestone 2: Build-Time Issuance Pipeline

- define the profiler responsibilities on the target Mac
- define the offline issuer and signer responsibilities
- define how the signed policy/blob is embedded into the executable image
- define reproducible build collateral for the embedding workflow

## Milestone 3: Runtime Core Implementation

- implement embedded policy/blob extraction
- implement policy decoding
- implement runtime environment queries for hardware, time, and minimal execution-environment state
- implement signature verification and binding checks
- implement authorization gating and allow/deny flow

## Milestone 4: Security Evaluation

- run relocation tests on unauthorized Macs
- run clock-tampering tests
- run embedded-policy tampering tests
- run minimal execution-environment denial tests
- evaluate timing leakage in hardware-fingerprint comparison
- document host-side and user-space bypass attempts

## Milestone 5: Final Report and Demo

- collect raw outputs and reproducibility notes
- align report text with the proposal-aligned architecture
- prepare the final demo of the self-checking executable
- include required AI logs and supporting artifacts

## Success Criteria

- the team shares one consistent self-checking-binary architecture
- the runtime path starts in the host and gates protected execution on Rust allow/deny
- copied binaries deny on unauthorized hardware
- expired binaries deny outside the allowed wall-clock window
- tampered embedded policies deny
- the docs and interface contract remain consistent with the final proposal defense

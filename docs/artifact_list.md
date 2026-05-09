# Artifact List

This file lists the expected final artifacts for the proposal-aligned self-checking Mach-O design.

## Design Documents

- architecture document
- embedded policy/blob format document
- interface contract document
- threat model document
- project plan document
- task split document

## Build-Time Artifacts

- target device profile script
- target profile JSON examples or logs
- offline issuer / signer implementation
- build integration for embedding the signed policy/blob
- reproducible build collateral and configuration

## Runtime Source Artifacts

- Rust core source for embedded-policy reading, runtime environment query, verification, authorization, and ABI logic
- C host source for protected-path control flow
- public header for the production ABI

## Tests and Evaluation Artifacts

- relocation test cases
- wall-clock tampering test cases
- embedded-policy tampering test cases
- execution-environment denial test cases
- timing-side-channel evaluation notes and logs
- documented bypass attempts and residual-risk notes

## Report Artifacts

- final report
- slides or demo material
- reproducibility notes
- AI usage logs required by the course

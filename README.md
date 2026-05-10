# COMS 6424 Final Project: Option 2

This repository is organized for Option 2: designing a self-checking software enforcement system for macOS on Apple Silicon (ARM64).

## Working Direction

The project should treat enforcement as a protected subsystem compiled together with a host application. The design should defend both:

- embedded policy integrity, such as signed claims, hardware binding, and executable binding
- enforcement integrity, such as control flow, parser behavior, authorization decisions, and anti-bypass logic

The current design pass is intentionally scoped to macOS on Apple Silicon. The protected executable performs a self-check at runtime before entering the protected path.

## Repository Layout

- `docs/`: threat model, architecture, checkpoint material, and design notes
- `include/`: public interface contracts
- `scripts/`: profile, issuance, build, and reproduction helpers
- `src/`: C host entry and Rust enforcement core
- `tests/`: integration, tamper, and Rust unit coverage
- `eval/`: evaluation harnesses, microbenchmarks, and attack experiments
- `artifacts/`: generated binaries, policies, device profiles, and issuer keys; ignored by Git

## Implemented Scope

1. Mach-O `__TEXT,__license` embedding and patching.
2. Ed25519-signed canonical CBOR policy.
3. Platform, device, executable image, time-window, code-signature, DYLD, and debugger constraints.
4. Keychain-backed device key material with target profile based issuance.
5. HKDF-SHA256 and ChaCha20-Poly1305 protected payload blocks with plaintext-dependent chaining.
6. Integration and tamper smoke tests for the main positive and negative paths.

## Reproducibility Rule

Every result in the final report should be traceable to a script, command, input artifact, and generated output under this repository.

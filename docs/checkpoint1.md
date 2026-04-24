# Checkpoint 1 Draft

Due: Monday, April 20, 2026, in class.

## Project

Option 2: design of a self-checking software license or policy enforcement system for macOS on Apple Silicon (ARM64).

## Baseline Project Claim

We will build and evaluate a single self-checking Mach-O executable. The executable contains a C host entry layer, a Rust enforcement core, an embedded signed policy/blob, and protected application logic. At runtime the program verifies its embedded policy and the live execution environment before entering the protected path.

The baseline remains software-first. TPM-, TEE-, or stronger platform-root enhancements may be discussed as later extensions, but they are not baseline dependencies.

## Security Goal

The protected path should execute only when:

- the embedded policy/blob is validly read and decoded
- the policy signature verifies
- the live composite hardware fingerprint matches the signed policy
- the current executable image matches the signed image binding
- the wall clock is within the permitted window
- minimal execution-environment constraints are satisfied

## Architecture Summary

```text
Build-Time Server
  -> profiler
  -> offline issuer / signer
  -> embedding step

Runtime Client
  Current Mach-O Executable
      -> C host entry
      -> Rust core
      -> embedded policy read
      -> live environment query
      -> verification
      -> authorization
      -> ALLOW or DENY
```

## Current Key Decisions

- production target is one self-checking Mach-O binary on macOS ARM64
- the signed policy/blob is physically embedded in the executable image
- device binding uses a composite hardware fingerprint
- production ABI does not take caller-supplied `product_id`
- runtime baseline checks are hardware identity, wall clock, and minimal execution-environment checks
- verification covers policy contents, hardware binding, executable-image binding, and relevant embedded metadata

## Near-Term Team Tasks

1. Freeze the embedded policy/blob layout and required claims.
2. Freeze the production ABI and the internal runtime abstraction chain.
3. Freeze the profiler, issuance, and embedding workflow.
4. Assign Rust core, host entry, build integration, and evaluation ownership.
5. Convert the design documents into concrete implementation tasks for each team member.

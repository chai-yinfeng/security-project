# Threat Model

## Security Boundary

The baseline design is a self-checking Mach-O executable for macOS on Apple Silicon (ARM64). The trusted boundary is the Rust core plus its narrow ABI surface. The C host controls whether execution continues, but it must not implement policy parsing, verification, or authorization logic on its own.

The production artifact is one executable image with one embedded signed policy/blob.

## Security Goal

The protected path must execute only after:

- the embedded policy/blob is read and decoded successfully
- the policy authenticity is established
- the live hardware environment matches the signed hardware binding
- the current executable image matches the signed image binding
- time-bound and execution-environment constraints succeed

Binary relocation, clock tampering, executable tampering, and runtime-environment mismatch must fail closed.

## Assets

- embedded signed policy/blob
- policy claims
- composite hardware fingerprint claims
- live hardware identity observations
- protected executable image identity
- runtime authorization decision
- control-flow gate before the protected path

## In-Scope Attacker Model

### Level 1: Malicious User-Space Operator

The attacker can:

- copy the binary to another Mac
- modify the system clock
- tamper with the executable image or embedded policy/blob
- attempt host-side or FFI-side bypasses
- attach ordinary user-space tooling
- observe or measure execution timing

Expected result: the system rejects unauthorized execution without entering the protected path.

### Level 2: Local User-Space Hooking Attacker

The attacker can additionally attempt:

- user-space hooking of hardware-identity queries
- user-space hooking of environment checks
- library-injection-style interference where the environment permits it

Expected result: the design minimizes trust in caller-side behavior, uses a narrow production ABI, and documents residual risk honestly where user-space can still influence observations.

## First-Class In-Scope Threats

- binary relocation to a different Mac
- wall-clock tampering to bypass expiration
- tampering with the embedded policy/blob
- tampering with the executable image bound to the policy
- host-side or FFI-side bypass attempts
- user-space hooking of runtime hardware-ID queries
- timing leakage during device-fingerprint comparison

## Security Assumptions

- the issuer signing key is protected offline
- hardware fingerprint is a binding identifier, not a secret
- leakage of the fingerprint alone does not authorize execution
- the system relies on comparing live queried identity against signed policy claims
- user-space hooks can still lie about environment state; this risk is mitigated but not eliminated in the baseline
- kernel-, firmware-, or privileged falsification of hardware state is out of scope

## Required Security Properties

- copied binaries deny on unauthorized hardware
- expired binaries deny when the wall clock is outside the signed window
- tampered embedded policies deny
- mismatched executable-image bindings deny
- unsupported runtime-environment states deny when covered by policy
- ABI misuse denies
- the host does not enter the protected path before an allow decision

## Constant-Time Comparison Requirement

Hardware identity comparison must avoid early-exit comparison behavior and should use constant-time comparison semantics where practical. This requirement exists to reduce timing leakage from partial hardware fingerprint matches.

## Out-of-Scope Attacker Model

The following remain out of scope for the baseline:

- compromised issuer signing keys
- malicious kernel, hypervisor, firmware, or microcode
- invasive physical attacks
- hardware debug access that can arbitrarily alter execution
- complete compromise of the platform's code-signing or trusted execution assumptions
- denial-of-service attacks whose only effect is preventing execution

## Residual Risks

- a sufficiently patched binary can bypass software-only checks if code integrity is absent
- user-space query hooks can distort runtime observations in some environments
- microarchitectural behavior is platform dependent and cannot be fully eliminated by documentation alone

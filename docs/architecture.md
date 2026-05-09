# Architecture

## Design Summary

The authoritative system model is a **single self-checking Mach-O executable** targeting **macOS on Apple Silicon (ARM64)**. The final protected artifact contains:

- the C host entry layer
- the Rust enforcement core
- an embedded signed policy/blob
- the protected application logic

The program does not depend on an external license file or an external runtime package input. Instead, the program performs a self-check before entering the protected path.

## Two-Phase System Model

### Phase 1: Build-Time Server

The build-time side is offline and prepares the protected executable for one target device class or one specific target device.

Responsibilities:

- consume a target profile generated on the target Mac
- collect or receive a composite hardware fingerprint
- receive Keychain-derived device payload key material without receiving the raw Keychain secret
- bind that fingerprint to a validity window and policy constraints
- sign the policy using the offline issuer key
- embed the signed policy/blob into the final Mach-O read-only image

### Phase 2: Runtime Client

The runtime side is the protected executable itself.

Responsibilities:

- start execution in the C host layer
- call the Rust core before entering the protected path
- read the embedded policy/blob from the current executable image
- query the live runtime environment
- verify policy authenticity, hardware binding, executable binding, and authorization constraints
- return `ALLOW` or `DENY`

## Runtime Layer Layout

```text
Current Mach-O Executable
        |
        v
C Host Entry
        |
        v
FFI Boundary
        |
        v
Embedded Policy Reader
        |
        v
Policy Decoder
        |
        v
Runtime Environment Query
        |
        v
Verification / Binding
        |
        v
Authorization Gate
        |
        v
ALLOW or DENY
```

## Layer Responsibilities

### C Host Entry

- receives control when the program starts
- invokes the Rust core before protected execution
- enters the protected application logic only after `ALLOW`
- does not implement policy parsing, signature checks, or hardware binding logic

### FFI Boundary

FFI means Foreign Function Interface. Here it is the language boundary between the C host and the Rust core.

Responsibilities:

- define the minimal host-to-core ABI
- convert host-side calls into Rust-side execution
- prevent Rust panics from escaping across the boundary
- collapse production failures into `ALLOW` or `DENY`

### Embedded Policy Reader

- locates and reads the embedded signed policy/blob from the current Mach-O image
- treats the embedded blob as untrusted input until verified
- exposes the blob as a structured read target for the Rust core

Current implementation note:

- this layer currently uses a temporary `include_bytes!` embedding path rather than Mach-O section lookup

### Policy Decoder

- parses the embedded blob into structured claims
- decodes policy fields without yet trusting them
- rejects malformed or unsupported policy representations

Current implementation note:

- the decoder currently expects a fixed blob layout with `magic + version + cbor_len + canonical_cbor + signature`
- canonical CBOR is re-encoded and byte-compared during verification

### Runtime Environment Query

- queries the live composite hardware fingerprint
- queries the current wall-clock time
- checks minimal execution-environment conditions required by policy

Baseline execution-environment checks should include at least:

- platform and architecture match
- expected runtime environment shape for macOS ARM64
- obvious unsupported injection or execution-context states when explicitly chosen by policy

### Verification / Binding

- verifies the policy signature
- verifies the live hardware fingerprint against the signed hardware binding
- verifies the protected executable image identity against the signed image binding
- verifies the integrity coverage of relevant embedded metadata

Current implementation note:

- executable binding currently hashes the whole current Mach-O image except for the embedded blob and code-signature-related regions
- richer Mach-O region selection remains future work

### Authorization Gate

- enforces expiration and other runtime policy constraints
- converts verification and policy results into the final execution decision

## Why the Layering Is Necessary

The layering is a security decision, not just a code organization preference.

- The C host should control only the transition into protected execution.
- The FFI layer should isolate language-boundary failures from security logic.
- Policy decoding should stay separate from trust decisions.
- Runtime environment querying should stay separate from signature verification.
- Verification should establish truth; authorization should decide permission.
- The external decision surface should remain narrow so the system fails closed.

Without these boundaries, self-check logic, environment probing, signature handling, and execution control become intertwined and harder to reason about or test.

## Runtime Execution Flow

From the executable's point of view, the runtime path is:

1. macOS loads the Mach-O executable.
2. Execution begins in the C host entry path.
3. The host calls the Rust core through the ABI.
4. The Rust core reads the embedded policy/blob from the current executable image.
5. The Rust core decodes the policy claims.
6. The Rust core queries the live hardware fingerprint, clock, and minimal execution-environment state.
7. The Rust core verifies signature, hardware binding, executable binding, and relevant embedded metadata.
8. The Rust core evaluates time-bound and other policy constraints.
9. The Rust core returns `ALLOW` or `DENY`.
10. The host enters the protected path only after `ALLOW`.

## Internal Abstract Objects

The recommended internal abstraction chain is:

```text
CurrentExecutableImage
    -> EmbeddedPolicyBlob
    -> PolicyClaims
    -> RuntimeEnvironmentSnapshot
    -> VerifiedRuntimeBinding
    -> AuthorizationDecision
    -> ALLOW / DENY
```

### CurrentExecutableImage

- the loaded Mach-O image that is being protected

### EmbeddedPolicyBlob

- the signed structured policy extracted from the executable image

### PolicyClaims

- decoded, not-yet-trusted policy fields

### RuntimeEnvironmentSnapshot

- live composite hardware fingerprint
- current wall-clock time
- minimal execution-environment status

### VerifiedRuntimeBinding

- policy authenticity established
- live hardware matched against the signed binding
- executable identity matched against the signed binding
- relevant embedded metadata integrity established

### AuthorizationDecision

- final decision on whether the protected path may execute

## Product Identity Decision

Production authorization does not depend on caller-supplied `product_id`.

The protected executable is self-describing through the embedded signed policy. Product identity, device identity, time bounds, and executable identity are all part of the signed policy and are not delegated to production caller input.

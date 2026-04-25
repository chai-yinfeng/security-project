# Rust Core Placeholder

This directory is the placeholder for the **Rust-side trusted boundary** inside the self-checking Mach-O executable.

The Rust core begins after the C host crosses the ABI boundary and ends when the core returns the final runtime decision.

## Core Responsibilities

The Rust core is responsible for all trusted runtime checks:

- read the embedded signed policy/blob from the current executable image
- decode the blob into structured policy claims
- query the live runtime environment
- verify signature, hardware binding, executable-image binding, and embedded metadata integrity
- enforce time-bound and execution-environment constraints
- return a fail-closed authorization decision

The Rust core should **not** assume that:

- the embedded blob is already trusted
- the host has done any meaningful security validation
- caller-supplied product context is needed in production

## Recommended Internal Layering

The Rust core should keep these responsibilities separate:

### 1. Embedded Policy Reader

Purpose:

- locate the embedded policy/blob in the current executable image
- expose raw blob bytes for further processing

This layer should answer:

- where the embedded blob is
- how large it is
- whether it can be read consistently

This layer should not answer:

- whether the blob is authentic
- whether execution is allowed

### 2. Policy Decoder

Purpose:

- parse the raw embedded blob into structured claims

This layer should answer:

- whether the blob is structurally well-formed
- whether all required claims are present and decodable

This layer should not answer:

- whether the claims are trusted
- whether the current machine is authorized

### 3. Runtime Environment Query

Purpose:

- collect the live runtime observations needed by policy

Expected inputs:

- none from the host in production

Expected outputs:

- composite hardware fingerprint
- current wall-clock time
- minimal execution-environment state

### 4. Verification / Binding

Purpose:

- establish whether the decoded policy is authentic and bound to the current runtime instance

This layer should verify:

- policy signature
- hardware binding
- executable-image binding
- relevant embedded metadata integrity

This is the layer that turns decoded claims into trusted bound state.

### 5. Authorization

Purpose:

- decide whether a successfully verified runtime instance is permitted to continue

This layer should enforce:

- expiration window
- execution-environment constraints
- any other permitted runtime policy conditions

This layer should not repeat signature or parsing logic.

### 6. Decision Mapping

Purpose:

- collapse internal success or failure into the production-facing runtime result

External surface:

- `ALLOW`
- `DENY`

## Recommended Internal State Objects

The Rust core should revolve around these conceptual objects:

```text
CurrentExecutableImage
    -> EmbeddedPolicyBlob
    -> PolicyClaims
    -> RuntimeEnvironmentSnapshot
    -> VerifiedRuntimeBinding
    -> AuthorizationDecision
```

### CurrentExecutableImage

Represents:

- the currently running Mach-O image that is being protected

It exists so later layers can reason about executable identity without mixing that concern into unrelated parsing code.

### EmbeddedPolicyBlob

Represents:

- the raw structured signed policy extracted from the executable image

It is still untrusted at this stage.

### PolicyClaims

Represents:

- decoded, not-yet-trusted claims from the embedded blob

Current implemented fields:

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

Planned future extensions may add richer execution-environment constraints or metadata coverage, but the list above is the current source-of-truth schema.

### RuntimeEnvironmentSnapshot

Represents:

- the live runtime state used for enforcement

Expected contents:

- live composite hardware fingerprint
- current wall-clock time
- minimal execution-environment status

### VerifiedRuntimeBinding

Represents:

- a runtime instance whose policy, hardware binding, executable binding, and relevant metadata checks have all succeeded

This object is important because authorization should operate on **verified runtime state**, not on raw decoded claims.

### AuthorizationDecision

Represents:

- the final permitted or denied result inside the Rust core

The implementation may keep richer internal reasons, but the production ABI should only expose `ALLOW` or `DENY`.

## Interface Design Constraints

The Rust core should be designed around a narrow production ABI:

- production input is the current executable image and live runtime environment
- production output is `ALLOW` or `DENY`

It should not be designed around:

- caller-supplied `product_id`
- detached runtime package files
- a split checker-versus-binary execution model

## Implementation Boundary

The detailed module names, helper functions, crates, and file structure remain open for the implementers. What should stay fixed is the abstraction and responsibility split above.

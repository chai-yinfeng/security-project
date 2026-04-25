# Interface Contract

## Goal

This document defines the narrow production interface and the recommended internal abstraction boundaries for the self-checking Mach-O design. It freezes the host-to-core contract and the runtime object model without prematurely freezing implementation details.

## Production ABI

The production C-facing ABI should be centered on the self-check path:

```c
typedef enum {
    LICENSE_DENY = 0,
    LICENSE_ALLOW = 1
} license_decision_t;

license_decision_t license_check(void);
```

Production semantics:

- the check operates on the **current executable image**
- the check reads the **embedded signed policy/blob**
- the check queries the **live runtime environment**
- all parsing, verification, and authorization failures collapse to `LICENSE_DENY`
- the caller must not enter the protected path unless the result is `LICENSE_ALLOW`

## Non-Production Helper Interfaces

If helper interfaces are retained for tests or tooling, they must be clearly documented as non-production interfaces.

Examples of helper-only interfaces:

- checking a policy/blob from a file
- checking a policy/blob from an in-memory byte buffer

These helper interfaces must not redefine the production trust boundary.

## No Production `product_id` Input

The production ABI does not take caller-supplied `product_id`.

Rationale:

- the embedded signed policy is the authoritative source of product identity
- product, hardware, executable identity, and validity window are all part of the signed self-description
- relying on production caller input would weaken the self-checking model

## Recommended Internal Abstraction Chain

The Rust core should conceptually transform runtime state through:

```text
CurrentExecutableImage
    -> EmbeddedPolicyBlob
    -> PolicyClaims
    -> RuntimeEnvironmentSnapshot
    -> VerifiedRuntimeBinding
    -> AuthorizationDecision
```

### CurrentExecutableImage

- the loaded Mach-O executable that is being protected

### EmbeddedPolicyBlob

- the structured signed policy extracted from the current executable image
- current implementation note: the blob is compiled into the binary via `include_bytes!`
- planned next step: replace the temporary embedding path with Mach-O section lookup

### PolicyClaims

- decoded policy fields prior to trust establishment

### RuntimeEnvironmentSnapshot

- live composite hardware fingerprint
- current wall-clock time
- minimal execution-environment status

### VerifiedRuntimeBinding

- policy signature validated
- live hardware matched against signed hardware claims
- executable image matched against signed image-binding claims
- relevant embedded metadata integrity established

### AuthorizationDecision

- final runtime result for protected execution

## Layer Ownership Contract

The recommended conceptual split is:

- FFI boundary: host-to-core ABI and fail-closed error collapse
- embedded policy reader: locate and read the policy/blob from the current executable
- policy decoder: decode structured policy claims
- runtime environment query: collect hardware, time, and execution-environment inputs
- verification layer: establish policy, hardware, and executable binding
- authorization layer: enforce time and other runtime constraints

Internal helper names may vary, but these responsibilities should remain separated.

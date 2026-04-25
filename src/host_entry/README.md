# C Host Entry Placeholder

This directory is the placeholder for the **C host entry logic** of the self-checking executable.

The host is part of the final protected Mach-O binary. It is not an external checker and it is not a detached loader for a separate runtime artifact.

## Host Responsibilities

The host side should remain intentionally narrow:

- receive control when the executable starts
- call the Rust core through the agreed production ABI
- wait for the Rust decision
- enter the protected path only after `ALLOW`
- terminate or refuse progress on `DENY`

## Host / Rust Boundary

Conceptually, the boundary is:

```text
C Host Entry
    -> license_check_embedded_policy()
    -> ALLOW or DENY
```

The host is responsible for control flow.

The Rust core is responsible for:

- embedded-policy reading
- policy decoding
- runtime environment query
- verification and binding
- authorization logic

## What the Host Must Not Do

The host side should not implement any of the following on its own:

- policy/blob parsing
- signature verification
- hardware fingerprint comparison
- executable-image binding checks
- time or execution-environment authorization logic

If the host duplicates those behaviors, the trusted boundary becomes harder to reason about and easier to bypass inconsistently.

## Recommended Host Control Flow

The intended runtime sequence is:

1. executable starts
2. host reaches the enforcement gate
3. host calls the Rust core through the ABI
4. Rust returns `ALLOW` or `DENY`
5. host enters protected logic only on `ALLOW`

## Interface Constraint

The host should depend only on the narrow production ABI.

It should not require:

- caller-supplied `product_id`
- external runtime package files
- detached policy inputs in production

Test or tooling-only helper interfaces may exist later, but they should not redefine the production runtime model.

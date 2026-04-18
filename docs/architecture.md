# Architecture Draft

## High-Level Components

- host application entry wrapper
- license verifier
- license parser
- cryptographic verification module
- policy engine
- protected decision handoff
- audit and measurement hooks
- evaluation harness

## Proposed Flow

1. The host application starts through a narrow entry wrapper.
2. The wrapper loads the license input from a configured source.
3. The parser validates structure, size bounds, version fields, and canonical encoding.
4. The verifier checks the license signature using an embedded or provisioned trust anchor.
5. The policy engine checks expiration, product identifier, feature flags, and optional device binding.
6. The wrapper enters the protected application path only if every check succeeds.
7. Any error, ambiguity, malformed input, or unexpected state returns deny.

## Software Attack Defenses

- memory-safe parser or hardened C/C++ subset with bounds checks
- canonical serialization to avoid ambiguous encodings
- signature verification over the full canonical payload
- constant-time comparison for secrets and tags
- fail-closed error handling
- small trusted checking surface
- compiler hardening flags and sanitizer-backed tests
- separation between parsing, verification, policy, and application logic

## Microarchitectural Attack Defenses

- minimize secret-dependent branches and memory accesses
- avoid using secret license material as table indices or pointers
- insert speculation barriers around authorization-dependent transitions where justified
- clear transiently useful data after verification
- isolate evaluation processes where possible
- evaluate timing variance and cache-observable behavior
- document Rowhammer assumptions and mitigation dependencies

## Design Questions To Resolve

- implementation language and crypto library
- exact license format
- whether device binding is included in the first prototype
- whether TPM, OS keystore, or TEE support is modeled, implemented, or treated as future work
- precise evaluation targets for side-channel and fault-injection resilience


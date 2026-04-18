# Threat Model

## Assets

- license signing public key or trust anchor
- signed license payloads and entitlement metadata
- authorization decision produced by the checker
- control-flow integrity of the checker and protected application entry path
- parser and serialization correctness
- telemetry, counters, or device-binding state if used

## Security Properties

- only valid licenses authorize execution
- invalid, expired, replayed, malformed, or forged licenses are rejected
- license validation cannot be bypassed by corrupting control flow or data flow
- sensitive license material is not leaked through direct reads, timing behavior, shared resources, speculation, or fault effects
- failures default to deny

## Attacker Capabilities

Assume the attacker can:

- provide arbitrary license files or serialized inputs
- run the protected binary locally
- inspect and patch user-space memory and files when OS permissions allow
- trigger malformed input, crashes, restarts, and rollback attempts
- attempt memory corruption, control-flow hijacking, unsafe parsing, and privilege misuse
- observe timing and cache-level side channels on shared hardware
- attempt speculative execution leakage and Rowhammer-style software-induced faults

## Out of Scope Candidates

These should be justified or revised as the design matures:

- physical invasive attacks
- compromised signing key
- malicious operating system or kernel-level rootkits
- fully compromised firmware or microcode
- denial of service

## Initial Residual Risks

- portable software-only defenses cannot fully eliminate all microarchitectural leakage on arbitrary CPUs
- Rowhammer resistance depends on platform memory, ECC, refresh policy, OS isolation, and allocation strategy
- strong anti-tamper guarantees may require OS, compiler, or hardware support


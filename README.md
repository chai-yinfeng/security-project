# COMS 6424 Final Project: Option 2

This repository is organized for Option 2: designing a software license enforcement component that is resilient to software attacks and microarchitectural attacks.

## Immediate Goal

Prepare Checkpoint 1 for Monday, April 20, 2026:

- threat model
- detailed system architecture
- step-by-step project plan and milestones
- final artifact list
- collaboration plan and responsibilities

## Working Direction

The project should treat license enforcement as a protected subsystem compiled together with a host application. The design should defend both:

- license data, such as keys, signed licenses, device bindings, counters, and entitlements
- enforcement integrity, such as control flow, parser behavior, authorization decisions, and anti-bypass logic

The first design pass should focus on a portable architecture that can run on standard processors available today. Hardware support such as TPM, OS keychain, memory protection, process isolation, or optional TEE support can be modeled as deployment variants rather than hard requirements.

## Repository Layout

- `docs/`: threat model, architecture, checkpoint material, and design notes
- `src/license_core/`: license parsing, verification, policy, and enforcement logic
- `src/app_integration/`: example host application integration points
- `tests/`: unit and security tests
- `eval/`: evaluation harnesses, microbenchmarks, and attack experiments
- `results/`: raw and processed experiment outputs
- `scripts/`: build, test, analysis, and reproduction helpers
- `report/`: final written report sources
- `slides/`: presentation or demo material
- `logs/gemini/`: required generative AI logs

## Suggested First Implementation Scope

1. Define the license format and trust anchors.
2. Implement a minimal verifier that accepts only signed, unexpired licenses.
3. Integrate the verifier with a toy host application so the protected path is concrete.
4. Add negative tests for malformed licenses, missing licenses, expired licenses, and signature failures.
5. Add security experiments for parser robustness, control-flow bypass attempts, timing leakage, speculative access assumptions, and fault-injection resilience.

## Reproducibility Rule

Every result in the final report should be traceable to a script, command, input artifact, and generated output under this repository.


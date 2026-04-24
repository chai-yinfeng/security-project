# COMS 6424 Final Project: Option 2

This repository is organized for Option 2: designing a self-checking software enforcement system for macOS on Apple Silicon (ARM64).

## Immediate Goal

Prepare Checkpoint 1 for Monday, April 20, 2026:

- threat model
- detailed system architecture
- step-by-step project plan and milestones
- final artifact list
- collaboration plan and responsibilities

## Working Direction

The project should treat enforcement as a protected subsystem compiled together with a host application. The design should defend both:

- embedded policy integrity, such as signed claims, hardware binding, and executable binding
- enforcement integrity, such as control flow, parser behavior, authorization decisions, and anti-bypass logic

The current design pass is intentionally scoped to macOS on Apple Silicon. The protected executable performs a self-check at runtime before entering the protected path.

## Repository Layout

- `docs/`: threat model, architecture, checkpoint material, and design notes
- `include/`: public interface contracts
- `src/`: source placeholders and ownership notes
- `tests/`: unit and security tests
- `eval/`: evaluation harnesses, microbenchmarks, and attack experiments
- `results/`: raw and processed experiment outputs
- `scripts/`: build, test, analysis, and reproduction helpers
- `report/`: final written report sources
- `slides/`: presentation or demo material
- `logs/gemini/`: required generative AI logs

## Suggested First Implementation Scope

1. Freeze the embedded policy/blob layout and interface contracts.
2. Implement the build-time profiler, issuer, signer, and embedding workflow.
3. Implement the Rust core layers for embedded-policy reading, runtime environment query, verification, and authorization.
4. Integrate the Rust core with the C host so the protected path is concrete.
5. Add relocation, clock-tampering, tampering, and timing-oriented evaluation.

## Reproducibility Rule

Every result in the final report should be traceable to a script, command, input artifact, and generated output under this repository.

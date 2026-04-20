# Artifact List

This file lists the artifacts expected in the final submission for the Option 2 license enforcement project. The list should remain aligned with the checkpoint plan and final report.

## Source Code

- Rust license core under `src/license_core`
- C toy host application under `src/app_integration`
- C ABI header under `include`
- license-generation helpers under `scripts`
- build and test helpers under `scripts`

## Build and Configuration

- top-level `Makefile`
- Rust `Cargo.toml` and `Cargo.lock`
- optional `rust-toolchain.toml` for reproducible Rust version selection
- documented compiler and OS environment
- build instructions in `README.md`

## License Format Artifacts

- canonical CBOR license schema or field specification
- sample valid license
- sample expired license
- sample wrong-product license
- sample tampered license
- sample malformed CBOR inputs
- test signing key used only for reproducible experiments
- embedded public verification key used by the prototype

Production issuer private keys are never part of the client or submission. Any submitted private key must be a test-only key clearly labeled for reproducibility.

## Tests

- Rust unit tests for parsing, canonical CBOR validation, signature verification, and policy checks
- C integration tests for host-to-core calls through the C ABI
- valid-license acceptance test
- missing-license rejection test
- malformed-license rejection tests
- tampered-field rejection tests
- invalid-signature rejection tests
- expired-license rejection test
- wrong-product rejection test
- FFI misuse tests, including null pointer and invalid path cases

## Software Security Evaluation

- malformed input corpus
- parser stress or fuzzing harness
- sanitizer build results for the C host and integration layer where available
- field-mutation tests showing signed fields cannot be changed without denial
- documentation of fail-closed behavior and error-handling paths
- notes on control-flow bypass risks and static-linking assumptions

## Microarchitectural Evaluation

- timing measurement harness for valid versus invalid license paths
- timing result logs under `results/raw`
- processed timing summaries under `results/processed`
- review of secret-dependent branches and memory accesses
- simulated fault-injection tests for corrupted license bytes and corrupted decision state
- documented assumptions for speculation and Rowhammer risks
- optional cache-observation experiments if tooling and time permit

## Documentation

- threat model in `docs/threat_model.md`
- architecture document in `docs/architecture.md`
- project plan in `docs/project_plan.md`
- checkpoint material in `docs/checkpoint1.md`
- final report under `report`
- slides or demo material under `slides`
- third-party dependency notes under `third_party`

## Results

- raw command outputs and experiment logs under `results/raw`
- processed summaries, tables, and plots under `results/processed`
- commands sufficient to reproduce every reported result
- notes explaining any failed, skipped, or inconclusive experiments

## AI Logs

- all required Gemini logs under `logs/gemini`
- any relevant AI-assisted design notes needed to explain project decisions

## Final Submission Checklist

- source code builds from a clean checkout
- `make test` or equivalent runs the main test suite
- final report cites the exact commands used for results
- all assumptions and residual risks are explicitly documented
- enhanced deployment options are separated from baseline claims
- no real production secrets are committed

## Planned Division of Work

All team members will participate in all major aspects of the project, including design discussions, implementation, evaluation, and documentation. To ensure a balanced workload and clear progress, each member will take primary responsibility for specific components:

- **Peiheng Li (pl2978)**: Will lead the threat model design and attack surface analysis. Responsible for defining attacker capabilities, identifying security goals, and constructing the attack-to-mitigation mapping. Will also contribute to system design and implementation.
- **Yinfeng Chai (yc4669)**: Will lead the system architecture design, including component decomposition, trust boundary definition, and interface specification. Will also participate in threat modeling, implementation planning, and documentation.
- **Peng Chen (pc3193)**: Will lead the implementation of the Rust license core, including CBOR parsing, signature verification, and policy enforcement logic. Will also contribute to architecture refinement and testing design.
- **Wenxuan Xu (wx2341)**: Will lead the C host application and integration layer, including the Rust–C ABI interface, build system, and integration testing. Will also contribute to implementation and evaluation.
- **Xiangyu Liao (xl3581)**: Will lead the evaluation and testing design, including malformed input testing, fuzzing, and microarchitectural risk analysis. Will also contribute to system design and implementation.

Overall, all team members will contribute to design decisions, code development, testing, and documentation, ensuring a balanced and collaborative workflow throughout the project.

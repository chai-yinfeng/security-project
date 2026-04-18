# Project Plan

## Milestone 1: Checkpoint 1 Package

- finalize threat model
- choose implementation language and crypto library
- draw architecture and trust boundary
- define final artifact list
- assign responsibilities

## Milestone 2: Minimal Correctness Prototype

- define canonical license format
- implement license parser
- implement signature verification
- integrate checker with a toy host application
- add unit tests for accept and reject cases

## Milestone 3: Software Attack Evaluation

- malformed input corpus
- fuzzing or parser stress tests
- sanitizer runs
- bypass-oriented tests for skipped checks, modified fields, and corrupted state
- compiler hardening configuration

## Milestone 4: Microarchitectural Risk Evaluation

- identify secret-dependent branches and memory accesses
- measure timing variation for valid and invalid inputs
- evaluate cache-observable behavior for selected code paths
- document speculative execution assumptions and mitigations
- document Rowhammer threat assumptions and platform-dependent mitigations

## Milestone 5: Final Report and Demo

- collect reproducible commands and outputs
- summarize results and residual risks
- prepare report figures and tables
- prepare presentation or demo script
- include required AI logs


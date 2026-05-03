#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN="$ROOT_DIR/artifacts/bin/license_demo"

"$ROOT_DIR/scripts/build_pipeline.sh" >/tmp/coms6424_debugger_constraint_build.log

set +e
OUTPUT="$(COMS6424_SIMULATE_DEBUGGER=1 "$BIN" 2>&1)"
STATUS=$?
set -e

printf '%s\n' "$OUTPUT"

if [[ $STATUS -eq 0 ]]; then
  echo "debugger constraint smoke test failed: binary exited successfully" >&2
  exit 1
fi

if [[ "$OUTPUT" != *"license denied"* ]]; then
  echo "debugger constraint smoke test failed: expected license denial output" >&2
  exit 1
fi

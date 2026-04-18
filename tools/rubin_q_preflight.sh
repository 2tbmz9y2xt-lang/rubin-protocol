#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MANIFEST_ARG=${1:-}

if [ -z "$MANIFEST_ARG" ]; then
  echo "BLOCKED: usage: tools/rubin_q_preflight.sh tools/agent_tasks/<Q-ID>.json"
  exit 1
fi

MANIFEST_PATH=$(python3 - "$MANIFEST_ARG" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1]).expanduser()
if not path.is_absolute():
    path = (Path.cwd() / path).resolve()
print(path)
PY
)

if [ ! -f "$MANIFEST_PATH" ]; then
  echo "BLOCKED: manifest not found: $MANIFEST_PATH"
  exit 1
fi

REPO_ROOT=$(git -C "$(dirname "$MANIFEST_PATH")" rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$REPO_ROOT" ]; then
  echo "BLOCKED: unable to discover repo root for manifest $MANIFEST_PATH"
  exit 1
fi

if ! python3 - "$SCRIPT_DIR" "$MANIFEST_PATH" <<'PY'
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])

from rubin_agent_contract import load_manifest

load_manifest(Path(sys.argv[2]))
print("PASS: manifest schema")
PY
then
  echo "BLOCKED: q preflight"
  exit 1
fi

if ! python3 "$SCRIPT_DIR/rubin_agent_scope_guard.py" --q-manifest "$MANIFEST_PATH"; then
  echo "BLOCKED: q preflight"
  exit 1
fi

if ! python3 "$SCRIPT_DIR/rubin_invariant_scan.py" --q-manifest "$MANIFEST_PATH"; then
  echo "BLOCKED: q preflight"
  exit 1
fi

TMP_ROOT=${TMPDIR:-/tmp}
TMP_ROOT=${TMP_ROOT%/}
if [ -z "$TMP_ROOT" ]; then
  TMP_ROOT=/
fi
COMMAND_LIST=$(mktemp "$TMP_ROOT/rubin-q-preflight.XXXXXX")
trap 'rm -f "$COMMAND_LIST"' EXIT HUP INT TERM

python3 - "$MANIFEST_PATH" > "$COMMAND_LIST" <<'PY'
import json
from pathlib import Path
import sys

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for command in manifest["required_tests"]:
    print(command)
PY

while IFS= read -r command; do
  [ -n "$command" ] || continue
  echo "RUN: $command"
  if ! (cd "$REPO_ROOT" && sh -c "$command"); then
    echo "BLOCKED: q preflight"
    exit 1
  fi
done < "$COMMAND_LIST"

rm -f "$COMMAND_LIST"
trap - EXIT HUP INT TERM

echo "PASS: q preflight"

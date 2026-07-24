#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export PATH="$HOME/.elan/bin:/opt/homebrew/bin:$PATH"

echo "[check] lake build"
lake build

echo "[check] package unit tests"
python3 -m unittest discover -s tests -p 'test_*.py'

echo "[check] formal registry truth"
python3 tools/check_formal_registry_truth.py

echo "[check] ok"

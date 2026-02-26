#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:---local}"
export PATH="$(go env GOPATH)/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

usage() {
  cat <<'EOF'
Usage:
  scripts/security/precheck.sh [--local|--ci]

Description:
  Runs a shared security precheck pipeline for local runs and GitHub Actions:
    - semgrep (ERROR severity only)
    - gosec (high severity + high confidence)
    - govulncheck (Go)
    - cargo audit (Rust)
EOF
}

require_cmd() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $command_name" >&2
    exit 1
  fi
}

ensure_semgrep() {
  if command -v semgrep >/dev/null 2>&1; then
    return 0
  fi
  echo "semgrep not found; installing with pip --user"
  python3 -m pip install --user semgrep
  export PATH="$HOME/.local/bin:$PATH"
  require_cmd semgrep
}

ensure_go_tool() {
  local tool_name="$1"
  local module_path="$2"
  if command -v "$tool_name" >/dev/null 2>&1; then
    return 0
  fi
  echo "$tool_name not found; installing via go install $module_path"
  go install "$module_path"
  export PATH="$(go env GOPATH)/bin:$PATH"
  require_cmd "$tool_name"
}

ensure_cargo_tool() {
  local tool_name="$1"
  local install_name="$2"
  if command -v "$tool_name" >/dev/null 2>&1; then
    return 0
  fi
  echo "$tool_name not found; installing via cargo install $install_name"
  cargo install "$install_name" --locked
  require_cmd "$tool_name"
}

log_step() {
  echo
  echo "==> $1"
}

case "$MODE" in
  --local|--ci) ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    echo "ERROR: unknown mode: $MODE" >&2
    usage
    exit 1
    ;;
esac

require_cmd go
require_cmd cargo
ensure_semgrep
ensure_go_tool gosec github.com/securego/gosec/v2/cmd/gosec@latest
ensure_go_tool govulncheck golang.org/x/vuln/cmd/govulncheck@latest
ensure_cargo_tool cargo-audit cargo-audit

log_step "Semgrep (ERROR severity)"
SEMGREP_RULES="$ROOT_DIR/tools/security/semgrep-rules.yml"
if [[ ! -f "$SEMGREP_RULES" ]]; then
  echo "ERROR: semgrep rules file not found: $SEMGREP_RULES" >&2
  exit 1
fi
semgrep scan \
  --config "$SEMGREP_RULES" \
  --error \
  --metrics=off \
  "$ROOT_DIR/clients/go" \
  "$ROOT_DIR/clients/rust"

log_step "gosec (high/high)"
(
  cd "$ROOT_DIR/clients/go"
  gosec -severity high -confidence high -fmt text ./...
)

log_step "govulncheck"
(
  cd "$ROOT_DIR/clients/go"
  govulncheck ./...
)

log_step "cargo audit"
(
  cd "$ROOT_DIR/clients/rust"
  cargo audit --deny warnings
)

echo
echo "security precheck: PASS"

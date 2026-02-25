#!/usr/bin/env bash
set -euo pipefail

#
# dev-env.sh
#
# Purpose:
# - Make local runs reproducible in macOS/Homebrew environments where Codex sessions may start
#   with a minimal PATH (missing /opt/homebrew/bin).
# - Provide a single, project-standard way to run commands with required toolchains available.
#
# Usage:
#   # Print environment summary + tool versions (exits 0/1)
#   scripts/dev-env.sh
#
#   # Run a command with fixed PATH and basic toolchain checks
#   scripts/dev-env.sh -- <command> [args...]
#

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

prepend_path_if_exists() {
  local dir="$1"
  if [[ -d "$dir" ]]; then
    case ":${PATH}:" in
      *":${dir}:"*) ;;
      *) PATH="${dir}:${PATH}" ;;
    esac
  fi
}

# Homebrew defaults
prepend_path_if_exists "/opt/homebrew/bin"
prepend_path_if_exists "/usr/local/bin"

# Lean toolchain (elan) defaults
prepend_path_if_exists "${HOME}/.elan/bin"

export PATH

select_openssl() {
  # Optional override for CI / Linux / Windows dev envs where we bring our own OpenSSL bundle.
  # Example:
  #   RUBIN_OPENSSL_PREFIX="$HOME/.cache/rubin-openssl/bundle-3.5.5" scripts/dev-env.sh -- openssl version -a
  if [[ -n "${RUBIN_OPENSSL_PREFIX:-}" ]]; then
    if [[ -x "${RUBIN_OPENSSL_PREFIX}/bin/openssl" ]]; then
      prepend_path_if_exists "${RUBIN_OPENSSL_PREFIX}/bin"
      export OPENSSL_DIR="${RUBIN_OPENSSL_PREFIX}"
      local rubin_pkg_paths=()
      if [[ -d "${RUBIN_OPENSSL_PREFIX}/lib64/pkgconfig" ]]; then
        rubin_pkg_paths+=("${RUBIN_OPENSSL_PREFIX}/lib64/pkgconfig")
      fi
      if [[ -d "${RUBIN_OPENSSL_PREFIX}/lib/pkgconfig" ]]; then
        rubin_pkg_paths+=("${RUBIN_OPENSSL_PREFIX}/lib/pkgconfig")
      fi
      if [[ ${#rubin_pkg_paths[@]} -gt 0 ]]; then
        export PKG_CONFIG_PATH="$(IFS=:; echo "${rubin_pkg_paths[*]}")${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
      fi
      if [[ -d "${RUBIN_OPENSSL_PREFIX}/lib/ossl-modules" ]]; then
        export OPENSSL_MODULES="${RUBIN_OPENSSL_PREFIX}/lib/ossl-modules"
      elif [[ -d "${RUBIN_OPENSSL_PREFIX}/lib64/ossl-modules" ]]; then
        export OPENSSL_MODULES="${RUBIN_OPENSSL_PREFIX}/lib64/ossl-modules"
      fi
    else
      echo "ERROR: RUBIN_OPENSSL_PREFIX is set but missing bin/openssl: ${RUBIN_OPENSSL_PREFIX}" >&2
      return 1
    fi
  fi

  # Prefer Homebrew OpenSSL@3 to avoid macOS LibreSSL default.
  # This is required by the normative non-consensus profile:
  #   spec/RUBIN_CRYPTO_BACKEND_PROFILE.md (OpenSSL 3.5+).
  if [[ -z "${OPENSSL_DIR:-}" ]]; then
    if [[ -x "/opt/homebrew/opt/openssl@3/bin/openssl" ]]; then
      prepend_path_if_exists "/opt/homebrew/opt/openssl@3/bin"
      export OPENSSL_DIR="/opt/homebrew/opt/openssl@3"
      export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
      if [[ -d "/opt/homebrew/opt/openssl@3/lib/ossl-modules" ]]; then
        export OPENSSL_MODULES="/opt/homebrew/opt/openssl@3/lib/ossl-modules"
      fi
    elif [[ -x "/usr/local/opt/openssl@3/bin/openssl" ]]; then
      prepend_path_if_exists "/usr/local/opt/openssl@3/bin"
      export OPENSSL_DIR="/usr/local/opt/openssl@3"
      export PKG_CONFIG_PATH="/usr/local/opt/openssl@3/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
      if [[ -d "/usr/local/opt/openssl@3/lib/ossl-modules" ]]; then
        export OPENSSL_MODULES="/usr/local/opt/openssl@3/lib/ossl-modules"
      fi
    fi
  fi

  # Optional explicit overrides (useful for FIPS module bring-up).
  if [[ -n "${RUBIN_OPENSSL_MODULES:-}" ]]; then
    export OPENSSL_MODULES="${RUBIN_OPENSSL_MODULES}"
  fi
  if [[ -n "${RUBIN_OPENSSL_CONF:-}" ]]; then
    export OPENSSL_CONF="${RUBIN_OPENSSL_CONF}"
  fi

  if [[ "${RUBIN_OPENSSL_FIPS_MODE:-off}" == "only" ]]; then
    local openssl_base=""
    if [[ -n "${RUBIN_OPENSSL_PREFIX:-}" ]]; then
      openssl_base="${RUBIN_OPENSSL_PREFIX}"
    elif [[ -n "${OPENSSL_DIR:-}" ]]; then
      openssl_base="${OPENSSL_DIR}"
    fi

    if [[ -n "${openssl_base}" ]]; then
      if [[ -z "${OPENSSL_MODULES:-}" && -d "${openssl_base}/lib/ossl-modules" ]]; then
        export OPENSSL_MODULES="${openssl_base}/lib/ossl-modules"
      elif [[ -z "${OPENSSL_MODULES:-}" && -d "${openssl_base}/lib64/ossl-modules" ]]; then
        export OPENSSL_MODULES="${openssl_base}/lib64/ossl-modules"
      fi
      if [[ -z "${OPENSSL_CONF:-}" && -f "${openssl_base}/ssl/openssl-fips.cnf" ]]; then
        export OPENSSL_CONF="${openssl_base}/ssl/openssl-fips.cnf"
      fi
    fi
  fi
}

select_openssl

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: missing required tool in PATH: ${cmd}" >&2
    return 1
  fi
}

maybe_cmd() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

print_versions() {
  echo "repo_root: ${REPO_ROOT}"
  echo "PATH: ${PATH}"
  if [[ -n "${OPENSSL_DIR:-}" ]]; then
    echo "OPENSSL_DIR: ${OPENSSL_DIR}"
  fi
  if [[ -n "${OPENSSL_MODULES:-}" ]]; then
    echo "OPENSSL_MODULES: ${OPENSSL_MODULES}"
  fi
  if [[ -n "${OPENSSL_CONF:-}" ]]; then
    echo "OPENSSL_CONF: ${OPENSSL_CONF}"
  fi
  if [[ -n "${PKG_CONFIG_PATH:-}" ]]; then
    echo "PKG_CONFIG_PATH: ${PKG_CONFIG_PATH}"
  fi
  echo

  echo "git: $(git --version 2>/dev/null || echo 'missing')"
  echo "python3: $(python3 --version 2>/dev/null || echo 'missing')"
  echo "node: $(node --version 2>/dev/null || echo 'missing')"
  echo "npm: $(npm --version 2>/dev/null || echo 'missing')"
  echo "go: $(go version 2>/dev/null || echo 'missing')"
  echo "rustc: $(rustc --version 2>/dev/null || echo 'missing')"
  echo "cargo: $(cargo --version 2>/dev/null || echo 'missing')"
  echo "openssl: $(openssl version 2>/dev/null || echo 'missing')"
  if maybe_cmd gh; then
    echo "gh: $(gh --version 2>/dev/null | head -n 1 || echo 'present')"
  else
    echo "gh: missing (ok unless opening PRs from CLI)"
  fi

  if maybe_cmd elan; then
    echo "elan: $(elan --version 2>/dev/null || echo 'missing')"
  else
    echo "elan: missing (ok unless running formal/Lean locally)"
  fi
  if maybe_cmd lake; then
    echo "lake: $(lake --version 2>/dev/null || echo 'missing')"
  else
    echo "lake: missing (ok unless running formal/Lean locally)"
  fi
}

check_required() {
  need_cmd git
  need_cmd python3
  need_cmd node
  need_cmd npm
  need_cmd go
  need_cmd cargo
  need_cmd rustc
  need_cmd openssl
  need_cmd pkg-config
}

if [[ "${1:-}" == "--" ]]; then
  shift
  if [[ $# -eq 0 ]]; then
    echo "ERROR: dev-env.sh: missing command after --" >&2
    exit 2
  fi
  check_required
  exec "$@"
fi

print_versions
check_required
echo
echo "OK: dev env looks usable. Tip: scripts/dev-env.sh -- <cmd>"

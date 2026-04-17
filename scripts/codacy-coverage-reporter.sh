#!/usr/bin/env bash
set -euo pipefail

PINNED_VERSION="14.1.3"
LINUX_SHA512="73a6c93fc5db509fd0423d6e545759c3f61d8360ee12054e32a9277daab6add0da6c6639248f6ed6c0042366440293ebc0b6144325aef52c5d3d4b230d65eb17"
DARWIN_SHA512="bdd9403f0d9b54626b8494890cc8c4b212b694e7f5c49a90733608507cd4555f709d23b592dc81d571bef242ee93db0fe293aefa7e8720930886f39cf2b55d0b"

download_file() {
  local url="$1"
  local out="$2"

  if command -v curl >/dev/null 2>&1; then
    if curl --fail --silent --show-error --location "$url" -o "$out"; then
      return 0
    fi
    echo "ERROR: curl failed to download $url" >&2
    return 1
  fi
  if command -v wget >/dev/null 2>&1; then
    if wget -q "$url" -O "$out"; then
      return 0
    fi
    echo "ERROR: wget failed to download $url" >&2
    return 1
  fi
  echo "ERROR: curl or wget required to download Codacy reporter" >&2
  return 1
}

compute_sha512() {
  local path="$1"
  local output=""

  if command -v sha512sum >/dev/null 2>&1; then
    output="$(sha512sum "$path")" || {
      echo "ERROR: sha512sum failed for $path" >&2
      return 1
    }
    printf '%s\n' "${output%% *}"
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    output="$(shasum -a 512 "$path")" || {
      echo "ERROR: shasum failed for $path" >&2
      return 1
    }
    printf '%s\n' "${output%% *}"
    return 0
  fi
  echo "ERROR: sha512 tool missing (need sha512sum or shasum -a 512)" >&2
  return 1
}

verify_sha512() {
  local path="$1"
  local expected="$2"
  local actual

  actual="$(compute_sha512 "$path")" || return 2
  [[ "$actual" == "$expected" ]]
}

platform_config() {
  local os_name_arch
  os_name_arch="$(uname -sm)"

  case "$os_name_arch" in
    "Linux x86_64")
      CODACY_BINARY_NAME="codacy-coverage-reporter-linux"
      CODACY_SHA512="$LINUX_SHA512"
      ;;
    "Darwin arm64"|"Darwin x86_64")
      CODACY_BINARY_NAME="codacy-coverage-reporter-darwin"
      CODACY_SHA512="$DARWIN_SHA512"
      ;;
    *)
      echo "ERROR: unsupported Codacy reporter platform: $os_name_arch" >&2
      return 1
      ;;
  esac
}

ensure_reporter() {
  local reporter_version="${CODACY_REPORTER_VERSION:-$PINNED_VERSION}"
  if [[ "$reporter_version" != "$PINNED_VERSION" ]]; then
    echo "ERROR: unsupported CODACY_REPORTER_VERSION=$reporter_version (expected $PINNED_VERSION)" >&2
    return 1
  fi

  platform_config

  local cache_root="${CODACY_REPORTER_TMP_FOLDER:-${HOME:-${TMPDIR:-/tmp}}/.cache/codacy/coverage-reporter}"
  local reporter_dir="$cache_root/$reporter_version"
  CODACY_REPORTER_PATH="$reporter_dir/$CODACY_BINARY_NAME"
  local tmp_path
  local reporter_url="https://artifacts.codacy.com/bin/codacy-coverage-reporter/$reporter_version/$CODACY_BINARY_NAME"
  local verify_rc=0

  mkdir -p "$reporter_dir"

  if [[ -x "$CODACY_REPORTER_PATH" ]]; then
    if verify_sha512 "$CODACY_REPORTER_PATH" "$CODACY_SHA512"; then
      return 0
    else
      verify_rc=$?
    fi
    if [[ $verify_rc -eq 2 ]]; then
      return 1
    fi
    rm -f "$CODACY_REPORTER_PATH"
  fi

  tmp_path="$(mktemp "${reporter_dir}/${CODACY_BINARY_NAME}.tmp.XXXXXX")"
  if ! download_file "$reporter_url" "$tmp_path"; then
    rm -f "$tmp_path"
    return 1
  fi
  if verify_sha512 "$tmp_path" "$CODACY_SHA512"; then
    verify_rc=0
  else
    verify_rc=$?
  fi
  if [[ $verify_rc -ne 0 ]]; then
    rm -f "$tmp_path"
    if [[ $verify_rc -eq 2 ]]; then
      return 1
    fi
    echo "ERROR: Codacy reporter checksum mismatch for $reporter_url" >&2
    return 1
  fi
  chmod +x "$tmp_path"
  mv "$tmp_path" "$CODACY_REPORTER_PATH"
}

main() {
  ensure_reporter
  if [[ "${1:-}" == "download" ]]; then
    printf '%s\n' "$CODACY_REPORTER_PATH"
    return 0
  fi
  "$CODACY_REPORTER_PATH" "$@"
}

main "$@"

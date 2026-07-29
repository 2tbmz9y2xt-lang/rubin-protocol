#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_DIR="${ROOT_DIR}/clients/go"
CONSENSUS_DIR="${GO_DIR}/consensus"
NODE_DIR="${GO_DIR}/node"
P2P_DIR="${GO_DIR}/node/p2p"
ARTIFACTS_DIR="${ROOT_DIR}/.artifacts/fuzz-stage2"
FUZZ_TIME="${FUZZ_TIME:-45s}"
FUZZ_MINIMIZE_TIME="${FUZZ_MINIMIZE_TIME:-5s}"

TARGETS=(
  "./consensus:FuzzValidateTxCovenantsGenesis"
  "./consensus:FuzzVerifySigDeterminism"
  "./consensus:FuzzRetargetV1Arithmetic"
  "./consensus:FuzzParseTxDAKinds"
  "./consensus:FuzzApplyNonCoinbaseTxBasic"
  "./consensus:FuzzSighashV1Digest"
  "./consensus:FuzzValidateBlockBasic"
  "./consensus:FuzzPowCheck"
  "./consensus:FuzzCompactShortID"
  "./consensus:FuzzParseHTLCCovenantData"
  "./consensus:FuzzParseVaultCovenantData"
  "./consensus:FuzzParseMultisigCovenantData"
  "./consensus:FuzzForkWork"
  "./consensus:FuzzBlockSubsidy"
  "./consensus:FuzzMerkleRootTxids"
  "./consensus:FuzzMarshalTxRoundtrip"
  "./consensus:FuzzVerifySigDispatch"
  "./consensus:FuzzSigCacheDeterminism"
  "./consensus:FuzzSigCheckQueueFlush"
  "./consensus:FuzzSigCacheConcurrentAccess"
  "./consensus:FuzzSuiteRegistryLookup"
  "./consensus:FuzzSigCheckQueueWithCacheIntegration"
  "./consensus:FuzzConnectBlockInMemory"
  "./consensus:FuzzTxDepGraphBuild"
  "./consensus:FuzzDAChunkHashVerify"
  "./consensus:FuzzDAPayloadCommitVerify"
  "./consensus:FuzzUtxoApplyNonCoinbase"
  "./node:FuzzMempoolFeeWeightOrdering"
  "./node:FuzzMempoolRollingFloorBoundaries"
  "./node:FuzzDaFeeFloorPolicyBoundaries"
  "./node/p2p:FuzzReadFrame"
  "./node/p2p:FuzzDecodeVersionPayload"
)

usage() {
  cat <<USAGE
Usage: scripts/ci/run_fuzz_stage2.sh [--list-json | --target <pkg:Target>]

Runs the bounded Go stage2 fuzz target list and writes reproducibility metadata
under .artifacts/fuzz-stage2/. The script does not commit, push, regenerate
tracked fixtures, or open issues.

Modes:
  (no args)          run every target in the list (local use)
  --list-json        print the target list as a compact JSON array and exit
  --target <spec>    run exactly one listed "pkg:Target" spec (CI matrix use)

Environment:
  FUZZ_TIME=${FUZZ_TIME}
  FUZZ_MINIMIZE_TIME=${FUZZ_MINIMIZE_TIME}

Artifact metadata includes:
  commit SHA, package, target, corpus/artifact paths, command, log path.
USAGE
}

# TARGETS entries are trusted in-file literals ("pkg:Target", no quotes or
# backslashes), so plain string concatenation yields valid JSON.
list_json() {
  local out="["
  local first=1
  local spec
  for spec in "${TARGETS[@]}"; do
    if ((first)); then first=0; else out+=","; fi
    out+="\"${spec}\""
  done
  printf '%s]\n' "${out}"
}

MODE="all"
TARGET_SPEC=""
# Full-loop mode only on truly empty argv: an empty-string first arg is rejected.
if (($# > 0)); then
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --list-json)
      if (($# > 1)); then
        echo "FAIL: --list-json takes no extra arguments" >&2
        exit 2
      fi
      list_json
      exit 0
      ;;
    --target)
      if (($# != 2)); then
        echo "FAIL: --target requires exactly one pkg:Target spec" >&2
        usage >&2
        exit 2
      fi
      MODE="single"
      TARGET_SPEC="$2"
      ;;
    *)
      echo "FAIL: unexpected arguments: $*" >&2
      usage >&2
      exit 2
      ;;
  esac
fi

if [[ "${MODE}" == "single" ]]; then
  target_known=0
  for spec in "${TARGETS[@]}"; do
    if [[ "${spec}" == "${TARGET_SPEC}" ]]; then
      target_known=1
      break
    fi
  done
  if [[ "${target_known}" -ne 1 ]]; then
    echo "FAIL: unknown target spec: ${TARGET_SPEC}" >&2
    exit 2
  fi
fi

# {1,6} bounds the value so the +600 arithmetic below can never wrap int64.
if [[ ! "${FUZZ_TIME}" =~ ^[0-9]{1,6}s$ ]]; then
  echo "FAIL: FUZZ_TIME must match ^[0-9]{1,6}s\$ (got: ${FUZZ_TIME})" >&2
  exit 2
fi
# 10# forces base-10: zero-padded input (e.g. 08s) is valid per the stated format but would otherwise be parsed as octal.
fuzz_seconds="$((10#${FUZZ_TIME%s}))"
# The +600s margin covers baseline-coverage gathering, minimisation
# (FUZZ_MINIMIZE_TIME), coordinator shutdown, and runner starvation; without an
# explicit -timeout the default 10m go test timeout would become the binding
# kill once fuzztime reaches minutes.
GO_TEST_TIMEOUT="$((fuzz_seconds + 600))s"

COMMIT_SHA="${GITHUB_SHA:-$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || printf '%s' unknown)}"

mkdir -p "${ARTIFACTS_DIR}"
STATUS=0

# shellcheck disable=SC2329
# Invoked indirectly via trap on EXIT.
collect_artifacts() {
  : > "${ARTIFACTS_DIR}/go-fuzz-files.txt"
  local tar_paths=()
  for dir in "${CONSENSUS_DIR}" "${NODE_DIR}" "${P2P_DIR}"; do
    if [[ -d "${dir}/testdata/fuzz" ]]; then
      find "${dir}/testdata/fuzz" -type f | sort >> "${ARTIFACTS_DIR}/go-fuzz-files.txt" || true
      tar_paths+=("${dir#"${GO_DIR}/"}/testdata/fuzz")
    fi
  done
  if [[ "${#tar_paths[@]}" -gt 0 ]]; then
    tar -czf "${ARTIFACTS_DIR}/go-fuzz-testdata.tgz" \
      -C "${GO_DIR}" \
      "${tar_paths[@]}" 2>/dev/null || true
  fi
}

seed_path_for_pkg() {
  local pkg="$1"
  local target="$2"

  case "${pkg}" in
    ./consensus)
      printf 'clients/go/consensus/testdata/fuzz/%s\n' "${target}"
      ;;
    ./node/p2p)
      printf 'clients/go/node/p2p/testdata/fuzz/%s\n' "${target}"
      ;;
    *)
      printf 'clients/go/%s/testdata/fuzz/%s\n' "${pkg#./}" "${target}"
      ;;
  esac
}

quote_env_value() {
  local value="$1"
  printf "'"
  printf '%s' "${value}" | sed "s/'/'\"'\"'/g"
  printf "'"
}

write_env_field() {
  local key="$1"
  local value="$2"
  printf '%s=%s\n' "${key}" "$(quote_env_value "${value}")"
}

write_run_metadata() {
  {
    write_env_field "commit_sha" "${COMMIT_SHA}"
    write_env_field "workflow_run_id" "${GITHUB_RUN_ID:-local}"
    write_env_field "workflow_run_attempt" "${GITHUB_RUN_ATTEMPT:-local}"
    write_env_field "fuzz_time" "${FUZZ_TIME}"
    write_env_field "fuzz_minimize_time" "${FUZZ_MINIMIZE_TIME}"
    write_env_field "artifact_dir" ".artifacts/fuzz-stage2"
    write_env_field "mutation_policy" "manual-only; ci does not commit, push, regenerate tracked fixtures, or open issues"
    write_env_field "promotion_docs" "conformance/README.md#fuzz-crash-promotion-manual-only"
  } > "${ARTIFACTS_DIR}/run-metadata.env"
}

write_target_metadata() {
  local pkg="$1"
  local target="$2"
  local metadata_file="${ARTIFACTS_DIR}/${target}.metadata.env"
  local artifacts_path
  local corpus_path
  corpus_path="$(seed_path_for_pkg "${pkg}" "${target}")"
  artifacts_path="${corpus_path}"

  {
    write_env_field "commit_sha" "${COMMIT_SHA}"
    write_env_field "package" "${pkg}"
    write_env_field "target" "${target}"
    write_env_field "corpus_path" "${corpus_path}"
    write_env_field "artifacts_path" "${artifacts_path}"
    write_env_field "seed_path" "${corpus_path}"
    write_env_field "go_test_timeout" "${GO_TEST_TIMEOUT}"
    write_env_field "command" "cd clients/go && go test -run=^$ -fuzz=\"${target}\" -fuzztime=\"${FUZZ_TIME}\" -fuzzminimizetime=\"${FUZZ_MINIMIZE_TIME}\" -timeout=\"${GO_TEST_TIMEOUT}\" \"${pkg}\""
    write_env_field "log_path" ".artifacts/fuzz-stage2/${target}.log"
  } > "${metadata_file}"
}

run_one_target() {
  local pkg="$1"
  local target="$2"
  local log_file="${ARTIFACTS_DIR}/${target}.log"
  local corpus_dir="${GO_DIR}/${pkg#./}/testdata/fuzz/${target}"
  local corpus_before="${ARTIFACTS_DIR}/${target}.corpus-before.txt"
  # Snapshot the corpus file list before the run: the benign-exit classifier
  # treats "no new file here" as proof no crasher was written.
  if [[ -d "${corpus_dir}" ]]; then
    find "${corpus_dir}" -type f | sort > "${corpus_before}"
  else
    : > "${corpus_before}"
  fi
  write_target_metadata "${pkg}" "${target}"
  echo "==> running ${target} (${pkg})" | tee -a "${ARTIFACTS_DIR}/summary.log"
  echo "metadata ${target}: ${ARTIFACTS_DIR}/${target}.metadata.env" >> "${ARTIFACTS_DIR}/summary.log"
  if go test -run=^$ -fuzz="${target}" -fuzztime="${FUZZ_TIME}" -fuzzminimizetime="${FUZZ_MINIMIZE_TIME}" -timeout="${GO_TEST_TIMEOUT}" "${pkg}" >"${log_file}" 2>&1; then
    # `go test -fuzz=<pattern>` matching no fuzz test exits 0, so a renamed or
    # deleted target left in TARGETS would otherwise report a silent green
    # PASS with zero coverage. Warning text pinned empirically on go1.26.5:
    # "testing: warning: no fuzz tests to fuzz".
    if grep -Eq -- '^fuzz: elapsed:' "${log_file}"; then
      echo "PASS ${target}" | tee -a "${ARTIFACTS_DIR}/summary.log"
    elif grep -Fq -- "testing: warning: no fuzz tests to fuzz" "${log_file}"; then
      STATUS=1
      echo "FAIL ${target} (no fuzzing executed — target missing from package?)" | tee -a "${ARTIFACTS_DIR}/summary.log"
    else
      # Measured 2026-07-29: targets whose setup f.Skipf()s on an unavailable
      # crypto backend exit 0 with a bare PASS log; visible-never-silent, and
      # red stays reserved for defect evidence.
      echo "SKIP_FUZZ_SETUP ${target} (fuzz target skipped during setup; zero fuzz coverage — ML-DSA backend unavailable? see RUB-1064)" | tee -a "${ARTIFACTS_DIR}/summary.log"
    fi
  elif "${ROOT_DIR}/scripts/ci/classify_go_fuzz_exit.sh" "${target}" "${fuzz_seconds}" "${log_file}" "${corpus_before}" "${corpus_dir}"; then
    echo "PASS_AFTER_BENIGN_DEADLINE ${target} (upstream fuzztime shutdown race; full budget spent, no defect evidence)" | tee -a "${ARTIFACTS_DIR}/summary.log"
  else
    STATUS=1
    echo "FAIL ${target}" | tee -a "${ARTIFACTS_DIR}/summary.log"
  fi
}

trap collect_artifacts EXIT
write_run_metadata

{
  echo "fuzz stage2 started at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit sha: ${COMMIT_SHA}"
  echo "fuzz time per target: ${FUZZ_TIME}"
  echo "fuzz minimize time: ${FUZZ_MINIMIZE_TIME}"
  echo "go test timeout: ${GO_TEST_TIMEOUT}"
  echo "metadata: ${ARTIFACTS_DIR}/run-metadata.env"
} > "${ARTIFACTS_DIR}/summary.log"

cd "${GO_DIR}"

if [[ "${MODE}" == "single" ]]; then
  run_one_target "${TARGET_SPEC%%:*}" "${TARGET_SPEC##*:}"
else
  for spec in "${TARGETS[@]}"; do
    run_one_target "${spec%%:*}" "${spec##*:}"
  done
fi

echo "fuzz stage2 finished at: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${ARTIFACTS_DIR}/summary.log"
exit "${STATUS}"

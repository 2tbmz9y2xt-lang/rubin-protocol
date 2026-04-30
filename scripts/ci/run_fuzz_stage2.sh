#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_DIR="${ROOT_DIR}/clients/go"
CONSENSUS_DIR="${GO_DIR}/consensus"
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
  "./node/p2p:FuzzReadFrame"
  "./node/p2p:FuzzDecodeVersionPayload"
)

usage() {
  cat <<USAGE
Usage: scripts/ci/run_fuzz_stage2.sh

Runs the bounded Go stage2 fuzz target list and writes reproducibility metadata
under .artifacts/fuzz-stage2/. The script does not commit, push, regenerate
tracked fixtures, or open issues.

Environment:
  FUZZ_TIME=${FUZZ_TIME}
  FUZZ_MINIMIZE_TIME=${FUZZ_MINIMIZE_TIME}

Artifact metadata includes:
  commit SHA, package, target, corpus/artifact paths, command, log path.
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if (($# > 0)); then
  echo "FAIL: unexpected arguments: $*" >&2
  usage >&2
  exit 2
fi

COMMIT_SHA="${GITHUB_SHA:-$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || printf '%s' unknown)}"

mkdir -p "${ARTIFACTS_DIR}"
STATUS=0

# shellcheck disable=SC2329
# Invoked indirectly via trap on EXIT.
collect_artifacts() {
  : > "${ARTIFACTS_DIR}/go-fuzz-files.txt"
  for dir in "${CONSENSUS_DIR}" "${P2P_DIR}"; do
    if [[ -d "${dir}/testdata/fuzz" ]]; then
      find "${dir}/testdata/fuzz" -type f | sort >> "${ARTIFACTS_DIR}/go-fuzz-files.txt" || true
    fi
  done
  if [[ -s "${ARTIFACTS_DIR}/go-fuzz-files.txt" ]]; then
    tar -czf "${ARTIFACTS_DIR}/go-fuzz-testdata.tgz" \
      -C "${GO_DIR}" \
      consensus/testdata/fuzz \
      node/p2p/testdata/fuzz 2>/dev/null || true
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
    write_env_field "command" "cd clients/go && go test -run=^$ -fuzz=\"${target}\" -fuzztime=\"${FUZZ_TIME}\" -fuzzminimizetime=\"${FUZZ_MINIMIZE_TIME}\" \"${pkg}\""
    write_env_field "log_path" ".artifacts/fuzz-stage2/${target}.log"
  } > "${metadata_file}"
}

trap collect_artifacts EXIT
write_run_metadata

{
  echo "fuzz stage2 started at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit sha: ${COMMIT_SHA}"
  echo "fuzz time per target: ${FUZZ_TIME}"
  echo "fuzz minimize time: ${FUZZ_MINIMIZE_TIME}"
  echo "metadata: ${ARTIFACTS_DIR}/run-metadata.env"
} > "${ARTIFACTS_DIR}/summary.log"

cd "${GO_DIR}"

for spec in "${TARGETS[@]}"; do
  pkg="${spec%%:*}"
  target="${spec##*:}"
  log_file="${ARTIFACTS_DIR}/${target}.log"
  write_target_metadata "${pkg}" "${target}"
  echo "==> running ${target} (${pkg})" | tee -a "${ARTIFACTS_DIR}/summary.log"
  echo "metadata ${target}: ${ARTIFACTS_DIR}/${target}.metadata.env" >> "${ARTIFACTS_DIR}/summary.log"
  if ! go test -run=^$ -fuzz="${target}" -fuzztime="${FUZZ_TIME}" -fuzzminimizetime="${FUZZ_MINIMIZE_TIME}" "${pkg}" >"${log_file}" 2>&1; then
    STATUS=1
    echo "FAIL ${target}" | tee -a "${ARTIFACTS_DIR}/summary.log"
  else
    echo "PASS ${target}" | tee -a "${ARTIFACTS_DIR}/summary.log"
  fi
done

echo "fuzz stage2 finished at: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${ARTIFACTS_DIR}/summary.log"
exit "${STATUS}"

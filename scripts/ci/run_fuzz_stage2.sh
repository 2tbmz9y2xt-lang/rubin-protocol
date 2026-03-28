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

mkdir -p "${ARTIFACTS_DIR}"
STATUS=0

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

trap collect_artifacts EXIT

{
  echo "fuzz stage2 started at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "fuzz time per target: ${FUZZ_TIME}"
  echo "fuzz minimize time: ${FUZZ_MINIMIZE_TIME}"
} > "${ARTIFACTS_DIR}/summary.log"

cd "${GO_DIR}"

for spec in "${TARGETS[@]}"; do
  pkg="${spec%%:*}"
  target="${spec##*:}"
  log_file="${ARTIFACTS_DIR}/${target}.log"
  echo "==> running ${target} (${pkg})" | tee -a "${ARTIFACTS_DIR}/summary.log"
  if ! go test -run=^$ -fuzz="${target}" -fuzztime="${FUZZ_TIME}" -fuzzminimizetime="${FUZZ_MINIMIZE_TIME}" "${pkg}" >"${log_file}" 2>&1; then
    STATUS=1
    echo "FAIL ${target}" | tee -a "${ARTIFACTS_DIR}/summary.log"
  else
    echo "PASS ${target}" | tee -a "${ARTIFACTS_DIR}/summary.log"
  fi
done

echo "fuzz stage2 finished at: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${ARTIFACTS_DIR}/summary.log"
exit "${STATUS}"

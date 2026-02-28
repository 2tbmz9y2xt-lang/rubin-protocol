#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONSENSUS_DIR="${ROOT_DIR}/clients/go/consensus"
ARTIFACTS_DIR="${ROOT_DIR}/.artifacts/fuzz-stage2"
FUZZ_TIME="${FUZZ_TIME:-45s}"
FUZZ_MINIMIZE_TIME="${FUZZ_MINIMIZE_TIME:-5s}"

TARGETS=(
  "FuzzValidateTxCovenantsGenesis"
  "FuzzVerifySigDeterminism"
  "FuzzRetargetV1Arithmetic"
  "FuzzParseTxDAKinds"
  "FuzzApplyNonCoinbaseTxBasic"
  "FuzzSighashV1Digest"
  "FuzzValidateBlockBasic"
  "FuzzPowCheck"
  "FuzzCompactShortID"
  "FuzzParseHTLCCovenantData"
  "FuzzParseVaultCovenantData"
  "FuzzParseMultisigCovenantData"
  "FuzzForkWork"
  "FuzzBlockSubsidy"
  "FuzzMerkleRootTxids"
  "FuzzMarshalTxRoundtrip"
)

mkdir -p "${ARTIFACTS_DIR}"
STATUS=0

collect_artifacts() {
  if [[ -d "${CONSENSUS_DIR}/testdata/fuzz" ]]; then
    find "${CONSENSUS_DIR}/testdata/fuzz" -type f | sort > "${ARTIFACTS_DIR}/go-fuzz-files.txt" || true
    tar -czf "${ARTIFACTS_DIR}/go-fuzz-testdata.tgz" -C "${CONSENSUS_DIR}" testdata/fuzz || true
  fi
}

trap collect_artifacts EXIT

{
  echo "fuzz stage2 started at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "fuzz time per target: ${FUZZ_TIME}"
  echo "fuzz minimize time: ${FUZZ_MINIMIZE_TIME}"
} > "${ARTIFACTS_DIR}/summary.log"

cd "${CONSENSUS_DIR}"

for target in "${TARGETS[@]}"; do
  log_file="${ARTIFACTS_DIR}/${target}.log"
  echo "==> running ${target}" | tee -a "${ARTIFACTS_DIR}/summary.log"
  if ! go test -run=^$ -fuzz="${target}" -fuzztime="${FUZZ_TIME}" -fuzzminimizetime="${FUZZ_MINIMIZE_TIME}" ./... >"${log_file}" 2>&1; then
    STATUS=1
    echo "FAIL ${target}" | tee -a "${ARTIFACTS_DIR}/summary.log"
  else
    echo "PASS ${target}" | tee -a "${ARTIFACTS_DIR}/summary.log"
  fi
done

echo "fuzz stage2 finished at: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${ARTIFACTS_DIR}/summary.log"
exit "${STATUS}"

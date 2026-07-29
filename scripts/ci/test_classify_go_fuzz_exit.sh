#!/usr/bin/env bash
# Executing corpus for scripts/ci/classify_go_fuzz_exit.sh. Runs locally in
# seconds, no network. Each case pins the classifier's exact exit code; any
# mismatch fails the suite.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLASSIFIER="${ROOT_DIR}/scripts/ci/classify_go_fuzz_exit.sh"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

TOTAL=0
PASS_COUNT=0
FAILED=0

run_case() {
  local name="$1"
  local expected="$2"
  shift 2
  local actual=0
  TOTAL=$((TOTAL + 1))
  if "${CLASSIFIER}" "$@" >/dev/null 2>&1; then
    actual=0
  else
    actual=$?
  fi
  if [[ "${actual}" -eq "${expected}" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "PASS ${name} (exit ${actual})"
  else
    FAILED=1
    echo "FAIL ${name}: expected exit ${expected}, got ${actual}" >&2
  fi
}

EMPTY_LIST="${WORKDIR}/empty-before.txt"
: > "${EMPTY_LIST}"

# Case 1: the verbatim benign log recorded from nightly run 30422282156
# (2026-07-29): full 45s budget spent, bare deadline, no crasher written.
BENIGN_LOG="${WORKDIR}/benign.log"
cat > "${BENIGN_LOG}" <<'EOF'
fuzz: elapsed: 0s, gathering baseline coverage: 0/2 completed
fuzz: elapsed: 0s, gathering baseline coverage: 2/2 completed, now fuzzing with 4 workers
fuzz: elapsed: 3s, execs: 18013 (6004/sec), new interesting: 3 (total: 5)
fuzz: elapsed: 6s, execs: 23121 (1701/sec), new interesting: 6 (total: 8)
fuzz: elapsed: 9s, execs: 23365 (81/sec), new interesting: 7 (total: 9)
fuzz: elapsed: 12s, execs: 24852 (496/sec), new interesting: 8 (total: 10)
fuzz: elapsed: 15s, execs: 24852 (0/sec), new interesting: 8 (total: 10)
fuzz: elapsed: 18s, execs: 28855 (1336/sec), new interesting: 9 (total: 11)
fuzz: elapsed: 21s, execs: 32203 (1116/sec), new interesting: 11 (total: 13)
fuzz: elapsed: 24s, execs: 60590 (9463/sec), new interesting: 12 (total: 14)
fuzz: elapsed: 27s, execs: 81347 (6919/sec), new interesting: 13 (total: 15)
fuzz: elapsed: 30s, execs: 128948 (15867/sec), new interesting: 13 (total: 15)
fuzz: elapsed: 33s, execs: 187312 (19455/sec), new interesting: 13 (total: 15)
fuzz: elapsed: 36s, execs: 238166 (16950/sec), new interesting: 13 (total: 15)
fuzz: elapsed: 39s, execs: 272865 (11564/sec), new interesting: 14 (total: 16)
fuzz: elapsed: 42s, execs: 284302 (3813/sec), new interesting: 14 (total: 16)
fuzz: elapsed: 45s, execs: 324315 (13337/sec), new interesting: 15 (total: 17)
fuzz: elapsed: 46s, execs: 324315 (0/sec), new interesting: 15 (total: 17)
--- FAIL: FuzzDAChunkHashVerify (46.02s)
    context deadline exceeded
FAIL
exit status 1
FAIL	github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus	46.024s
EOF
EMPTY_CORPUS_DIR="${WORKDIR}/corpus-empty/FuzzDAChunkHashVerify"
mkdir -p "${EMPTY_CORPUS_DIR}"
run_case benign_real_log 0 \
  FuzzDAChunkHashVerify 45 "${BENIGN_LOG}" "${EMPTY_LIST}" "${EMPTY_CORPUS_DIR}"

# Case 2: a written failing input is a reproducible crash (conjunct 3), even
# when the FAIL block itself is benign-shaped and the budget was spent.
CRASH_LOG="${WORKDIR}/crash.log"
cat > "${CRASH_LOG}" <<'EOF'
fuzz: elapsed: 45s, execs: 324315 (13337/sec), new interesting: 15 (total: 17)
--- FAIL: FuzzX (46.02s)
    context deadline exceeded
Failing input written to testdata/fuzz/FuzzX/abc
FAIL
exit status 1
EOF
run_case crash_with_input 1 \
  FuzzX 45 "${CRASH_LOG}" "${EMPTY_LIST}" "${WORKDIR}/no-such-corpus"

# Case 3: a hung/terminated worker is abnormal termination (conjunct 3).
HUNG_LOG="${WORKDIR}/hung.log"
cat > "${HUNG_LOG}" <<'EOF'
fuzz: elapsed: 3s, execs: 18013 (6004/sec), new interesting: 3 (total: 5)
--- FAIL: FuzzX (52.00s)
    fuzzing process hung or terminated unexpectedly: exit status 2
FAIL
exit status 1
EOF
run_case hung_or_terminated 1 \
  FuzzX 45 "${HUNG_LOG}" "${EMPTY_LIST}" "${WORKDIR}/no-such-corpus"

# Case 4: any failure text other than the bare deadline is defect evidence
# (conjunct 1).
OTHER_LOG="${WORKDIR}/other.log"
cat > "${OTHER_LOG}" <<'EOF'
fuzz: elapsed: 45s, execs: 324315 (13337/sec), new interesting: 15 (total: 17)
--- FAIL: FuzzX (46.02s)
    fuzz_test.go:33: round-trip mismatch
FAIL
exit status 1
EOF
run_case non_benign_text 1 \
  FuzzX 45 "${OTHER_LOG}" "${EMPTY_LIST}" "${WORKDIR}/no-such-corpus"

# Case 5: benign-looking text plus a new corpus file stays FAIL (conjunct 4).
GROWN_CORPUS_DIR="${WORKDIR}/corpus-grown/FuzzDAChunkHashVerify"
mkdir -p "${GROWN_CORPUS_DIR}"
printf 'go test fuzz v1\n[]byte("x")\n' > "${GROWN_CORPUS_DIR}/deadbeef"
run_case benign_text_plus_new_corpus_file 1 \
  FuzzDAChunkHashVerify 45 "${BENIGN_LOG}" "${EMPTY_LIST}" "${GROWN_CORPUS_DIR}"

# Case 6: a deadline below the budget means fuzz coverage was not delivered
# (conjunct 2): the same 46.02s log checked against a 60s budget.
run_case duration_below_budget 1 \
  FuzzDAChunkHashVerify 60 "${BENIGN_LOG}" "${EMPTY_LIST}" "${EMPTY_CORPUS_DIR}"

# Case 7: malformed fuzztime argument fails closed with the usage code.
run_case malformed_fuzztime 2 \
  FuzzDAChunkHashVerify 45s "${BENIGN_LOG}" "${EMPTY_LIST}" "${EMPTY_CORPUS_DIR}"

echo "classifier corpus: ${PASS_COUNT}/${TOTAL} PASS"
if [[ "${FAILED}" -ne 0 ]]; then
  exit 1
fi

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_DIR="${ROOT_DIR}/clients/go"
ARTIFACTS_DIR="${ROOT_DIR}/.artifacts/fuzz-stage2"
FUZZ_TIME="${FUZZ_TIME:-45s}"
FUZZ_MINIMIZE_TIME="${FUZZ_MINIMIZE_TIME:-5s}"
MODULE_PREFIX="github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/"
DIFF_PREFIX="./cmd/rubin-consensus-cli:FuzzRubinConsensusCLI_RustParity_"
TAB=$'\t'
GO_CMD=(go)

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
  "./cmd/rubin-consensus-cli:FuzzRubinConsensusCLI_RustParity_MerkleRoots"
  "./cmd/rubin-consensus-cli:FuzzRubinConsensusCLI_RustParity_ParseTx"
  "./cmd/rubin-consensus-cli:FuzzRubinConsensusCLI_RustParity_Sighash"
  "./consensus:FuzzAccumulateBlockResourceStats"
  "./consensus:FuzzBlockTxSemanticsNonce"
  "./consensus:FuzzConnectBlockParallelDeterminism"
  "./consensus:FuzzExtractCryptoSigAndSighash"
  "./consensus:FuzzFeatureBitStateAtHeightFromWindowCounts"
  "./consensus:FuzzFlagDayHelpers"
  "./consensus:FuzzParseBlockBytes"
  "./consensus:FuzzParseBlockHeaderBytes"
  "./consensus:FuzzParseStealthCovenantData"
  "./consensus:FuzzParseTx"
  "./consensus:FuzzReadCompactSize"
  "./consensus:FuzzValidateP2PKSpendStructural"
  "./consensus:FuzzValidateTxLocalDispatch"
  "./node:FuzzDisconnectBlock"
)

usage() {
  cat <<USAGE
Usage: scripts/ci/run_fuzz_stage2.sh [--list-json | --check-inventory | --self-test-inventory | --target <pkg:Target>]

Runs the bounded Go stage2 fuzz target list and writes reproducibility metadata
under .artifacts/fuzz-stage2/. The script does not commit, push, regenerate
tracked fixtures, or open issues.

Modes:
  (no args)          run every target in the list (local use)
  --list-json        print the target list as a compact JSON array and exit
  --check-inventory  fail unless the list equals the compiled module-wide Fuzz* inventory
  --self-test-inventory  run the inventory comparison over literal cases (no go)
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

# Inventory records, one per line: K<key> compiled key, F<./pkg> package whose
# listed keys are not compared, D<line> defect line, G go list failed.
is_footer() {
  local path="$1" line="$2"
  case "${line}" in
    "ok  ${TAB}${path}" | "ok  ${TAB}${path}${TAB}"* | "?   ${TAB}${path}${TAB}[no test files]") return 0 ;;
  esac
  return 1
}

package_records() {
  local LC_ALL=C
  local path="$1" rc="$2" out="$3" pkg keys="" bad=0 footers=0 last=0 line
  if [[ "${path}" != "${MODULE_PREFIX}"* ]]; then
    echo "DUNSUPPORTED ${path}"
    return 0
  fi
  pkg="./${path#"${MODULE_PREFIX}"}"
  if ((rc != 0)); then
    printf 'DDISCOVERY_FAILED %s\nF%s\n' "${path}" "${pkg}"
    return 0
  fi
  while IFS= read -r line || [[ -n "${line}" ]]; do
    last=0
    if is_footer "${path}" "${line}"; then
      footers=$((footers + 1))
      last=1
    elif [[ "${line}" =~ ^Fuzz[A-Za-z0-9_]+$ ]]; then
      keys+="K${pkg}:${line}"$'\n'
    else
      bad=1
      echo "DUNSUPPORTED ${line}"
    fi
  done < <(printf '%s' "${out}")
  if ((footers != 1 || last != 1)); then
    bad=1
    echo "DUNSUPPORTED ${path} (footer)"
  fi
  if ((bad)); then echo "F${pkg}"; else printf '%s' "${keys}"; fi
}

# Sets CAP_RC and CAP_OUT (stdout only, trailing newlines kept); stderr passes through.
capture() {
  local raw
  raw="$(rc=0; "$@" || rc=$?; printf 'x%s' "${rc}")"
  CAP_RC="${raw##*x}"
  CAP_OUT="${raw%x"${CAP_RC}"}"
}

discover_inventory() {
  local path
  capture "${GO_CMD[@]}" list ./... </dev/null
  if ((CAP_RC != 0)); then
    printf 'G\nDDISCOVERY_FAILED go list\n'
    return 0
  fi
  while IFS= read -r path || [[ -n "${path}" ]]; do
    CAP_RC=0 CAP_OUT=""
    if [[ "${path}" == "${MODULE_PREFIX}"* ]]; then
      capture "${GO_CMD[@]}" test -count=1 -run='^$' -list='^Fuzz' "${path}" </dev/null
    fi
    package_records "${path}" "${CAP_RC}" "${CAP_OUT}"
  done < <(printf '%s' "${CAP_OUT}")
}

inventory_diff() {
  local listed="$1" compiled="$2" failed="$3" discovery="$4" nl=$'\n' key
  if [[ "${compiled}" == "${nl}" && "${discovery}" -eq 0 ]]; then
    echo "EMPTY_INVENTORY"
    return 0
  fi
  while IFS= read -r key; do
    if [[ -z "${key}" ]]; then continue; fi
    case "${listed}" in *"${nl}${key}${nl}"*) ;; *) echo "MISSING ${key}" ;; esac
  done < <(printf '%s' "${compiled}")
  while IFS= read -r key; do
    if [[ -z "${key}" ]]; then continue; fi
    case "${failed}" in *"${nl}${key%%:*}${nl}"*) continue ;; esac
    case "${compiled}" in *"${nl}${key}${nl}"*) ;; *) echo "STALE ${key}" ;; esac
  done < <(printf '%s' "${listed}")
}

# Reads records on stdin, compares with the listed keys in "$@".
inventory_compare() {
  local nl=$'\n' listed=$'\n' dups=$'\n' compiled=$'\n' failed=$'\n' out="" diff
  local glist=0 discovery=0 rec key
  for key in "$@"; do
    case "${listed}" in
      *"${nl}${key}${nl}"*)
        case "${dups}" in
          *"${nl}${key}${nl}"*) ;;
          *) dups+="${key}${nl}"; out+="DUPLICATE ${key}${nl}" ;;
        esac
        ;;
      *) listed+="${key}${nl}" ;;
    esac
  done
  while IFS= read -r rec; do
    case "${rec}" in
      K*) compiled+="${rec#K}${nl}" ;;
      F*) failed+="${rec#F}${nl}" ;;
      G) glist=1; discovery=1 ;;
      D*) out+="${rec#D}${nl}"; discovery=1 ;;
    esac
  done
  if ((glist == 0)); then
    diff="$(inventory_diff "${listed}" "${compiled}" "${failed}" "${discovery}")"
    if [[ -n "${diff}" ]]; then out+="${diff}${nl}"; fi
  fi
  if [[ -z "${out}" ]]; then
    printf 'inventory OK: %d targets\n' "$#"
    return 0
  fi
  printf '%s' "${out}" | LC_ALL=C sort
  return 1
}

# The --check-inventory pipeline; listed keys in "$@".
check_inventory() {
  discover_inventory | inventory_compare "$@"
}

# Pipes the records into inventory_compare and checks the exit code (0 for an "inventory OK"
# want, else 1) and stdout as a bash string (NUL bytes are dropped, trailing newlines kept as
# in capture) against want plus one final newline.
st_case() {
  local name="$1" want="$2"$'\n' recs="$3" want_rc=1 raw got rc
  shift 3
  raw="$(rc=0; printf '%s\n' "${recs}" | inventory_compare "$@" || rc=$?; printf 'x%s' "${rc}")"
  rc="${raw##*x}"
  got="${raw%x"${rc}"}"
  if [[ "${want}" == "inventory OK:"* ]]; then want_rc=0; fi
  if [[ "${got}" != "${want}" || "${rc}" -ne "${want_rc}" ]]; then
    printf 'SELF-TEST FAIL: %s: rc=%s want_rc=%s got %q want %q\n' \
      "${name}" "${rc}" "${want_rc}" "${got}" "${want}" >&2
    ST_FAILS=$((ST_FAILS + 1))
  fi
}

# shellcheck disable=SC2329
# Invoked indirectly via GO_CMD.
# Stand-in for go (GO_CMD) in the self-test: scripted exit codes and stdout, noise on stderr.
st_go() {
  echo "#warning st_go $1 noise" >&2
  case "$1" in
    list) printf '%s' "${ST_LIST_OUT}"; return "${ST_LIST_RC}" ;;
  esac
  case "${!#}" in
    *node) printf '%s' "${ST_N_OUT}"; return "${ST_N_RC}" ;;
    *) printf '%s' "${ST_C_OUT}"; return 0 ;;
  esac
}

st_cmp() {
  local name="$1" stream="$2" want_rc="$3" want="$4"$'\n' raw="$5" got rc
  rc="${raw##*x}"
  got="${raw%x"${rc}"}"
  if [[ "${got}" != "${want}" || "${rc}" -ne "${want_rc}" ]]; then
    printf 'SELF-TEST FAIL: %s: rc=%s want_rc=%s %s %q want %q\n' "${name}" "${rc}" "${want_rc}" "${stream}" "${got}" "${want}" >&2
    ST_FAILS=$((ST_FAILS + 1))
  fi
}

# Runs check_inventory against st_go twice and checks the exit code against want_rc, stdout
# against out and stderr against err, each as a bash string (NUL bytes are dropped, trailing
# newlines kept as in capture) plus one final newline.
st_err() {
  local name="$1" want_rc="$2" out="$3" err="$4" raw
  local GO_CMD=(st_go)
  shift 4
  raw="$(rc=0; check_inventory "$@" 2>/dev/null </dev/null || rc=$?; printf 'x%s' "${rc}")"
  st_cmp "${name}" stdout "${want_rc}" "${out}" "${raw}"
  raw="$(rc=0; check_inventory "$@" 2>&1 >/dev/null </dev/null || rc=$?; printf 'x%s' "${rc}")"
  st_cmp "${name}" stderr "${want_rc}" "${err}" "${raw}"
}

pn() { package_records "${MODULE_PREFIX}node" "$@"; }
pc() { package_records "${MODULE_PREFIX}consensus" "$@"; }

self_test_inventory() {
  local nl=$'\n' N="${MODULE_PREFIX}node" fn fc recs k want a=./node:FuzzA
  local lw="#warning st_go list noise" tw="#warning st_go test noise"
  local cgo=(./consensus:FuzzConnectBlockInMemory ./consensus:FuzzTxDepGraphBuild ./consensus:FuzzDAChunkHashVerify
    ./consensus:FuzzDAPayloadCommitVerify ./consensus:FuzzUtxoApplyNonCoinbase ./consensus:FuzzVerifySigDispatch
    ./consensus:FuzzSigCacheDeterminism ./consensus:FuzzSigCheckQueueFlush ./consensus:FuzzSigCacheConcurrentAccess
    ./consensus:FuzzSuiteRegistryLookup ./consensus:FuzzSigCheckQueueWithCacheIntegration)
  fn="ok  ${TAB}${N}${TAB}0.1s${nl}" fc="ok  ${TAB}${MODULE_PREFIX}consensus${TAB}0.1s${nl}"
  ST_FAILS=0
  if ((${#cgo[@]} != 11)); then echo "SELF-TEST FAIL: cgo key literals: ${#cgo[@]} != 11" >&2; ST_FAILS=1; fi
  recs="$(pn 0 "FuzzA${nl}${fn}")"
  st_case "equal sets" "inventory OK: 1 targets" "${recs}" ${a}
  st_case "MISSING" "MISSING ${a}" "${recs}"
  st_case "STALE" "STALE ./node:FuzzB" "${recs}" ${a} ./node:FuzzB
  st_case "DUPLICATE once for three copies" "DUPLICATE ${a}" "${recs}" ${a} ${a} ${a}
  st_case "same name in two packages" "inventory OK: 2 targets" "${recs}${nl}$(pc 0 "FuzzA${nl}${fc}")" ${a} ./consensus:FuzzA
  recs="$(pn 1 "FuzzA${nl}"; pc 0 "FuzzC${nl}${fc}")"
  st_case "failed package, others compared" "DISCOVERY_FAILED ${N}" "${recs}" ${a} ./consensus:FuzzC
  st_case "failed package beside duplicate" "DISCOVERY_FAILED ${N}${nl}DUPLICATE ${a}" "${recs}" ${a} ${a} ./consensus:FuzzC
  st_case "failed package, other stale, no EMPTY_INVENTORY" "DISCOVERY_FAILED ${N}${nl}STALE ./consensus:FuzzX" "$(pn 1 ""; pc 0 "${fc}")" ${a} ./consensus:FuzzX
  st_case "build failed output not classified" "DISCOVERY_FAILED ${N}" "$(pn 1 "FAIL${TAB}${N} [build failed]${nl}FAIL${nl}")" ${a}
  st_case "malformed line, valid footer" "UNSUPPORTED fuzzFoo" "$(pn 0 "fuzzFoo${nl}FuzzA${nl}${fn}")" ${a}
  st_case "malformed line with space" "UNSUPPORTED Fuzz Foo" "$(pn 0 "Fuzz Foo${nl}${fn}")" ${a}
  st_case "missing footer" "UNSUPPORTED ${N} (footer)" "$(pn 0 "FuzzA${nl}")" ${a}
  st_case "malformed line and missing footer" "UNSUPPORTED ${N} (footer)${nl}UNSUPPORTED junk" "$(pn 0 "junk${nl}FuzzA")" ${a}
  st_case "empty line inside" "UNSUPPORTED " "$(pn 0 "FuzzA${nl}${nl}${fn}")" ${a}
  st_case "empty line after footer" "UNSUPPORTED ${nl}UNSUPPORTED ${N} (footer)" "$(pn 0 "FuzzA${nl}${fn}${nl}")" ${a}
  st_case "two footers" "UNSUPPORTED ${N} (footer)" "$(pn 0 "${fn}${fn}")" ${a}
  st_case "footer of another path" "UNSUPPORTED ${N} (footer)${nl}UNSUPPORTED ok  ${TAB}${N}x${TAB}0.1s" "$(pn 0 "ok  ${TAB}${N}x${TAB}0.1s${nl}")" ${a}
  st_case "no test files footer" "EMPTY_INVENTORY" "$(pn 0 "?   ${TAB}${N}${TAB}[no test files]${nl}")"
  st_case "footer without trailing tab" "inventory OK: 1 targets" "$(pn 0 "FuzzA${nl}ok  ${TAB}${N}")" ${a}
  st_case "path outside module prefix" "STALE ${a}${nl}UNSUPPORTED example.com/other" "$(package_records example.com/other 0 "")" ${a}
  ST_LIST_RC=1 ST_LIST_OUT="${N}${nl}" ST_N_RC=1 ST_N_OUT="FuzzA${nl}${fn}"
  st_err "go list failure, no package run" 1 "DISCOVERY_FAILED go list" "${lw}" ${a}
  st_err "go list failure beside duplicate" 1 "DISCOVERY_FAILED go list${nl}DUPLICATE ${a}" "${lw}" ${a} ${a}
  ST_LIST_RC=0 ST_N_RC=0 ST_LIST_OUT="${N}${nl}${MODULE_PREFIX}consensus${nl}" ST_C_OUT="FuzzC${nl}${fc}"
  st_err "go list ok, packages compared" 0 "inventory OK: 2 targets" "${lw}${nl}${tw}${nl}${tw}" ${a} ./consensus:FuzzC
  st_err "go list ok, MISSING and STALE" 1 "MISSING ./consensus:FuzzC${nl}STALE ./node:FuzzB" "${lw}${nl}${tw}${nl}${tw}" ${a} ./node:FuzzB
  ST_LIST_OUT+="example.com/other${nl}"
  st_err "go list ok, foreign path unsupported, not run" 1 "UNSUPPORTED example.com/other" "${lw}${nl}${tw}${nl}${tw}" ${a} ./consensus:FuzzC
  ST_N_RC=1
  st_err "forwarded list-run exit code" 1 "DISCOVERY_FAILED ${N}${nl}UNSUPPORTED example.com/other" "${lw}${nl}${tw}${nl}${tw}" ${a} ./consensus:FuzzC
  ST_N_RC=0 ST_LIST_OUT="${N}${nl}" ST_N_OUT="fuzzFoo${nl}${fn}"
  st_err "go list ok, malformed line" 1 "UNSUPPORTED fuzzFoo" "${lw}${nl}${tw}" ${a}
  ST_N_OUT="FuzzA${nl}"
  st_err "go list ok, missing footer" 1 "UNSUPPORTED ${N} (footer)" "${lw}${nl}${tw}" ${a}
  ST_N_OUT="${fn}"
  st_err "go list ok, empty compiled output" 1 "EMPTY_INVENTORY" "${lw}${nl}${tw}" ${a}
  recs="$(pn 0 "${fn}")"
  st_case "empty compiled output" "EMPTY_INVENTORY" "${recs}" ${a}
  st_case "empty compiled output beside duplicate" "DUPLICATE ${a}${nl}EMPTY_INVENTORY" "${recs}" ${a} ${a}
  recs=""
  for k in "${TARGETS[@]}"; do
    case " ${cgo[*]} " in *" ${k} "*) ;; *) recs+="K${k}${nl}" ;; esac
  done
  want="$(printf 'STALE %s\n' "${cgo[@]}" | LC_ALL=C sort)"
  st_case "TARGETS minus the 11 cgo keys" "${want}" "${recs}" "${TARGETS[@]}"
  if ((ST_FAILS != 0)); then return 1; fi
  echo "inventory self-test OK"
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
    --check-inventory|--self-test-inventory)
      if (($# > 1)); then
        echo "FAIL: $1 takes no extra arguments" >&2
        exit 2
      fi
      if [[ "$1" == "--self-test-inventory" ]]; then
        self_test_inventory
        exit $?
      fi
      cd "${GO_DIR}"
      if check_inventory "${TARGETS[@]}"; then exit 0; fi
      exit 1
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
  local tar_paths=() seen=$'\n' spec dir
  for spec in "${TARGETS[@]}"; do
    dir="${spec%%:*}"
    dir="${dir#./}"
    case "${seen}" in *$'\n'"${dir}"$'\n'*) continue ;; esac
    seen+="${dir}"$'\n'
    if [[ -d "${GO_DIR}/${dir}/testdata/fuzz" ]]; then
      find "${GO_DIR}/${dir}/testdata/fuzz" -type f | sort >> "${ARTIFACTS_DIR}/go-fuzz-files.txt" || true
      tar_paths+=("${dir}/testdata/fuzz")
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
  local metadata_file="${ARTIFACTS_DIR}/${pkg#./}/${target}.metadata.env"
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
    write_env_field "command" "cd clients/go && go test -run=^$ -fuzz=\"^${target}\$\" -fuzztime=\"${FUZZ_TIME}\" -fuzzminimizetime=\"${FUZZ_MINIMIZE_TIME}\" -timeout=\"${GO_TEST_TIMEOUT}\" \"${pkg}\""
    write_env_field "log_path" ".artifacts/fuzz-stage2/${pkg#./}/${target}.log"
  } > "${metadata_file}"
}

# Requires cargo and the passing, non-skipped seed-parity test before fuzzing.
differential_preflight() {
  local preflight_log="$1" test_name="TestRubinConsensusCLI_RustParity_SeedRequests"
  if ! cargo --version >"${preflight_log}" 2>&1; then return 1; fi
  go test -count=1 -v -run "^${test_name}\$" ./cmd/rubin-consensus-cli >>"${preflight_log}" 2>&1 || return 1
  grep -q -- "^--- PASS: ${test_name}" "${preflight_log}" && ! grep -q -- '^--- SKIP:' "${preflight_log}"
}

run_one_target() {
  local pkg="$1"
  local target="$2"
  local key="${pkg}:${target}"
  local target_dir="${ARTIFACTS_DIR}/${pkg#./}"
  local log_file="${target_dir}/${target}.log"
  local corpus_dir="${GO_DIR}/${pkg#./}/testdata/fuzz/${target}"
  local corpus_before="${target_dir}/${target}.corpus-before.txt"
  mkdir -p "${target_dir}"
  # Snapshot the corpus file list before the run: the benign-exit classifier
  # treats "no new file here" as proof no crasher was written.
  if [[ -d "${corpus_dir}" ]]; then
    find "${corpus_dir}" -type f | sort > "${corpus_before}"
  else
    : > "${corpus_before}"
  fi
  write_target_metadata "${pkg}" "${target}"
  echo "==> running ${key} (${pkg})" | tee -a "${ARTIFACTS_DIR}/summary.log"
  echo "metadata ${key}: ${target_dir}/${target}.metadata.env" >> "${ARTIFACTS_DIR}/summary.log"
  if [[ "${key}" == "${DIFF_PREFIX}"* ]]; then
    if differential_preflight "${target_dir}/${target}.preflight.log"; then
      echo "PREFLIGHT_PASS ${key}" | tee -a "${ARTIFACTS_DIR}/summary.log"
    else
      STATUS=1
      echo "FAIL ${key} (differential preflight)" | tee -a "${ARTIFACTS_DIR}/summary.log"
      return 0
    fi
  fi
  if go test -run=^$ -fuzz="^${target}\$" -fuzztime="${FUZZ_TIME}" -fuzzminimizetime="${FUZZ_MINIMIZE_TIME}" -timeout="${GO_TEST_TIMEOUT}" "${pkg}" >"${log_file}" 2>&1; then
    # A zero exit is a real PASS only with fuzz-execution evidence: `go test
    # -fuzz=<pattern>` matching nothing exits 0, and a setup f.Skipf() (e.g.
    # unavailable ML-DSA backend, measured 2026-07-29) leaves a bare PASS log.
    if grep -Eq -- '^fuzz: elapsed:' "${log_file}"; then
      echo "PASS ${key}" | tee -a "${ARTIFACTS_DIR}/summary.log"
    # Disambiguate via the test binary's own -list output — the truth source
    # for target existence: the no-fuzz-tests warning is not emitted when the
    # package has no fuzz tests at all. The -list run reuses the already-built
    # test binary, so it is cheap. Ambiguity is FAIL (fail closed).
    elif go test -run='^$' -list "^${target}\$" "${pkg}" >"${target_dir}/${target}.list.txt" 2>&1 &&
      grep -Fxq -- "${target}" "${target_dir}/${target}.list.txt"; then
      echo "SKIP_FUZZ_SETUP ${key} (fuzz target skipped during setup; zero fuzz coverage — ML-DSA backend unavailable? see RUB-1064)" | tee -a "${ARTIFACTS_DIR}/summary.log"
    else
      STATUS=1
      echo "FAIL ${key} (no fuzzing executed — target missing from package?)" | tee -a "${ARTIFACTS_DIR}/summary.log"
    fi
  elif "${ROOT_DIR}/scripts/ci/classify_go_fuzz_exit.sh" "${target}" "${fuzz_seconds}" "${log_file}" "${corpus_before}" "${corpus_dir}"; then
    echo "PASS_AFTER_BENIGN_DEADLINE ${key} (upstream fuzztime shutdown race; full budget spent, no defect evidence)" | tee -a "${ARTIFACTS_DIR}/summary.log"
  else
    STATUS=1
    echo "FAIL ${key}" | tee -a "${ARTIFACTS_DIR}/summary.log"
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

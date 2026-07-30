#!/usr/bin/env bash
#
# RUB-1083: Go/Rust `rubin-node --dry-run` parity and zero-write harness.
#
# For every storage shape and every flag row the RUB-1083 contract lists it
# snapshots the datadir exactly, runs the Go binary and then the Rust binary,
# requires each client's post-run snapshot to equal the pre-run one, and
# requires exit 0, empty stderr and an identical finite cross-client projection
# of stdout on both.
#
# `flag_rows` is the contract's finite list of COMMON dry-run rows, not the whole
# legal dry-run surface: Go additionally accepts `--log-level`,
# `--mempool-max-txs`, `--mempool-max-bytes` and `--featurebits-deployments`,
# which Rust rejects, so those are outside cross-client comparison entirely.
#
# Both binaries are built from the current checkout; a preinstalled or
# PATH-resolved rubin-node is never used. Set KEEP_TMP=1 to preserve
# artifacts on success (they are always preserved on failure).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"

# Only the tools this script invokes in its OWN PATH are precondition-checked.
# `go` and `cargo` are deliberately absent: they run through `dev-env.sh`, whose
# job is repairing a minimal PATH, so checking them here would reject an
# environment the build then handles fine.
for tool in python3 diff cmp; do
  command -v "${tool}" >/dev/null 2>&1 || {
    printf 'missing required tool: %s\n' "${tool}" >&2
    exit 1
  }
done

# shellcheck source=scripts/devnet-process-common.sh
source "${REPO_ROOT}/scripts/devnet-process-common.sh"
rubin_process_init "rubin-dry-run-parity"
ART="${RUBIN_PROCESS_ARTIFACT_ROOT}"

# Set only while a row runs against a mode-0500 datadir. ANY exit in that
# window — fail(), an unexpected `set -e` abort, Ctrl-C — must restore 0700 or
# the preserved artifact tree keeps a directory the operator cannot remove, so
# the restore hangs off the EXIT trap rather than off fail(). Overwriting the
# helper's EXIT trap and calling `rubin_process_cleanup` with the original
# status is the pattern in `devnet-go-da-relay.sh:38-45`.
RESTORE_MODE_DIR=""

dry_run_parity_exit_trap() {
  local status=$? cleanup_status=0
  [[ -z "${RESTORE_MODE_DIR}" ]] || chmod 0700 "${RESTORE_MODE_DIR}" 2>/dev/null || true
  rubin_process_cleanup "${status}" || cleanup_status=$?
  [[ "${status}" == "0" ]] || exit "${status}"
  exit "${cleanup_status}"
}
trap dry_run_parity_exit_trap EXIT
# A bare SIGINT/SIGTERM kills the shell without running the EXIT trap; routing
# them through `exit` runs it with the conventional 128+signal status.
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

# Rows the contract allows to be skipped (uid 0, no symlink support). The final
# summary must name them rather than claim every row held.
SKIPPED_ROWS=()

SNAPSHOT_PY="${ART}/snapshot_datadir.py"
PROJECT_PY="${ART}/project_dry_run.py"

cat >"${SNAPSHOT_PY}" <<'PY'
"""Exact filesystem snapshot of one datadir, as defined by the RUB-1083 contract.

Sorted recursive lstat inventory: relative path, entry kind, regular-file
SHA-256, symlink target, size, permission bits, device/inode, link count and
nanosecond mtime. atime and ctime are excluded because a pure read moves them.
"""
import hashlib
import os
import stat
import sys

root = os.path.abspath(sys.argv[1])

def digest(path, mode):
    # The mode-000 tip-header row is unreadable as-is, so its read is bracketed
    # by a temporary +r and an unconditional restore of the ORIGINAL mode, which
    # is also the mode row() records. Safe ONLY because this snapshot excludes
    # ctime: chmod moves ctime, never mtime. Do not "simplify" the restore away —
    # a permanent relaxation would mutate the very state being observed. The
    # relaxing chmod stays INSIDE the try so no signal can land between it and
    # the restoring finally; the restore is idempotent, so a relax that itself
    # fails only re-applies the mode already on disk and still propagates.
    relax = not mode & stat.S_IRUSR
    try:
        if relax:
            os.chmod(path, mode | stat.S_IRUSR)
        sha = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                sha.update(chunk)
        return sha.hexdigest()
    finally:
        if relax:
            os.chmod(path, mode)


def row(path):
    st = os.lstat(path)
    # filemode()[0] is the type character: d/-/l/p/s/b/c, exact and exhaustive.
    kind = stat.filemode(st.st_mode)[0]
    if kind == "-":
        content = digest(path, stat.S_IMODE(st.st_mode))
    elif kind == "l":
        content = "link:" + os.readlink(path)
    else:
        content = "-"
    return "\t".join(
        [
            os.path.relpath(path, root),
            kind,
            content,
            str(st.st_size),
            oct(stat.S_IMODE(st.st_mode)),
            str(st.st_dev),
            str(st.st_ino),
            str(st.st_nlink),
            str(st.st_mtime_ns),
        ]
    )


def reraise(error):
    # Propagate the walk error. Silently dropping an unreadable subtree removes
    # it from the before AND after snapshot alike, so the diff passes over
    # whatever changed inside it. Mirrors the walkErr return in
    # `clients/go/cmd/rubin-node/main_test.go:2774-2777`.
    raise error


rows = [row(root)]
for dirpath, dirnames, filenames in os.walk(root, onerror=reraise, followlinks=False):
    for name in dirnames + filenames:
        rows.append(row(os.path.join(dirpath, name)))
rows.sort()
sys.stdout.write("\n".join(rows) + "\n")
PY

cat >"${PROJECT_PY}" <<'PY'
"""Finite cross-client projection of `rubin-node --dry-run` stdout (RUB-1083).

Emits only the fields the contract compares across clients. Go-only and
Rust-only JSON fields are dropped. Absent and null stay distinct tokens rather
than being normalized, except for `rpc_bind_addr` and `mine_address`, where
absent, null and "" are one unset value.

`ibd` is compared cross-client and must be `true` on every listed row. Neither
client hydrates a tip timestamp on the dry-run path — Go's `NewSyncEngine` never
reads the tip header and Rust's dry-run reporting engine is constructed with no
blockstore — so both sit at timestamp zero and `is_in_ibd` is structurally true.
Nothing here may depend on the fixture's age; `ibd=false` is a real regression,
not a stale-fixture artifact, so it fails here rather than being tolerated.
"""
import json
import re
import sys

BOOL = re.compile(r"^(true|false)$")
TRUE = re.compile(r"^true$")
UINT = re.compile(r"^(0|[1-9][0-9]*)$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def die(message):
    sys.stderr.write("projection error: {}\n".format(message))
    raise SystemExit(1)


def parse_kv(line, prefix, keys):
    body = line[len(prefix):]
    tokens = body.split(" ")
    if len(tokens) != len(keys):
        die("{!r}: expected {} fields, got {}".format(line, len(keys), len(tokens)))
    values = {}
    for token, key in zip(tokens, keys):
        name, sep, value = token.partition("=")
        if sep != "=" or name != key:
            die("{!r}: expected key {!r}, got token {!r}".format(line, key, token))
        values[key] = value
    return values


def require(line, key, value, pattern, expectation):
    if not pattern.match(value):
        die("{!r}: {} must be {}, got {!r}".format(line, key, expectation, value))


def json_string(cfg, key):
    if key not in cfg:
        return "<absent>"
    value = cfg[key]
    if value is None:
        return "<null>"
    if not isinstance(value, str):
        die("{} must be a JSON string, got {!r}".format(key, value))
    return value


def json_unset_or_string(cfg, key):
    value = cfg.get(key)
    if value is None or value == "":
        return "<unset>"
    if not isinstance(value, str):
        die("{} must be a JSON string, got {!r}".format(key, value))
    return value


with open(sys.argv[1], "rb") as handle:
    raw = handle.read().decode("utf-8")

start = raw.find("{")
if start < 0:
    die("no effective-config JSON object in stdout")
cfg, end = json.JSONDecoder().raw_decode(raw, start)
if not isinstance(cfg, dict):
    die("effective config is not a JSON object")

lines = [line for line in raw[end:].splitlines() if line.strip()]
prefixes = ("chainstate: ", "blockstore: ", "sync: ", "p2p: ")
if len(lines) != len(prefixes):
    die("expected exactly {} banner lines after the JSON, got {}: {!r}".format(
        len(prefixes), len(lines), lines))
for line, prefix in zip(lines, prefixes):
    if not line.startswith(prefix):
        die("expected a line starting with {!r}, got {!r}".format(prefix, line))
chainstate_line, blockstore_line, sync_line, p2p_line = lines

chainstate_keys = ["has_tip", "height", "utxos", "already_generated"]
if " tip=" in chainstate_line:
    chainstate_keys.append("tip")
chainstate = parse_kv(chainstate_line, "chainstate: ", chainstate_keys)
require(chainstate_line, "has_tip", chainstate["has_tip"], BOOL, "a bool token")
for key in ("height", "utxos", "already_generated"):
    require(chainstate_line, key, chainstate[key], UINT, "a decimal uint")
if "tip" in chainstate:
    require(chainstate_line, "tip", chainstate["tip"], HEX64, "64 lowercase hex")

if blockstore_line == "blockstore: empty":
    blockstore = None
else:
    blockstore = parse_kv(blockstore_line, "blockstore: ", ["tip_height", "tip_hash"])
    require(blockstore_line, "tip_height", blockstore["tip_height"], UINT, "a decimal uint")
    require(blockstore_line, "tip_hash", blockstore["tip_hash"], HEX64, "64 lowercase hex")

# Frozen Go gating rule: the chainstate `tip=` field is present exactly when the
# canonical index has a tip, never when the chainstate merely claims one.
if ("tip" in chainstate) != (blockstore is not None):
    die("chainstate tip= presence must follow the blockstore tip: {!r} / {!r}".format(
        chainstate_line, blockstore_line))

sync = parse_kv(sync_line, "sync: ", ["header_request_has_from", "header_request_limit", "ibd"])
require(sync_line, "header_request_has_from", sync["header_request_has_from"], BOOL, "a bool")
require(sync_line, "header_request_limit", sync["header_request_limit"], UINT, "a decimal uint")
require(sync_line, "ibd", sync["ibd"], TRUE, "true on every listed dry-run row")

p2p = parse_kv(p2p_line, "p2p: ", ["peer_slots", "connected"])
require(p2p_line, "peer_slots", p2p["peer_slots"], UINT, "a decimal uint")
require(p2p_line, "connected", p2p["connected"], UINT, "a decimal uint")

peers = cfg.get("peers")
if not isinstance(peers, list) or any(not isinstance(peer, str) for peer in peers):
    die("peers must be a JSON array of strings, got {!r}".format(peers))
max_peers = cfg.get("max_peers")
if not isinstance(max_peers, int) or isinstance(max_peers, bool):
    die("max_peers must be a JSON integer, got {!r}".format(max_peers))

out = [
    ("json.network", json_string(cfg, "network")),
    ("json.data_dir", json_string(cfg, "data_dir")),
    ("json.chain_id_hex", json_string(cfg, "chain_id_hex")),
    ("json.bind_addr", json_string(cfg, "bind_addr")),
    ("json.peers", json.dumps(peers)),
    ("json.max_peers", str(max_peers)),
    ("json.rpc_bind_addr", json_unset_or_string(cfg, "rpc_bind_addr")),
    ("json.mine_address", json_unset_or_string(cfg, "mine_address")),
    ("chainstate.has_tip", chainstate["has_tip"]),
    ("chainstate.height", chainstate["height"]),
    ("chainstate.utxos", chainstate["utxos"]),
    ("chainstate.already_generated", chainstate["already_generated"]),
    ("chainstate.tip", chainstate.get("tip", "<absent>")),
    ("blockstore.tip_height", "<empty>" if blockstore is None else blockstore["tip_height"]),
    ("blockstore.tip_hash", "<empty>" if blockstore is None else blockstore["tip_hash"]),
    ("sync.header_request_has_from", sync["header_request_has_from"]),
    ("sync.header_request_limit", sync["header_request_limit"]),
    ("sync.ibd", sync["ibd"]),
    ("p2p.peer_slots", p2p["peer_slots"]),
    ("p2p.connected", p2p["connected"]),
]
sys.stdout.write("".join("{}={}\n".format(key, value) for key, value in out))
PY

GO_BIN="${ART}/rubin-node-go"
RUST_BIN="${ART}/rubin-node-rust"

echo "Building the Go node from the current checkout"
"${DEV_ENV}" -- go -C "${REPO_ROOT}/clients/go" build -o "${GO_BIN}" ./cmd/rubin-node
echo "Building the Rust node from the current checkout"
# The binary path comes from cargo's own machine-readable artifact event, not a
# guessed `target/debug/` layout: under `CARGO_TARGET_DIR`, `build.target-dir`
# or a configured target triple the guess either fails outright or — the
# dangerous branch — copies a stale binary from an earlier build. Same pattern
# as `scripts/devnet-rust-binary-soak.sh:258-370`.
CARGO_BUILD_LOG="${ART}/cargo-build.jsonl"
"${DEV_ENV}" -- cargo build --manifest-path "${REPO_ROOT}/clients/rust/Cargo.toml" \
  -p rubin-node --message-format=json-render-diagnostics >"${CARGO_BUILD_LOG}"
# Fail-closed: cargo routes JSON events to stdout and rendered diagnostics to
# stderr, so a non-JSON line is contamination, and zero matching
# compiler-artifact events means cargo never linked the binary we are about to
# run. Both exit non-zero rather than falling back to a path guess.
CARGO_RUST_BIN="$(python3 - "${CARGO_BUILD_LOG}" <<'PY'
import json
import sys

selected = None
with open(sys.argv[1], encoding="utf-8") as handle:
    for raw in handle:
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("{"):
            raise SystemExit("cargo log contamination: {!r}".format(line[:160]))
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit("cargo log parse error: {}: {!r}".format(exc, line[:160]))
        target = event.get("target") or {}
        if (
            event.get("reason") == "compiler-artifact"
            and target.get("name") == "rubin-node"
            and "bin" in (target.get("kind") or [])
            and event.get("executable")
        ):
            # Last match wins: a relink emits a later event than any earlier one.
            selected = event["executable"]
if selected is None:
    raise SystemExit("no rubin-node bin artifact in the cargo build log")
print(selected)
PY
)" || fail "cargo did not report a rubin-node executable (raw log: ${CARGO_BUILD_LOG})"
[[ -x "${CARGO_RUST_BIN}" ]] || fail "cargo-reported executable is not executable: ${CARGO_RUST_BIN}"
cp -- "${CARGO_RUST_BIN}" "${RUST_BIN}"

artifact() { printf '%s/%s.%s' "${ART}" "$1" "$2"; }

snapshot() { python3 "${SNAPSHOT_PY}" "$1"; }

# compare_row <label> <datadir> <argv...>
#
# Runs both clients with the same argv, proves neither touched <datadir>, then
# requires the contract's disposition for every listed row — exit 0 with empty
# stderr on BOTH clients — and an identical finite projection.
#
# Every listed row is an accepted (exit 0, empty stderr) row, so that assertion
# is unconditional: a row where both clients failed identically must never
# report PASS with the projection uncompared. There is deliberately no reject
# row — rejects diverge on stderr wording by design, so no reject row could pass
# byte-identical stderr, and one would need exit-code plus normalized-shape
# comparison instead.
compare_row() {
  local label="$1" datadir="$2"
  shift 2
  local -a args=("$@")
  local impl bin rc before after

  # A row whose argv named some OTHER datadir would snapshot an untouched tree,
  # diff clean and print PASS while the clients wrote to the real target.
  local seen=0 declared="" i
  for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[i]}" in
      --datadir) seen=$((seen + 1)) declared="${args[i + 1]-}" ;;
      --datadir=*) seen=$((seen + 1)) declared="${args[i]#--datadir=}" ;;
    esac
  done
  [[ "${seen}" == "1" && "${declared}" == "${datadir}" ]] ||
    fail "${label}: argv must name --datadir exactly once as ${datadir}, got ${seen} occurrence(s) naming ${declared:-<none>}"

  for impl in go rust; do
    case "${impl}" in
      go) bin="${GO_BIN}" ;;
      *) bin="${RUST_BIN}" ;;
    esac
    before="$(artifact "${label}" "${impl}.snapshot.before")"
    after="$(artifact "${label}" "${impl}.snapshot.after")"
    snapshot "${datadir}" >"${before}"
    rc=0
    "${bin}" "${args[@]}" \
      >"$(artifact "${label}" "${impl}.stdout")" \
      2>"$(artifact "${label}" "${impl}.stderr")" || rc=$?
    snapshot "${datadir}" >"${after}"
    diff -u "${before}" "${after}" >"$(artifact "${label}" "${impl}.snapshot.diff")" ||
      fail "${label}: ${impl} --dry-run mutated ${datadir} (see $(artifact "${label}" "${impl}.snapshot.diff"))"
    printf '%s\n' "${rc}" >"$(artifact "${label}" "${impl}.exit")"
  done

  local go_rc rust_rc
  go_rc="$(cat "$(artifact "${label}" "go.exit")")"
  rust_rc="$(cat "$(artifact "${label}" "rust.exit")")"
  [[ "${go_rc}" == "${rust_rc}" ]] ||
    fail "${label}: exit code mismatch go=${go_rc} rust=${rust_rc}"
  cmp -s "$(artifact "${label}" "go.stderr")" "$(artifact "${label}" "rust.stderr")" || {
    diff -u "$(artifact "${label}" "go.stderr")" "$(artifact "${label}" "rust.stderr")" >&2 || true
    fail "${label}: stderr bytes differ"
  }
  [[ "${go_rc}" == "0" ]] ||
    fail "${label}: every listed row must exit 0 on both clients, got ${go_rc}"
  # Byte-identity above already ties the two together, so one emptiness check
  # covers both clients.
  [[ ! -s "$(artifact "${label}" "go.stderr")" ]] || {
    cat "$(artifact "${label}" "go.stderr")" >&2
    fail "${label}: every listed row must leave stderr empty"
  }

  for impl in go rust; do
    python3 "${PROJECT_PY}" "$(artifact "${label}" "${impl}.stdout")" \
      >"$(artifact "${label}" "${impl}.projection")" ||
      fail "${label}: ${impl} stdout does not match the frozen dry-run layout"
  done
  diff -u "$(artifact "${label}" "go.projection")" "$(artifact "${label}" "rust.projection")" ||
    fail "${label}: cross-client projection mismatch"

  printf 'PASS  %-32s exit=%s\n' "${label}" "${go_rc}"
}

MINE_ADDRESS="$(printf '1%.0s' {1..64})"
GENESIS_FILE="${ART}/genesis.json"
printf '%s\n' '{"chain_id_hex":"0x88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103","genesis_hash_hex":"0x8d48b863805b96e5fcb79ee9652cd6257ae352b2f52088af921212039f9e8aff"}' >"${GENESIS_FILE}"
chmod 0444 "${GENESIS_FILE}"

HEALTHY_DIR="${ART}/healthy"
BASE_DIR="${ART}/base-height-1"
echo "Preparing the healthy initialized store"
"${GO_BIN}" --create-store --datadir "${HEALTHY_DIR}" --mine-address "${MINE_ADDRESS}" \
  --mine-blocks 2 --mine-exit >"${ART}/healthy.mine.log" 2>&1
"${GO_BIN}" --create-store --datadir "${BASE_DIR}" --mine-address "${MINE_ADDRESS}" \
  --mine-blocks 1 --mine-exit >"${ART}/base.mine.log" 2>&1

# The encoded empty/no-tip chainstate has to come from the client's own encoder,
# not from a hand-written fixture: start a real node on a freshly created empty
# store through the process lifecycle helpers, wait for its readiness evidence,
# stop it, and take the snapshot it saved.
echo "Capturing the encoded empty/no-tip chainstate"
EMPTY_DIR="${ART}/empty-capture"
rubin_process_start "empty-capture.log" "${GO_BIN}" --create-store --datadir "${EMPTY_DIR}" \
  --bind 127.0.0.1:0
EMPTY_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_wait_for_log "empty-capture.log" "rubin-node skeleton running" 60 "${EMPTY_PID}"
rubin_process_stop_pid "${EMPTY_PID}"
EMPTY_CHAINSTATE="${EMPTY_DIR}/chainstate.json"
[[ -f "${EMPTY_CHAINSTATE}" ]] || fail "empty-chainstate capture produced no chainstate file"
"${GO_BIN}" --datadir "${EMPTY_DIR}" --dry-run >"${ART}/empty-capture.verify" 2>&1
grep -F -q -x "chainstate: has_tip=false height=0 utxos=0 already_generated=0" \
  "${ART}/empty-capture.verify" ||
  fail "empty-chainstate capture is not the encoded no-tip state"
grep -F -q -x "blockstore: empty" "${ART}/empty-capture.verify" ||
  fail "empty-chainstate capture store is not empty"

TIP_HASH="$(python3 - "${BASE_DIR}/blockstore/index.json" <<'PY'
import json
import sys

with open(sys.argv[1], "rb") as handle:
    canonical = json.load(handle)["canonical"]
if not canonical:
    raise SystemExit("canonical index is empty")
print(canonical[-1])
PY
)"
[[ "${TIP_HASH}" =~ ^[0-9a-f]{64}$ ]] || fail "unexpected canonical tip hash: ${TIP_HASH}"

echo "Preparing the storage shapes"
ABSENT_DIR="${ART}/absent-chainstate"
cp -R "${BASE_DIR}" "${ABSENT_DIR}"
rm -- "${ABSENT_DIR}/chainstate.json"

STALE_DIR="${ART}/stale-chainstate"
cp -R "${BASE_DIR}" "${STALE_DIR}"
cp -- "${EMPTY_CHAINSTATE}" "${STALE_DIR}/chainstate.json"

NO_UNDO_DIR="${ART}/tip-undo-absent"
cp -R "${BASE_DIR}" "${NO_UNDO_DIR}"
rm -- "${NO_UNDO_DIR}/blockstore/undo/${TIP_HASH}.json"

NO_BLOB_DIR="${ART}/tip-block-blob-absent"
cp -R "${BASE_DIR}" "${NO_BLOB_DIR}"
rm -- "${NO_BLOB_DIR}/blockstore/blocks/${TIP_HASH}.bin"
[[ -f "${NO_BLOB_DIR}/blockstore/headers/${TIP_HASH}.bin" ]] ||
  fail "block-blob-absent shape must keep the tip header"
[[ -f "${NO_BLOB_DIR}/blockstore/undo/${TIP_HASH}.json" ]] ||
  fail "block-blob-absent shape must keep the tip undo entry"

# One datadir per tip-header shape: the canonical index and the chainstate name
# the same tip and its block and undo entries stay present, so only the header
# path differs. Neither client reads that header on the dry-run path, so every
# shape is an accepted row.
prepare_header_shape() {
  local shape="$1" dir="${ART}/tip-header-$1" header
  cp -R "${BASE_DIR}" "${dir}"
  header="${dir}/blockstore/headers/${TIP_HASH}.bin"
  case "${shape}" in
    absent) rm -- "${header}" ;;
    dangling-symlink)
      rm -- "${header}"
      ln -s "${dir}/blockstore/headers/no-such-header.bin" "${header}"
      ;;
    zero-length) : >"${header}" ;;
    malformed) printf 'not a block header' >"${header}" ;;
    mode-000) chmod 0000 "${header}" ;;
    directory)
      rm -- "${header}"
      mkdir -- "${header}"
      ;;
    *) fail "unknown tip-header shape: ${shape}" ;;
  esac
  [[ -e "${dir}/blockstore/blocks/${TIP_HASH}.bin" ]] ||
    fail "${shape}: the shape must keep the tip block blob"
  [[ -e "${dir}/blockstore/undo/${TIP_HASH}.json" ]] ||
    fail "${shape}: the shape must keep the tip undo entry"
}

# Probed once up front rather than from a failure inside the loop, so a broken
# `cp` can never be misreported as an unsupported-platform skip.
SYMLINK_SUPPORTED=1
ln -s /nonexistent "${ART}/symlink-probe" 2>/dev/null || SYMLINK_SUPPORTED=0
[[ "${SYMLINK_SUPPORTED}" == "0" ]] || rm -- "${ART}/symlink-probe"

HARDLINK_DIR="${ART}/hardlinked-chainstate"
cp -R "${BASE_DIR}" "${HARDLINK_DIR}"
HARDLINK_WITNESS_DIR="${ART}/hardlink-witness"
mkdir -- "${HARDLINK_WITNESS_DIR}"
ln -- "${HARDLINK_DIR}/chainstate.json" "${HARDLINK_WITNESS_DIR}/chainstate.link"

RO_DIR="${ART}/datadir-mode-0500"
cp -R "${BASE_DIR}" "${RO_DIR}"

LIVE_DIR="${ART}/live-node-datadir"
cp -R "${BASE_DIR}" "${LIVE_DIR}"

echo
echo "Storage/permission/hardlink/live-node shapes (F0_BASE on each)"
for attempt in 1 2 3; do
  compare_row "healthy-run-${attempt}" "${HEALTHY_DIR}" --datadir "${HEALTHY_DIR}" --dry-run
done
compare_row "absent-chainstate" "${ABSENT_DIR}" --datadir "${ABSENT_DIR}" --dry-run
compare_row "stale-chainstate" "${STALE_DIR}" --datadir "${STALE_DIR}" --dry-run
compare_row "tip-undo-absent" "${NO_UNDO_DIR}" --datadir "${NO_UNDO_DIR}" --dry-run
compare_row "tip-block-blob-absent" "${NO_BLOB_DIR}" --datadir "${NO_BLOB_DIR}" --dry-run

# The rows the contract pins field-by-field: chainstate and the canonical index
# both name a tip, and only the shape at its header path varies. Rust builds the
# dry-run reporting engine with no blockstore and therefore never reads that
# header, matching Go, so the values below must hold on BOTH clients for all six.
for shape in absent dangling-symlink zero-length malformed mode-000 directory; do
  HEADER_LABEL="tip-header-${shape}"
  HEADER_DIR="${ART}/${HEADER_LABEL}"
  if [[ "${shape}" == "dangling-symlink" && "${SYMLINK_SUPPORTED}" == "0" ]]; then
    printf 'SKIP  %-32s reason=symlink_unsupported\n' "${HEADER_LABEL}"
    SKIPPED_ROWS+=("${HEADER_LABEL}")
    continue
  fi
  # A mode-000 file does not block uid 0, so as root the row would prove nothing.
  if [[ "${shape}" == "mode-000" && "$(id -u)" == "0" ]]; then
    printf 'SKIP  %-32s reason=euid_is_root\n' "${HEADER_LABEL}"
    SKIPPED_ROWS+=("${HEADER_LABEL}")
    continue
  fi
  prepare_header_shape "${shape}"
  compare_row "${HEADER_LABEL}" "${HEADER_DIR}" --datadir "${HEADER_DIR}" --dry-run
  for impl in go rust; do
    for expected in \
      "chainstate.tip=${TIP_HASH}" \
      "blockstore.tip_hash=${TIP_HASH}" \
      "sync.header_request_has_from=true" \
      "sync.header_request_limit=512" \
      "sync.ibd=true"; do
      grep -F -q -x "${expected}" "$(artifact "${HEADER_LABEL}" "${impl}.projection")" ||
        fail "${HEADER_LABEL}: ${impl} projection is missing ${expected}"
    done
  done
  [[ -e "${HEADER_DIR}/blockstore/blocks/${TIP_HASH}.bin" ]] ||
    fail "${HEADER_LABEL}: the tip block blob must survive the row"
  printf 'PASS  %-32s\n' "${HEADER_LABEL}-fields"
done

WITNESS_BEFORE="${ART}/hardlink-witness.before"
WITNESS_AFTER="${ART}/hardlink-witness.after"
snapshot "${HARDLINK_WITNESS_DIR}" >"${WITNESS_BEFORE}"
compare_row "hardlinked-chainstate" "${HARDLINK_DIR}" --datadir "${HARDLINK_DIR}" --dry-run
snapshot "${HARDLINK_WITNESS_DIR}" >"${WITNESS_AFTER}"
diff -u "${WITNESS_BEFORE}" "${WITNESS_AFTER}" ||
  fail "hardlinked chainstate lost its bytes, inode or link count"

if [[ "$(id -u)" == "0" ]]; then
  printf 'SKIP  %-32s reason=euid_is_root\n' "datadir-mode-0500"
  SKIPPED_ROWS+=("datadir-mode-0500")
else
  RESTORE_MODE_DIR="${RO_DIR}"
  chmod 0500 "${RO_DIR}"
  compare_row "datadir-mode-0500" "${RO_DIR}" --datadir "${RO_DIR}" --dry-run
  chmod 0700 "${RO_DIR}"
  RESTORE_MODE_DIR=""
fi

echo "Starting a live node on a prepared datadir"
rubin_process_start "live-node.log" "${GO_BIN}" --datadir "${LIVE_DIR}" --bind 127.0.0.1:0
LIVE_PID="${RUBIN_PROCESS_LAST_PID}"
rubin_process_wait_for_log "live-node.log" "rubin-node skeleton running" 60 "${LIVE_PID}"
compare_row "live-node-holds-datadir" "${LIVE_DIR}" --datadir "${LIVE_DIR}" --dry-run
rubin_process_is_alive "${LIVE_PID}" ||
  fail "live node exited during the observation window; the row proves nothing"
rubin_process_stop_pid "${LIVE_PID}"

echo
echo "Flag rows on the healthy initialized store"
# F0_BASE on the healthy store is argv-identical to healthy-run-1..3 above and
# is not repeated here; the contract lists it in both places because it is also
# the row driven across every storage shape.
compare_row "f1-network-genesis" "${HEALTHY_DIR}" \
  --network devnet --genesis-file "${GENESIS_FILE}" --datadir "${HEALTHY_DIR}" --dry-run
compare_row "f2-bind" "${HEALTHY_DIR}" \
  --datadir "${HEALTHY_DIR}" --bind 127.0.0.1:29111 --dry-run
compare_row "f3-peers-csv-first" "${HEALTHY_DIR}" \
  --datadir "${HEALTHY_DIR}" --peers 127.0.0.1:29114,127.0.0.1:29115 \
  --peer 127.0.0.1:29112 --peer 127.0.0.1:29113 --max-peers 8 --dry-run
compare_row "f3-peers-repeat-first" "${HEALTHY_DIR}" \
  --datadir "${HEALTHY_DIR}" --peer 127.0.0.1:29112 --peer 127.0.0.1:29113 \
  --peers 127.0.0.1:29114,127.0.0.1:29115 --max-peers 8 --dry-run
compare_row "f3-peers-last-wins" "${HEALTHY_DIR}" \
  --datadir "${HEALTHY_DIR}" --peers 127.0.0.1:29114,127.0.0.1:29115 \
  --peer 127.0.0.1:29112 --peers 127.0.0.1:29117 --peer 127.0.0.1:29113 \
  --max-peers 8 --dry-run
compare_row "f4-rpc" "${HEALTHY_DIR}" \
  --datadir "${HEALTHY_DIR}" --rpc-bind 127.0.0.1:29116 --dry-run
# f5/f6 contribute no compared bytes for the flags they name: `mine_blocks`,
# `mine_exit`, `pv_mode` and `pv_shadow_max` are all client-only JSON fields,
# excluded from the projection. They prove the flags stay accepted and
# zero-write, not that their values agree.
compare_row "f5-miner" "${HEALTHY_DIR}" \
  --datadir "${HEALTHY_DIR}" --mine-address "${MINE_ADDRESS}" --mine-blocks 2 --mine-exit --dry-run
compare_row "f6-pv" "${HEALTHY_DIR}" \
  --datadir "${HEALTHY_DIR}" --pv-mode shadow --pv-shadow-max 7 --dry-run
compare_row "f7-all" "${HEALTHY_DIR}" \
  --network devnet --genesis-file "${GENESIS_FILE}" --datadir "${HEALTHY_DIR}" \
  --bind 127.0.0.1:29111 --peers 127.0.0.1:29114,127.0.0.1:29115 \
  --peer 127.0.0.1:29112 --peer 127.0.0.1:29113 --max-peers 8 --rpc-bind 127.0.0.1:29116 \
  --mine-address "${MINE_ADDRESS}" --mine-blocks 2 --mine-exit --pv-mode shadow \
  --pv-shadow-max 7 --dry-run

# Both argv permutations must yield the same ordered peer list on both clients:
# every `--peers` CSV entry precedes every repeated `--peer` entry.
for impl in go rust; do
  diff -u "$(artifact "f3-peers-csv-first" "${impl}.projection")" \
    "$(artifact "f3-peers-repeat-first" "${impl}.projection")" ||
    fail "${impl}: peer argv permutation changed the projection"
done
printf 'PASS  %-32s\n' "peer-argv-permutation"

# `F3_PEERS_LAST_WINS`: Go's `--peers` is a `flag.String`
# (`clients/go/cmd/rubin-node/main.go:292`), so a repeated occurrence overwrites
# and only the final CSV reaches `append([]string{*peerCSV}, peers...)`.
# compare_row's cross-client diff reddens if exactly one client accumulated, but
# not if both accumulate alike, so pin the exact ordered list per client.
PEERS_LAST_WINS_EXPECTED='json.peers=["127.0.0.1:29117", "127.0.0.1:29112", "127.0.0.1:29113"]'
for impl in go rust; do
  grep -Fxq -- "${PEERS_LAST_WINS_EXPECTED}" \
    "$(artifact "f3-peers-last-wins" "${impl}.projection")" ||
    fail "${impl}: a repeated --peers must keep only the final CSV; expected ${PEERS_LAST_WINS_EXPECTED}"
done
printf 'PASS  %-32s\n' "peers-last-occurrence-wins"

echo
if ((${#SKIPPED_ROWS[@]} > 0)); then
  printf 'PASS: Go/Rust --dry-run parity and zero-write hold on every RUB-1083 row except %d allowed skip(s): %s\n' \
    "${#SKIPPED_ROWS[@]}" "${SKIPPED_ROWS[*]}"
else
  echo "PASS: Go/Rust --dry-run parity and zero-write hold on every RUB-1083 row"
fi

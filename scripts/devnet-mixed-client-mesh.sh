#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"; GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
RUST_WORKSPACE_ROOT="${REPO_ROOT}/clients/rust"; HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"; VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"
CHECK_REPORT="" CHECK_REPORT_MODE="" MESH_TIMEOUT="${MESH_TIMEOUT:-90}" TX_PATH_MODE=0 RUST_RESTART_MODE=0 PARTITION_HEAL_REORG_MODE=0 DETERMINISTIC_TX_FEE="${DETERMINISTIC_TX_FEE:-100000000}"
usage() {
  cat >&2 <<EOF
usage:
  $0 [--rust-restart|--partition-heal-reorg|--go-submit-rust-accept|--go-submit-rust-mine-go-converge|--rust-submit-go-mine-rust-converge]
  $0 --check-report PATH
  $0 --rust-restart --check-report PATH
  $0 --check-report-live PATH

--check-report and --check-report-live validate mixed_client_mesh reports.
tx-path proofs are same-run producer validation and are not accepted from public
report revalidation paths. Use --rust-restart or --partition-heal-reorg with
--check-report to validate same-run producer reports offline. Public
--rust-restart/--partition-heal-reorg --check-report-live is unsupported because
these lifecycle proofs are same-run producer evidence.
EOF
}
set_tx_path_mode() { local mode="$1" flag="$2"; (( TX_PATH_MODE == 0 )) || { echo "tx-path modes are mutually exclusive: ${flag}" >&2; usage; exit 2; }; TX_PATH_MODE="${mode}"; }
while (($#)); do case "$1" in --rust-restart) RUST_RESTART_MODE=1; shift ;; --partition-heal-reorg) PARTITION_HEAL_REORG_MODE=1; shift ;; --go-submit-rust-accept) set_tx_path_mode 1 "$1"; shift ;; --go-submit-rust-mine-go-converge) set_tx_path_mode 2 "$1"; shift ;; --rust-submit-go-mine-rust-converge) set_tx_path_mode 3 "$1"; shift ;; --check-report|--check-report-live) [[ $# -ge 2 ]] || { usage; exit 2; }; CHECK_REPORT_MODE=offline; [[ "$1" == "--check-report-live" ]] && CHECK_REPORT_MODE=live; CHECK_REPORT="$2"; shift 2 ;; -h|--help) usage; exit 0 ;; *) usage; exit 2 ;; esac; done
if [[ -n "${CHECK_REPORT_MODE}" && "${TX_PATH_MODE}" != "0" ]]; then echo "tx-path modes cannot be combined with --check-report or --check-report-live" >&2; exit 2; fi
if (( RUST_RESTART_MODE == 1 && TX_PATH_MODE != 0 )); then echo "--rust-restart cannot be combined with tx-path modes" >&2; exit 2; fi
if (( PARTITION_HEAL_REORG_MODE == 1 && TX_PATH_MODE != 0 )); then echo "--partition-heal-reorg cannot be combined with tx-path modes" >&2; exit 2; fi
if (( RUST_RESTART_MODE == 1 && PARTITION_HEAL_REORG_MODE == 1 )); then echo "--rust-restart cannot be combined with --partition-heal-reorg" >&2; exit 2; fi
if (( RUST_RESTART_MODE == 1 )) && [[ "${CHECK_REPORT_MODE}" == "live" ]]; then echo "--rust-restart --check-report-live is unsupported; same-run producer evidence is required" >&2; exit 2; fi
if (( PARTITION_HEAL_REORG_MODE == 1 )) && [[ "${CHECK_REPORT_MODE}" == "live" ]]; then echo "--partition-heal-reorg --check-report-live is unsupported; same-run producer evidence is required" >&2; exit 2; fi
need_tool() { command -v -- "$1" >/dev/null 2>&1 || { echo "$1 is required for mixed-client mesh evidence" >&2; exit 1; }; }
validate_deterministic_tx_fee() {
  [[ "${DETERMINISTIC_TX_FEE}" =~ ^[0-9]{1,9}$ ]] || { echo "DETERMINISTIC_TX_FEE must be a positive integer <= 100000000" >&2; exit 2; }
  DETERMINISTIC_TX_FEE="$((10#${DETERMINISTIC_TX_FEE}))"
  (( DETERMINISTIC_TX_FEE > 0 && DETERMINISTIC_TX_FEE <= 100000000 )) || { echo "DETERMINISTIC_TX_FEE must be a positive integer <= 100000000" >&2; exit 2; }
  export DETERMINISTIC_TX_FEE
}
run_validator() { RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- python3 "${VALIDATOR}" "$@"; }
check_report() { local report="${1:-}" mode="${2:-offline}" expected_mode="${3:-public}"
  [[ -n "${report}" ]] || { echo "FAIL: report path is required" >&2; return 1; }
  RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- python3 - "${report}" "${VALIDATOR}" "${mode}" "${expected_mode}" "${DEV_ENV}" "${GO_MODULE_ROOT}" <<'PY'
import datetime as dt, json, math, os, re, socket, struct, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path
path = Path(sys.argv[1]); live = sys.argv[3] == "live"; expected_mode = sys.argv[4]; dev_env = sys.argv[5]; go_module_root = sys.argv[6]
SCENARIO_MESH = "mixed_client_mesh"
SCENARIO_TX = "mixed_client_go_submit_rust_accept"
SCENARIO_CONVERGE = "mixed_client_go_submit_rust_mine_go_converge"
SCENARIO_RUST_SUBMIT_GO_MINE = "mixed_client_rust_submit_go_mine_rust_converge"
SCENARIO_RUST_RESTART = "mixed_client_rust_restart"
SCENARIO_PARTITION_HEAL_REORG = "mixed_client_partition_heal_reorg"
MAX_JSON_BYTES = 1_000_000
MAX_PARSER_OUTPUT_BYTES = 100_000
MAX_TX_HEX_CHARS = 20_000
def fail(message: str) -> None: print(f"FAIL: {message}", file=sys.stderr); sys.exit(1)
try: LIVE_TIMEOUT = int(os.environ["MESH_TIMEOUT"])
except (KeyError, ValueError): fail("MESH_TIMEOUT must be an integer in [1, 600]")
def req(ok: bool, message: str) -> None:
    if not ok: fail(message)
def eventually(fn, message: str) -> None:
    deadline = time.monotonic() + LIVE_TIMEOUT
    while True:
        if fn(): return
        if not live or time.monotonic() >= deadline: fail(message)
        time.sleep(1)
def checked_path(label: str, value: object) -> Path:
    req(isinstance(value, str) and value.strip() == value and value and value[0] not in "'\"" and value[-1] not in "'\"" and "\0" not in value and all(ord(c) >= 32 for c in value), f"{label} is not a safe unquoted path string")
    try: p = Path(value); req(p.is_absolute(), f"{label} is not absolute"); return p.resolve()
    except (OSError, ValueError) as exc: fail(f"{label} path is invalid: {exc}")
def ep(value: object) -> bool:
    if not isinstance(value, str): return False
    host, sep, port = value.partition(":")
    return sep == ":" and host == "127.0.0.1" and ":" not in port and port.isascii() and port.isdigit() and 1 <= len(port) <= 5 and 1 <= int(port) <= 65535
def nonempty_str(value: object) -> bool: return isinstance(value, str) and bool(value.strip())
def exact_object(data: object, keys: set[str], label: str) -> dict:
    req(isinstance(data, dict), f"{label} is not an object")
    req(set(data) == keys, f"{label} keys mismatch: {sorted(data)}")
    return data
def load_bounded_json(label: str, p: Path) -> object:
    try:
        req(p.is_file(), f"{label} is not a regular file")
        with p.open("rb") as f:
            raw = f.read(MAX_JSON_BYTES + 1)
    except OSError as exc:
        fail(f"{label} read failed: {exc}")
    req(raw != b"", f"{label} is empty")
    req(len(raw) <= MAX_JSON_BYTES, f"{label} is too large")
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        fail(f"{label} malformed JSON: {exc}")
def load_json_file(label: str, p: Path) -> dict:
    data = load_bounded_json(label, p)
    req(isinstance(data, dict), f"{label} root is not an object")
    return data
def hex32(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
def is_json_int(value: object, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= 1_000_000_000
def tip_obj(value: object, label: str) -> dict:
    req(isinstance(value, dict) and set(value) == {"height", "hash"}, f"{label} keys mismatch")
    req(is_json_int(value.get("height")) and hex32(value.get("hash")), f"{label} malformed")
    return value
def tip_sidecar(label: str, p: Path, impl: str, endpoint: str, height: int, block_hash: str) -> None:
    tip = load_json_file(label, p)
    req(set(tip) == {"best_known_height", "has_tip", "height", "implementation", "in_ibd", "request_path", "rpc_endpoint", "tip_hash"}, f"{label} keys mismatch: {sorted(tip)}")
    req(tip.get("implementation") == impl and tip.get("rpc_endpoint") == endpoint and tip.get("request_path") == "/get_tip", f"{label} sidecar identity mismatch")
    req(tip.get("has_tip") is True and tip.get("height") == height and tip.get("tip_hash") == block_hash and is_json_int(tip.get("best_known_height")) and tip["best_known_height"] >= height, f"{label} does not match expected tip")
def block_sidecar(label: str, p: Path, impl: str, endpoint: str, height: int, block_hash: str) -> None:
    block = load_json_file(label, p)
    req(set(block) == {"block_hex", "canonical", "hash", "height", "implementation", "request_path", "rpc_endpoint"}, f"{label} keys mismatch: {sorted(block)}")
    req(block.get("implementation") == impl and block.get("rpc_endpoint") == endpoint and block.get("request_path") == f"/get_block?height={height}", f"{label} sidecar identity mismatch")
    req(block.get("canonical") is True and block.get("height") == height and block.get("hash") == block_hash and isinstance(block.get("block_hex"), str) and re.fullmatch(r"[0-9a-f]+", block["block_hex"] or "") is not None, f"{label} does not match expected block")
    request = json.dumps({"op": "block_basic_check", "block_hex": block["block_hex"], "height": height}) + "\n"
    try:
        proc = subprocess.run([dev_env, "--", "go", "-C", go_module_root, "run", "./cmd/rubin-consensus-cli"], check=False, env={**os.environ, "RUBIN_OPENSSL_SKIP_FIPS_GUARD": "1"}, input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=max(30, min(LIVE_TIMEOUT, 60)))
    except subprocess.TimeoutExpired:
        fail(f"{label} block payload check timeout")
    except OSError as exc:
        fail(f"{label} block payload checker unavailable: {exc}")
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    req(len(stdout) <= MAX_PARSER_OUTPUT_BYTES and len(stderr) <= MAX_PARSER_OUTPUT_BYTES, f"{label} block payload check output too large")
    if proc.returncode != 0:
        detail = ((stderr or stdout).strip().splitlines() or ["block checker returned nonzero"])[0]
        fail(f"{label} block payload check failed: {detail}")
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        fail(f"{label} block payload checker malformed output: {exc}")
    req(isinstance(parsed, dict), f"{label} block payload checker root is not an object")
    if parsed.get("ok") is not True:
        detail = parsed.get("err")
        fail(f"{label} block payload check failed: {detail if isinstance(detail, str) else 'block_basic_check rejected block'}")
    req(parsed.get("block_hash") == block_hash, f"{label} parsed block hash mismatch")
def mine_sidecar(label: str, p: Path, impl: str, endpoint: str, min_height: int = 1) -> dict:
    mine = load_json_file(label, p)
    req(set(mine) == {"block_hash", "height", "implementation", "mined", "nonce", "request_path", "rpc_endpoint", "timestamp", "tx_count"}, f"{label} keys mismatch: {sorted(mine)}")
    req(mine.get("implementation") == impl and mine.get("rpc_endpoint") == endpoint and mine.get("request_path") == "/mine_next", f"{label} sidecar identity mismatch")
    req(mine.get("mined") is True and is_json_int(mine.get("height"), min_height) and hex32(mine.get("block_hash")) and is_json_int(mine.get("tx_count"), 1), f"{label} malformed mine result")
    return mine
def peer_snapshot(label: str, p: Path, expected, want_connected: bool) -> None:
    snap = load_json_file(label, p)
    peers = snap.get("peers")
    req(set(snap) == {"count", "peers"} and isinstance(peers, list) and snap.get("count") == len(peers), f"{label} peer snapshot malformed")
    req(all(isinstance(peer, dict) and ep(peer.get("addr")) and isinstance(peer.get("handshake_complete"), bool) for peer in peers), f"{label} peer entries malformed")
    req(len({peer.get("addr") for peer in peers}) == len(peers), f"{label} peer entries are duplicated")
    complete = [peer["addr"] for peer in peers if peer.get("handshake_complete") is True]
    if want_connected:
        req(expected is not None and complete == [expected] and len(peers) == 1, f"{label} does not prove expected connected peer")
    else:
        req(expected is None and complete == [] and len(peers) == 0, f"{label} does not prove partitioned peer state")
def artifact_file(label: str, value: object, root: Path) -> Path:
    p = checked_path(label, value)
    try: p.relative_to(root)
    except ValueError: fail(f"{label} is outside artifact_root")
    req(p.is_file(), f"{label} file is missing")
    return p
def tx_sidecars(status: dict, got: dict, txid: str, txhex: str, label: str, impl: str, endpoint: str, status_path: str, get_path: str) -> None:
    req(set(status) == {"implementation", "request_path", "rpc_endpoint", "status", "txid"}, f"{label}.tx_status keys mismatch: {sorted(status)}")
    req(status.get("implementation") == impl and status.get("rpc_endpoint") == endpoint and status.get("request_path") == status_path, f"{label}.tx_status capture identity mismatch")
    req(status.get("status") == "pending", f"{label}.tx_status is not pending")
    req(status.get("txid") == txid, f"{label}.tx_status txid mismatch")
    req(set(got) == {"found", "implementation", "raw_hex", "request_path", "rpc_endpoint", "txid"}, f"{label}.get_tx keys mismatch: {sorted(got)}")
    req(got.get("implementation") == impl and got.get("rpc_endpoint") == endpoint and got.get("request_path") == get_path, f"{label}.get_tx capture identity mismatch")
    req(got.get("found") is True, f"{label}.get_tx did not find tx")
    req(got.get("txid") == txid, f"{label}.get_tx txid mismatch")
    req(got.get("raw_hex") == txhex, f"{label}.get_tx raw_hex mismatch")
def tx_rpc(addr: str, path_suffix: str, label: str, impl: str) -> dict:
    try:
        with urllib.request.urlopen(f"http://{addr}{path_suffix}", timeout=5) as resp: raw = resp.read(1000001)
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc: fail(f"{label} rpc failed: {exc}")
    req(len(raw) <= 1000000, f"{label} rpc response too large")
    try: data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc: fail(f"{label} rpc malformed JSON: {exc}")
    req(isinstance(data, dict), f"{label} rpc root is not an object")
    data.update({"implementation": impl, "rpc_endpoint": addr, "request_path": path_suffix})
    return data
def parse_txid_from_hex(txhex: str) -> str:
    request = json.dumps({"op": "parse_tx", "tx_hex": txhex}) + "\n"
    try:
        proc = subprocess.run([dev_env, "--", "go", "-C", go_module_root, "run", "./cmd/rubin-consensus-cli"], check=False, env={**os.environ, "RUBIN_OPENSSL_SKIP_FIPS_GUARD": "1"}, input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        fail("tx parser timeout")
    except OSError as exc:
        fail(f"tx parser unavailable: {exc}")
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    req(len(stdout) <= MAX_PARSER_OUTPUT_BYTES and len(stderr) <= MAX_PARSER_OUTPUT_BYTES, "tx parser output too large")
    if proc.returncode != 0:
        detail = ((stderr or stdout).strip().splitlines() or ["parser returned nonzero"])[0]
        fail(f"tx parser failed: {detail}")
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        fail(f"tx parser malformed output: {exc}")
    req(isinstance(parsed, dict), "tx parser root is not an object")
    txid = parsed.get("txid")
    req(parsed.get("ok") is True and isinstance(txid, str) and re.fullmatch(r"[0-9a-f]{64}", txid), "tx parser did not produce txid")
    req(parsed.get("consumed") == len(txhex) // 2, "tx parser consumed mismatch")
    return txid
def verify_block_inclusion_sidecar(label: str, p: Path, txhex: str, txid: str, height: int, block_hash: str, tx_count: int, impl: str, endpoint: str, request_path: str) -> None:
    block = load_json_file(label, p)
    req(set(block) == {"block_hex", "canonical", "hash", "height", "implementation", "request_path", "rpc_endpoint"}, f"{label} keys mismatch: {sorted(block)}")
    req(block.get("implementation") == impl and block.get("rpc_endpoint") == endpoint and block.get("request_path") == request_path, f"{label} sidecar identity mismatch")
    req(block.get("canonical") is True and block.get("height") == height and block.get("hash") == block_hash, f"{label} sidecar height/hash/canonical mismatch")
    req(isinstance(block.get("block_hex"), str) and block["block_hex"], f"{label} block_hex is missing")
    source = r'''
package main
import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)
type blockResp struct {
	Hash string `json:"hash"`
	Height uint64 `json:"height"`
	Canonical bool `json:"canonical"`
	BlockHex string `json:"block_hex"`
}
func die(v any) { fmt.Fprintln(os.Stderr, v); os.Exit(1) }
func main() {
	respPath := flag.String("block-response", "", "")
	txHex := flag.String("tx-hex", "", "")
	txidHex := flag.String("txid", "", "")
	heightRaw := flag.String("height", "", "")
	hashHex := flag.String("hash", "", "")
	txCountRaw := flag.String("tx-count", "", "")
	flag.Parse()
	wantHeight, err := strconv.ParseUint(*heightRaw, 10, 64); if err != nil { die("bad height") }
	wantTxCount, err := strconv.ParseUint(*txCountRaw, 10, 64); if err != nil { die("bad tx_count") }
	raw, err := os.ReadFile(*respPath); if err != nil { die("read block response: " + err.Error()) }
	var resp blockResp; if err := json.Unmarshal(raw, &resp); err != nil { die("decode block response: " + err.Error()) }
	if resp.Height != wantHeight || strings.ToLower(resp.Hash) != strings.ToLower(*hashHex) || !resp.Canonical { die("block response height/hash/canonical mismatch") }
	txBytes, err := hex.DecodeString(strings.TrimSpace(*txHex)); if err != nil { die("decode tx_hex: " + err.Error()) }
	_, wantTxid, _, consumed, err := consensus.ParseTx(txBytes); if err != nil || consumed != len(txBytes) { die("parse tx_hex failed") }
	if hex.EncodeToString(wantTxid[:]) != strings.ToLower(*txidHex) { die("tx_hex txid mismatch") }
	blockBytes, err := hex.DecodeString(strings.TrimSpace(resp.BlockHex)); if err != nil { die("decode block_hex: " + err.Error()) }
	pb, err := consensus.ParseBlockBytes(blockBytes); if err != nil { die("parse block_hex failed: " + err.Error()) }
	gotBlockHash, err := consensus.BlockHash(pb.HeaderBytes); if err != nil || hex.EncodeToString(gotBlockHash[:]) != strings.ToLower(*hashHex) { die("parsed block hash mismatch") }
	if pb.TxCount != wantTxCount { die("parsed block tx_count mismatch") }
	if _, err := consensus.ValidateBlockBasicAtHeight(blockBytes, nil, nil, wantHeight); err != nil { die("basic block validation failed: " + err.Error()) }
	for i, got := range pb.Txids { if i > 0 && got == wantTxid { return } }
	die("submitted txid missing from parsed block txids")
}
'''
    with tempfile.TemporaryDirectory(prefix="rubin-mesh-block-check-") as td:
        source_path = Path(td) / "block-check.go"
        source_path.write_text(source, encoding="utf-8")
        try:
            proc = subprocess.run([dev_env, "--", "go", "-C", go_module_root, "run", str(source_path), "--block-response", str(p), "--tx-hex", txhex, "--txid", txid, "--height", str(height), "--hash", block_hash, "--tx-count", str(tx_count)], check=False, env={**os.environ, "RUBIN_OPENSSL_SKIP_FIPS_GUARD": "1"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=max(30, min(LIVE_TIMEOUT, 60)))
        except subprocess.TimeoutExpired:
            fail(f"{label} inclusion check timeout")
        except OSError as exc:
            fail(f"{label} inclusion check unavailable: {exc}")
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    req(len(stdout) <= MAX_PARSER_OUTPUT_BYTES and len(stderr) <= MAX_PARSER_OUTPUT_BYTES, f"{label} inclusion check output too large")
    if proc.returncode != 0:
        detail = ((stderr or stdout).strip().splitlines() or ["block checker returned nonzero"])[0]
        fail(f"{label} inclusion check failed: {detail}")
def pid_exe(pid: int) -> str:
    proc = Path(f"/proc/{pid}/exe")
    if proc.exists() or Path("/proc").is_dir():
        try: return str(proc.resolve(strict=True))
        except FileNotFoundError: return ""
        except OSError as exc: fail(f"pid_exe_failed: {exc}")
    try:
        import ctypes; buf = ctypes.create_string_buffer(4096); n = ctypes.CDLL(None).proc_pidpath(int(pid), buf, len(buf))
    except (AttributeError, OSError) as exc: fail(f"pid_exe_unavailable: {exc}")
    return os.path.realpath(buf.value.decode()) if n > 0 else ""
def pid_argv(pid: int) -> list[str]:
    cmdline = Path(f"/proc/{pid}/cmdline")
    if cmdline.exists() or Path("/proc").is_dir():
        try: raw = cmdline.read_bytes()
        except FileNotFoundError: return []
        except OSError as exc: fail(f"argv_unavailable: {exc}")
        return [a.decode("utf-8", "surrogateescape") for a in raw.rstrip(b"\0").split(b"\0") if a]
    try:
        import ctypes; libc = ctypes.CDLL(None); mib = (ctypes.c_int * 3)(1, 49, int(pid)); size = ctypes.c_size_t(0)
        if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0: fail("argv_unavailable")
        buf = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, 3, buf, ctypes.byref(size), None, 0) != 0: fail("argv_unavailable")
    except (AttributeError, OSError) as exc: fail(f"argv_unavailable: {exc}")
    raw = buf.raw[:size.value]; argc = struct.unpack_from("i", raw)[0]; i = raw.find(b"\0", 4)
    while i < len(raw) and raw[i] == 0: i += 1
    args = []
    for _ in range(argc):
        j = raw.find(b"\0", i)
        if j < 0: break
        args.append(raw[i:j].decode("utf-8", "surrogateescape")); i = j + 1
    return args
def argv_eq(actual: list[str], expected: list[str], actual_label: str = "live argv", expected_label: str = "report command_argv") -> bool:
    if len(actual) != len(expected) or not actual:
        return False
    if checked_path(f"{actual_label}[0]", actual[0]) != checked_path(f"{expected_label}[0]", expected[0]):
        return False
    path_flags = {"--datadir"}
    i = 1
    while i < len(expected):
        if expected[i] in path_flags:
            if i + 1 >= len(expected):
                return False
            if actual[i] != expected[i] or checked_path(f"{actual_label}[{i + 1}]", actual[i + 1]) != checked_path(f"{expected_label}[{i + 1}]", expected[i + 1]):
                return False
            i += 2
            continue
        if actual[i] != expected[i]:
            return False
        i += 1
    return True
def report_node_argv_eq(node: dict, datadir_name: str, extra: list[str]) -> bool:
    argv = node.get("command_argv")
    expected = [node["binary"], "--network", "devnet", "--datadir", str(Path(artifact_root_arg) / datadir_name), "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0"] + extra
    return isinstance(argv, list) and len(argv) == len(expected) and argv_eq(argv, expected, "report command_argv", "expected command_argv")
def lsof_lines(pid: int, state: str) -> list[str]:
    try:
        p = subprocess.run(["lsof", "-nP", "-a", "-p", str(pid), "-iTCP", f"-sTCP:{state}", "-Fn"], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    except FileNotFoundError: fail("lsof_unavailable")
    except subprocess.TimeoutExpired: fail("lsof_timeout")
    except OSError as exc: fail(f"lsof_failed: {exc}")
    req(p.returncode == 0 or not (p.stdout.strip() or p.stderr.strip()), "lsof_failed")
    if p.returncode != 0: return []
    return [line[1:] for line in p.stdout.splitlines() if line.startswith("n")]
def owns_listen(pid: int, endpoint: str) -> bool: return endpoint in lsof_lines(pid, "LISTEN")
def peers(addr: str) -> dict:
    try:
        with urllib.request.urlopen(f"http://{addr}/peers", timeout=5) as resp: raw = resp.read(MAX_JSON_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, socket.timeout):
        return None
    req(len(raw) <= MAX_JSON_BYTES, f"live peer snapshot too large for {addr}")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        fail(f"live peer snapshot malformed JSON for {addr}: {exc}")
    req(isinstance(data, dict), f"live peer snapshot malformed JSON for {addr}")
    return data
def snapshot_norm(snapshot: object, expected_addr: str, exact: bool = True) -> list[tuple[str, bool]]:
    count = snapshot.get("count") if isinstance(snapshot, dict) else None
    peers = snapshot.get("peers") if isinstance(snapshot, dict) else None
    req(isinstance(count, int) and not isinstance(count, bool) and isinstance(peers, list) and count == len(peers), "peer snapshot count/peers are invalid")
    norm = sorted((p.get("addr"), p.get("handshake_complete")) for p in peers if isinstance(p, dict) and ep(p.get("addr")) and isinstance(p.get("handshake_complete"), bool))
    req(len(norm) == len(peers) and len({addr for addr, _ in norm}) == len(norm), "peer snapshot entries are malformed or duplicated")
    if exact: req(norm == [(expected_addr, True)], "peer snapshot has unexpected peer set")
    return norm
def ts(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 20 or value[-1] != "Z": return False
    try: return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H:%M:%SZ") == value
    except ValueError: return False
def finite_nonnegative(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except (OverflowError, TypeError, ValueError):
        return False
def json_int(value, label, minimum=None):
    req(isinstance(value, int) and not isinstance(value, bool), f"{label} is not an integer")
    if minimum is not None:
        req(value >= minimum, f"{label} is below {minimum}")
    return value
def json_bool(value, label):
    req(isinstance(value, bool), f"{label} is not a boolean")
    return value
def json_hex32(value, label):
    req(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value or "") is not None, f"{label} is not lowercase 32-byte hex")
    return value
def validate_raw_sample_record(sample, label, kind, direction, source, target, txid, block_hash=None, height=None):
    keys = {"classification", "elapsed", "path_direction", "source", "target", "tx_id", "unit"}
    if kind == "convergence": keys |= {"block_hash", "height"}
    sample = exact_object(sample, keys, label)
    req(sample.get("classification") == "observed", f"{label}.classification is not observed")
    req(sample.get("unit") == "seconds", f"{label}.unit is not seconds")
    req(sample.get("path_direction") == direction and sample.get("source") == source and sample.get("target") == target, f"{label} path identity mismatch")
    elapsed = sample.get("elapsed")
    req(finite_nonnegative(elapsed), f"{label}.elapsed is not finite non-negative seconds")
    req(sample.get("tx_id") == txid, f"{label}.tx_id mismatch")
    if kind == "convergence":
        sample_block_hash = sample.get("block_hash")
        sample_height = sample.get("height")
        req(isinstance(sample_block_hash, str) and re.fullmatch(r"[0-9a-f]{64}", sample_block_hash or "") is not None, f"{label}.block_hash is not lowercase 32-byte hex")
        req(sample_block_hash == block_hash, f"{label}.block_hash mismatch")
        req(isinstance(sample_height, int) and not isinstance(sample_height, bool), f"{label}.height is not an integer")
        req(sample_height == height, f"{label}.height mismatch")
def validate_raw_sample_bucket(raw_samples, label, expected, direction, txid=None, block_hash=None, height=None):
    bucket = exact_object(raw_samples.get(label), {"classification", "path_direction", "reason", "samples", "unit"}, f"raw_samples.{label}")
    req(bucket.get("unit") == "seconds", f"raw_samples.{label}.unit is not seconds")
    req(bucket.get("path_direction") == direction, f"raw_samples.{label}.path_direction mismatch")
    samples = bucket.get("samples")
    req(isinstance(samples, list), f"raw_samples.{label}.samples is not a list")
    if expected == "observed":
        req(bucket.get("classification") == "observed", f"raw_samples.{label}.classification is not observed")
        req(bucket.get("reason") is None, f"raw_samples.{label}.reason must be null for observed samples")
        req(len(samples) == 1, f"raw_samples.{label} requires one observed sample")
        source_impl, target_impl = direction.split("->") if direction else ("", "")
        validate_raw_sample_record(samples[0], f"raw_samples.{label}.samples[0]", label, direction, f"node-{source_impl}", f"node-{target_impl}", txid or "", block_hash, height)
    else:
        expected_reason = f"{label}_sample_not_requested_by_scenario"
        req(bucket.get("classification") == "not_requested" and bucket.get("reason") == expected_reason, f"raw_samples.{label} must be not_requested with canonical reason")
        req(samples == [], f"raw_samples.{label} not_requested must not carry samples")
def validate_raw_samples(data, tx_mode, go_submit_mode, converge_mode, txid=None, block_hash=None, height=None):
    raw_samples = exact_object(data.get("raw_samples"), {"convergence", "propagation", "schema_version", "semantics"}, "raw_samples")
    req(raw_samples.get("schema_version") == "rubin-devnet-process-soak-raw-samples-v1", "raw_samples schema_version mismatch")
    req(raw_samples.get("semantics") == "raw samples only; no SLO threshold or pass claim", "raw_samples semantics must avoid SLO/pass threshold claims")
    if not tx_mode:
        validate_raw_sample_bucket(raw_samples, "propagation", "not_requested", None)
        validate_raw_sample_bucket(raw_samples, "convergence", "not_requested", None)
        return
    propagation_direction = "go->rust" if go_submit_mode else "rust->go"
    validate_raw_sample_bucket(raw_samples, "propagation", "observed", propagation_direction, txid)
    if not converge_mode:
        validate_raw_sample_bucket(raw_samples, "convergence", "not_requested", None)
        return
    convergence_direction = "rust->go" if go_submit_mode else "go->rust"
    validate_raw_sample_bucket(raw_samples, "convergence", "observed", convergence_direction, txid, block_hash, height)
data = load_json_file("report", path)
req(expected_mode in {"public", "producer-tx", "rust-restart", "partition-heal-reorg"}, f"check_report expected mode is invalid: {expected_mode!r}")
scenario = data.get("scenario")
go_submit_mode = scenario in {SCENARIO_TX, SCENARIO_CONVERGE}
rust_submit_mode = scenario == SCENARIO_RUST_SUBMIT_GO_MINE
tx_mode = go_submit_mode or rust_submit_mode
converge_mode = scenario in {SCENARIO_CONVERGE, SCENARIO_RUST_SUBMIT_GO_MINE}
restart_mode = scenario == SCENARIO_RUST_RESTART
partition_mode = scenario == SCENARIO_PARTITION_HEAL_REORG
req(scenario in {SCENARIO_MESH, SCENARIO_TX, SCENARIO_CONVERGE, SCENARIO_RUST_SUBMIT_GO_MINE, SCENARIO_RUST_RESTART, SCENARIO_PARTITION_HEAL_REORG}, f"scenario is not supported: {scenario!r}")
if tx_mode and expected_mode != "producer-tx":
    fail(("public tx-path check-report-live is unsupported" if live else "public tx-path check-report is unsupported") + "; same-run producer evidence is required")
if restart_mode and expected_mode != "rust-restart":
    fail(("public restart check-report-live is unsupported" if live else "public restart check-report is unsupported") + "; use --rust-restart with --check-report")
if partition_mode and expected_mode != "partition-heal-reorg":
    fail(("public partition-heal-reorg check-report-live is unsupported" if live else "public partition-heal-reorg check-report is unsupported") + "; use --partition-heal-reorg with --check-report")
if expected_mode == "producer-tx":
    req(tx_mode, "producer tx validation requires a mixed-client tx-path report")
if expected_mode == "rust-restart":
    req(restart_mode, "rust restart validation requires a mixed_client_rust_restart report")
if expected_mode == "partition-heal-reorg":
    req(partition_mode, "partition-heal-reorg validation requires a mixed_client_partition_heal_reorg report")
req(data.get("verdict") == "PASS", f"report verdict is not PASS: {data.get('verdict')!r}")
req("failure_reason" not in data and "schema_marker" not in data, "PASS report must not carry failure/schema-marker verdict fields")
base_keys = {"artifact_root", "final_verification", "legacy_schema_compatibility", "nodes", "peer_connectivity", "raw_samples", "scenario", "verdict"}
allowed_keys = base_keys
if go_submit_mode:
    allowed_keys |= {"go_submit", "rust_accept", "tx_path"}
    if converge_mode:
        allowed_keys |= {"rust_mine", "go_converge"}
elif rust_submit_mode:
    allowed_keys |= {"rust_submit", "go_accept", "go_mine", "rust_converge", "tx_path"}
elif restart_mode:
    allowed_keys |= {"artifact_created_at_utc", "restart", "run_id", "rust_restart"}
elif partition_mode:
    allowed_keys |= {"artifact_created_at_utc", "observations", "proof", "run_id"}
req(set(data) == allowed_keys, f"report top-level keys mismatch: {sorted(data)}")
artifact_root_arg = data.get("artifact_root"); artifact_root = checked_path("artifact_root", artifact_root_arg)
legacy_schema = data.get("legacy_schema_compatibility")
req(isinstance(legacy_schema, dict) and legacy_schema.get("authoritative") is False and "verdict" not in legacy_schema and nonempty_str(legacy_schema.get("marker_path")), "legacy_schema_compatibility missing marker_path")
if restart_mode:
    req(legacy_schema.get("purpose") == "schema-valid legacy artifact only; not the Rust restart report verdict", "legacy_schema_compatibility restart purpose mismatch")
    req(legacy_schema.get("reason") == "existing mixed_client_evidence_v1 PASS requires tx_path; Rust restart PASS lives in this report", "legacy_schema_compatibility restart reason mismatch")
marker_path = checked_path("legacy_schema_compatibility.marker_path", legacy_schema.get("marker_path"))
try: marker_path.relative_to(artifact_root)
except ValueError: fail("legacy marker is outside artifact_root")
marker = load_json_file("legacy marker", marker_path)
req(isinstance(marker, dict) and marker.get("scenario") == "mixed_client_mesh_schema_marker" and marker.get("evidence_type") == "mixed_client_process_soak", "legacy marker has wrong schema marker shape")
if tx_mode:
    req(set(marker) == {"evidence_type", "participants", "scenario", "schema_version", "tx_path", "verdict"}, f"legacy marker keys mismatch: {sorted(marker)}")
    req(marker.get("verdict") == "PASS" and marker.get("tx_path") == data.get("tx_path"), "legacy marker is not bound to tx_path PASS")
else:
    req(marker.get("verdict") == "FAIL", "legacy marker has wrong non-authoritative FAIL shape")
    if restart_mode:
        req(marker.get("restart") == data.get("restart"), "legacy marker restart object is not bound to report restart object")
try: validator = subprocess.run([sys.executable, sys.argv[2], str(marker_path)], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
except (OSError, subprocess.TimeoutExpired) as exc: fail(f"legacy marker schema validation failed: {exc}")
validator_detail_lines = (validator.stderr or validator.stdout).strip().splitlines()
req(validator.returncode == 0, "legacy marker schema validation failed: " + (" ".join(validator_detail_lines[:3]) if validator_detail_lines else "validator returned nonzero"))
nodes = data.get("nodes")
req(isinstance(nodes, list) and len(nodes) == 2 and all(isinstance(n, dict) for n in nodes), "PASS report requires exactly two node records")
expected = {"go": ("node-go", "rubin-node-go"), "rust": ("node-rust", "rubin-node-rust")}
expected_node_keys = {"binary", "command", "command_argv", "implementation", "name", "p2p_endpoint", "p2p_endpoint_process_backed", "pid", "process_alive", "process_comm", "rpc_endpoint", "rpc_endpoint_process_backed", "started_at"}
for node in nodes:
    impl, name = node.get("implementation"), node.get("name")
    req(isinstance(impl, str) and impl in expected, f"node has invalid implementation: {impl!r}")
    req(set(node) == expected_node_keys, f"{impl} node keys mismatch: {sorted(node)}")
    expected_name, expected_bin = expected[impl]
    req(name == expected_name, f"{impl} node has invalid name: {name!r}")
    command, binary, command_argv = node.get("command"), node.get("binary"), node.get("command_argv")
    binary_path = checked_path(f"{name}.binary", binary)
    try: binary_path.relative_to(artifact_root)
    except ValueError: fail(f"{name} binary is outside artifact_root")
    req(node.get("process_comm") == expected_bin, f"{name} process_comm does not prove {impl} identity")
    req(nonempty_str(command) and isinstance(command_argv, list) and all(isinstance(arg, str) for arg in command_argv) and command_argv and checked_path(f"{name}.command_argv[0]", command_argv[0]) == binary_path and binary_path.name == expected_bin and binary_path.is_file() and os.access(binary_path, os.X_OK), f"{name} command/binary is not bound to executable {expected_bin}")
    req(ep(node.get("rpc_endpoint")) and ep(node.get("p2p_endpoint")) and ts(node.get("started_at")), f"{name} has malformed endpoint or timestamp")
    req(isinstance(node.get("pid"), int) and not isinstance(node.get("pid"), bool) and node["pid"] > 0, f"{name} pid is not a positive integer")
    if live:
        eventually(lambda node=node, binary_path=binary_path, command_argv=command_argv: checked_path(f"{name}.live_exe", pid_exe(node["pid"])) == binary_path and argv_eq(pid_argv(node["pid"]), command_argv), f"{name} live process argv/executable does not match report")
        eventually(lambda node=node: owns_listen(node["pid"], node["rpc_endpoint"]) and owns_listen(node["pid"], node["p2p_endpoint"]), f"{name} live listeners are not pid-owned")
    for field in ("process_alive", "rpc_endpoint_process_backed", "p2p_endpoint_process_backed"):
        req(node.get(field) is True, f"{name} does not prove {field}")
req((impls := {n["implementation"] for n in nodes}) == {"go", "rust"}, f"PASS report requires one go and one rust node, got {sorted(impls)}")
nodes_by_impl = {node["implementation"]: node for node in nodes}
rust_expected_peer = nodes_by_impl["go"]["p2p_endpoint"]
if partition_mode:
    proof_for_argv = data.get("proof")
    req(isinstance(proof_for_argv, dict) and ep(proof_for_argv.get("partition_proxy_endpoint")), "partition proxy endpoint is malformed")
    rust_expected_peer = proof_for_argv["partition_proxy_endpoint"]
req(report_node_argv_eq(nodes_by_impl["go"], "node-go", []) and report_node_argv_eq(nodes_by_impl["rust"], "node-rust", ["--peer", rust_expected_peer]), "node command_argv does not match exact launched argv")
req(nodes_by_impl["go"]["pid"] != nodes_by_impl["rust"]["pid"], "go/rust process evidence uses the same pid")
req(nodes_by_impl["go"]["binary"] != nodes_by_impl["rust"]["binary"] and nodes_by_impl["go"]["command"] != nodes_by_impl["rust"]["command"] and nodes_by_impl["go"].get("command_argv") != nodes_by_impl["rust"].get("command_argv"), "go/rust process evidence is not implementation-distinct")
req(len({nodes_by_impl[i][f] for i in ("go", "rust") for f in ("rpc_endpoint", "p2p_endpoint")}) == 4, "node rpc/p2p endpoints are not pairwise distinct")
if restart_mode:
    req(nonempty_str(data.get("run_id")), "restart report run_id missing")
    req(data.get("run_id") == artifact_root.name, "restart report run_id mismatch")
    req(ts(data.get("artifact_created_at_utc")), "restart report artifact_created_at_utc invalid")
    restart = exact_object(data.get("restart"), {"catch_up_height", "pre_restart_height", "stopped_node"}, "restart")
    req(restart.get("stopped_node") == "node-rust", "restart.stopped_node must be node-rust")
    req(isinstance(restart.get("pre_restart_height"), int) and not isinstance(restart.get("pre_restart_height"), bool), "restart.pre_restart_height is not an integer")
    req(isinstance(restart.get("catch_up_height"), int) and not isinstance(restart.get("catch_up_height"), bool), "restart.catch_up_height is not an integer")
    req(restart["catch_up_height"] >= restart["pre_restart_height"], "restart.catch_up_height below pre_restart_height")
    restart_info = exact_object(data.get("rust_restart"), {"catch_up_has_tip", "catch_up_height", "catch_up_tip", "catch_up_tip_path", "datadir", "go_target_has_tip", "go_target_height", "go_target_mine_next_path", "go_target_tip", "go_target_tip_path", "go_target_tx_count", "new_command_argv", "new_p2p_endpoint", "new_pid", "new_rpc_endpoint", "new_started_at", "old_command_argv", "old_p2p_endpoint", "old_pid", "old_pid_stopped", "old_rpc_endpoint", "old_started_at", "peer_reconnect_observed", "pre_restart_has_tip", "pre_restart_height", "pre_restart_tip", "pre_restart_tip_path", "same_datadir"}, "rust_restart")
    old_pid = restart_info.get("old_pid")
    new_pid = restart_info.get("new_pid")
    req(isinstance(old_pid, int) and not isinstance(old_pid, bool) and old_pid > 0, "rust_restart.old_pid is not a positive integer")
    req(isinstance(new_pid, int) and not isinstance(new_pid, bool) and new_pid > 0, "rust_restart.new_pid is not a positive integer")
    req(old_pid != new_pid, "rust_restart reused the stopped pid")
    req(new_pid == nodes_by_impl["rust"]["pid"], "rust_restart.new_pid is not the final rust node pid")
    req(old_pid not in {nodes_by_impl["go"]["pid"], nodes_by_impl["rust"]["pid"]}, "rust_restart.old_pid aliases a final live node pid")
    req(ep(restart_info.get("old_rpc_endpoint")) and ep(restart_info.get("old_p2p_endpoint")), "rust_restart old endpoints are malformed")
    req(restart_info.get("new_rpc_endpoint") == nodes_by_impl["rust"]["rpc_endpoint"] and restart_info.get("new_p2p_endpoint") == nodes_by_impl["rust"]["p2p_endpoint"], "rust_restart new endpoints are not bound to final rust node")
    req(ts(restart_info.get("old_started_at")) and restart_info.get("new_started_at") == nodes_by_impl["rust"]["started_at"], "rust_restart timestamps are not bound to old/new processes")
    req(restart_info.get("old_pid_stopped") is True, "rust_restart does not prove old process stopped")
    req(restart_info.get("peer_reconnect_observed") is True, "rust_restart peer reconnect was not observed")
    req(restart_info.get("same_datadir") is True, "rust_restart does not prove same datadir restart")
    datadir_raw = restart_info.get("datadir")
    root_datadir = artifact_root / "node-rust"
    try:
        datadir_path = Path(datadir_raw).resolve() if isinstance(datadir_raw, str) and Path(datadir_raw).is_absolute() else None
    except (OSError, ValueError):
        datadir_path = None
    req(isinstance(datadir_raw, str) and Path(datadir_raw).name == "node-rust" and datadir_path == root_datadir and root_datadir.is_dir() and not root_datadir.is_symlink(), "rust_restart datadir is not bound to artifact root")
    pre_restart_height = json_int(restart_info.get("pre_restart_height"), "rust_restart.pre_restart_height")
    req(pre_restart_height == restart["pre_restart_height"], "rust_restart pre_restart_height mismatch")
    go_target_height = json_int(restart_info.get("go_target_height"), "rust_restart.go_target_height")
    catch_up_height = json_int(restart_info.get("catch_up_height"), "rust_restart.catch_up_height")
    req(catch_up_height == restart["catch_up_height"], "rust_restart catch_up_height mismatch")
    req(isinstance(restart_info.get("pre_restart_has_tip"), bool) and isinstance(restart_info.get("go_target_has_tip"), bool) and isinstance(restart_info.get("catch_up_has_tip"), bool), "rust_restart tip flags are not booleans")
    req(restart_info.get("pre_restart_has_tip") is True, "rust_restart pre-restart tip is not proven")
    req(restart_info.get("go_target_has_tip") is True, "rust_restart go target tip is not proven")
    req(restart_info.get("catch_up_has_tip") is True, "rust_restart catch-up tip is not proven")
    req((restart_info.get("pre_restart_tip") is None or (isinstance(restart_info.get("pre_restart_tip"), str) and re.fullmatch(r"[0-9a-f]{64}", restart_info.get("pre_restart_tip")))), "rust_restart.pre_restart_tip is malformed")
    req((restart_info.get("go_target_tip") is None or (isinstance(restart_info.get("go_target_tip"), str) and re.fullmatch(r"[0-9a-f]{64}", restart_info.get("go_target_tip")))), "rust_restart.go_target_tip is malformed")
    req((restart_info.get("catch_up_tip") is None or (isinstance(restart_info.get("catch_up_tip"), str) and re.fullmatch(r"[0-9a-f]{64}", restart_info.get("catch_up_tip")))), "rust_restart.catch_up_tip is malformed")
    req((restart_info["pre_restart_has_tip"] and restart_info.get("pre_restart_tip") is not None) or (not restart_info["pre_restart_has_tip"] and restart_info.get("pre_restart_tip") is None), "rust_restart.pre_restart_tip does not match pre_restart_has_tip")
    req((restart_info["go_target_has_tip"] and restart_info.get("go_target_tip") is not None) or (not restart_info["go_target_has_tip"] and restart_info.get("go_target_tip") is None), "rust_restart.go_target_tip does not match go_target_has_tip")
    req((restart_info["catch_up_has_tip"] and restart_info.get("catch_up_tip") is not None) or (not restart_info["catch_up_has_tip"] and restart_info.get("catch_up_tip") is None), "rust_restart.catch_up_tip does not match catch_up_has_tip")
    req(go_target_height > pre_restart_height, "rust_restart go target did not advance beyond pre-restart tip")
    req(catch_up_height == go_target_height, "rust_restart catch-up height does not match go target")
    req(restart_info.get("catch_up_tip") == restart_info.get("go_target_tip"), "rust_restart catch-up tip does not match go target")
    req(isinstance(restart_info.get("go_target_tx_count"), int) and not isinstance(restart_info.get("go_target_tx_count"), bool) and restart_info["go_target_tx_count"] >= 1, "rust_restart.go_target_tx_count is malformed")
    def restart_tip_sidecar(path_field, impl, endpoint, height, tip):
        sidecar_path = artifact_file(f"rust_restart.{path_field}", restart_info.get(path_field), artifact_root)
        sidecar = load_json_file(f"rust_restart.{path_field}", sidecar_path)
        req(set(sidecar) == {"best_known_height", "has_tip", "height", "implementation", "in_ibd", "request_path", "rpc_endpoint", "tip_hash"}, f"rust_restart.{path_field} keys mismatch: {sorted(sidecar)}")
        sidecar_height = json_int(sidecar.get("height"), f"rust_restart.{path_field}.height", 0)
        sidecar_best_known_height = json_int(sidecar.get("best_known_height"), f"rust_restart.{path_field}.best_known_height", 0)
        sidecar_has_tip = json_bool(sidecar.get("has_tip"), f"rust_restart.{path_field}.has_tip")
        json_bool(sidecar.get("in_ibd"), f"rust_restart.{path_field}.in_ibd")
        sidecar_tip = json_hex32(sidecar.get("tip_hash"), f"rust_restart.{path_field}.tip_hash")
        req(sidecar_best_known_height >= sidecar_height, f"rust_restart.{path_field}.best_known_height below height")
        req(sidecar.get("implementation") == impl and sidecar.get("rpc_endpoint") == endpoint and sidecar.get("request_path") == "/get_tip", f"rust_restart.{path_field} identity mismatch")
        req(sidecar_has_tip is True and sidecar_height == height and sidecar_tip == tip, f"rust_restart.{path_field} does not match report")
    restart_tip_sidecar("pre_restart_tip_path", "rust", restart_info["old_rpc_endpoint"], pre_restart_height, restart_info["pre_restart_tip"])
    restart_tip_sidecar("go_target_tip_path", "go", nodes_by_impl["go"]["rpc_endpoint"], go_target_height, restart_info["go_target_tip"])
    restart_tip_sidecar("catch_up_tip_path", "rust", nodes_by_impl["rust"]["rpc_endpoint"], catch_up_height, restart_info["catch_up_tip"])
    mine_next_path = artifact_file("rust_restart.go_target_mine_next_path", restart_info.get("go_target_mine_next_path"), artifact_root)
    mine_next = load_json_file("rust_restart.go_target_mine_next_path", mine_next_path)
    req(set(mine_next) == {"block_hash", "height", "implementation", "mined", "nonce", "request_path", "rpc_endpoint", "timestamp", "tx_count"}, f"rust_restart.go_target_mine_next_path keys mismatch: {sorted(mine_next)}")
    mine_height = json_int(mine_next.get("height"), "rust_restart.go_target_mine_next_path.height", 0)
    mine_hash = json_hex32(mine_next.get("block_hash"), "rust_restart.go_target_mine_next_path.block_hash")
    mine_tx_count = json_int(mine_next.get("tx_count"), "rust_restart.go_target_mine_next_path.tx_count", 1)
    json_int(mine_next.get("nonce"), "rust_restart.go_target_mine_next_path.nonce", 0)
    json_int(mine_next.get("timestamp"), "rust_restart.go_target_mine_next_path.timestamp", 0)
    req(mine_next.get("implementation") == "go" and mine_next.get("rpc_endpoint") == nodes_by_impl["go"]["rpc_endpoint"] and mine_next.get("request_path") == "/mine_next", "rust_restart go target mine_next sidecar identity mismatch")
    req(mine_next.get("mined") is True and mine_height == go_target_height and mine_hash == restart_info["go_target_tip"] and mine_tx_count == restart_info["go_target_tx_count"], "rust_restart go target mine_next sidecar does not match report")
    expected_old_rust_argv = [nodes_by_impl["rust"]["binary"], "--network", "devnet", "--datadir", str(artifact_root / "node-rust"), "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0", "--peer", nodes_by_impl["go"]["p2p_endpoint"]]
    old_argv = restart_info.get("old_command_argv")
    new_argv = restart_info.get("new_command_argv")
    req(isinstance(old_argv, list) and all(isinstance(arg, str) for arg in old_argv) and argv_eq(old_argv, expected_old_rust_argv, "rust_restart.old_command_argv", "expected old rust argv"), "rust_restart old argv mismatch")
    req(isinstance(new_argv, list) and new_argv == nodes_by_impl["rust"]["command_argv"], "rust_restart new argv mismatch")
if partition_mode:
    req(nonempty_str(data.get("run_id")), "partition report run_id missing")
    req(data.get("run_id") == artifact_root.name, "partition report run_id mismatch")
    req(ts(data.get("artifact_created_at_utc")), "partition report artifact_created_at_utc invalid")
    proof = exact_object(data.get("proof"), {"final_go_tip", "final_rust_tip", "fork_diverged", "go_partition_tip", "go_reorg_metrics", "heal_go_peer_addr", "heal_restored_peer_state", "partition_changed_peer_state", "partition_proxy_endpoint", "partition_proxy_pid", "pre_partition_go_peer_addr", "process_identity_rechecked_after_heal", "reorg_converged", "rust_winning_tip"}, "proof")
    req(all(proof.get(key) is True for key in ("partition_changed_peer_state", "fork_diverged", "heal_restored_peer_state", "reorg_converged", "process_identity_rechecked_after_heal")), "partition proof booleans are not all true")
    req(ep(proof.get("partition_proxy_endpoint")) and ep(proof.get("pre_partition_go_peer_addr")) and ep(proof.get("heal_go_peer_addr")), "partition proxy endpoints are malformed")
    req(isinstance(proof.get("partition_proxy_pid"), int) and not isinstance(proof.get("partition_proxy_pid"), bool) and proof["partition_proxy_pid"] > 0, "partition proxy pid is malformed")
    metrics = exact_object(proof.get("go_reorg_metrics"), {"rubin_node_last_reorg_depth", "rubin_node_reorg_total"}, "proof.go_reorg_metrics")
    req(json_int(metrics.get("rubin_node_reorg_total"), "proof.go_reorg_metrics.rubin_node_reorg_total", 1) >= 1 and json_int(metrics.get("rubin_node_last_reorg_depth"), "proof.go_reorg_metrics.rubin_node_last_reorg_depth", 1) >= 1, "partition go reorg metrics do not prove reorg")
    go_fork, rust_win = tip_obj(proof.get("go_partition_tip"), "proof.go_partition_tip"), tip_obj(proof.get("rust_winning_tip"), "proof.rust_winning_tip")
    final_go, final_rust = tip_obj(proof.get("final_go_tip"), "proof.final_go_tip"), tip_obj(proof.get("final_rust_tip"), "proof.final_rust_tip")
    req(go_fork["hash"] != rust_win["hash"] and rust_win["height"] > go_fork["height"], "partition fork tips do not prove Rust winning branch")
    req(final_go == rust_win and final_rust == rust_win, "partition final tips are not the Rust winning tip")
    connectivity = exact_object(data.get("peer_connectivity"), {"bidirectional_observed", "counterpart_links", "go_peer_snapshot", "go_to_rust", "rust_peer_snapshot", "rust_to_go"}, "peer_connectivity")
    req(connectivity.get("go_to_rust") is False and connectivity.get("rust_to_go") is False and connectivity.get("bidirectional_observed") is False, "partition peer_connectivity overclaims direct link")
    links = exact_object(connectivity.get("counterpart_links"), {"go_peer_snapshot_expected_addr", "rust_outbound_local_addr", "rust_outbound_pid", "rust_outbound_remote_addr", "rust_peer_snapshot_expected_addr"}, "peer_connectivity.counterpart_links")
    req(all(links.get(key) is None for key in links), "partition peer_connectivity counterpart links must be null")
    for field in ("go_peer_snapshot", "rust_peer_snapshot"):
        snapshot = exact_object(connectivity.get(field), {"count", "peers"}, f"peer_connectivity.{field}")
        req(snapshot.get("count") == 0 and snapshot.get("peers") == [], f"partition peer_connectivity.{field} must be empty")
    obs = exact_object(data.get("observations"), {"fork", "heal", "partition", "pre_partition", "reorg"}, "observations")
    obs_keys = {
        "pre_partition": {"common_go_block", "common_go_mine", "common_rust_block", "common_rust_tip", "go_peer_snapshot", "rust_peer_snapshot"},
        "partition": {"go_peer_snapshot", "rust_peer_snapshot"},
        "fork": {"go_block", "go_mine", "go_peer_snapshot", "go_tip", "rust_block_1", "rust_block_2", "rust_mine_1", "rust_mine_2", "rust_peer_snapshot", "rust_tip"},
        "heal": {"go_peer_snapshot", "rust_peer_snapshot"},
        "reorg": {"go_reorg_parent_block", "go_tip", "go_tip_block", "rust_tip", "rust_tip_block"},
    }
    obs_paths = {}
    for group, keys in obs_keys.items():
        group_obj = exact_object(obs.get(group), keys, f"observations.{group}")
        for key in keys:
            obs_paths[f"{group}.{key}"] = artifact_file(f"observations.{group}.{key}", group_obj.get(key), artifact_root)
    req(len(set(obs_paths.values())) == len(obs_paths), "partition observation sidecar paths are not pairwise distinct")
    peer_snapshot("observations.pre_partition.rust_peer_snapshot", obs_paths["pre_partition.rust_peer_snapshot"], proof["partition_proxy_endpoint"], True)
    peer_snapshot("observations.pre_partition.go_peer_snapshot", obs_paths["pre_partition.go_peer_snapshot"], proof["pre_partition_go_peer_addr"], True)
    peer_snapshot("observations.partition.rust_peer_snapshot", obs_paths["partition.rust_peer_snapshot"], None, False)
    peer_snapshot("observations.partition.go_peer_snapshot", obs_paths["partition.go_peer_snapshot"], None, False)
    peer_snapshot("observations.fork.rust_peer_snapshot", obs_paths["fork.rust_peer_snapshot"], None, False)
    peer_snapshot("observations.fork.go_peer_snapshot", obs_paths["fork.go_peer_snapshot"], None, False)
    peer_snapshot("observations.heal.rust_peer_snapshot", obs_paths["heal.rust_peer_snapshot"], proof["partition_proxy_endpoint"], True)
    peer_snapshot("observations.heal.go_peer_snapshot", obs_paths["heal.go_peer_snapshot"], proof["heal_go_peer_addr"], True)
    common_mine = mine_sidecar("observations.pre_partition.common_go_mine", obs_paths["pre_partition.common_go_mine"], "go", nodes_by_impl["go"]["rpc_endpoint"])
    req(common_mine.get("height") == go_fork["height"] - 1, "pre-partition common mine height is not the fork parent")
    block_sidecar("observations.pre_partition.common_go_block", obs_paths["pre_partition.common_go_block"], "go", nodes_by_impl["go"]["rpc_endpoint"], common_mine["height"], common_mine["block_hash"])
    tip_sidecar("observations.pre_partition.common_rust_tip", obs_paths["pre_partition.common_rust_tip"], "rust", nodes_by_impl["rust"]["rpc_endpoint"], common_mine["height"], common_mine["block_hash"])
    block_sidecar("observations.pre_partition.common_rust_block", obs_paths["pre_partition.common_rust_block"], "rust", nodes_by_impl["rust"]["rpc_endpoint"], common_mine["height"], common_mine["block_hash"])
    go_mine = mine_sidecar("observations.fork.go_mine", obs_paths["fork.go_mine"], "go", nodes_by_impl["go"]["rpc_endpoint"])
    req(go_mine.get("height") == go_fork["height"] and go_mine.get("block_hash") == go_fork["hash"], "go fork mine sidecar mismatch")
    tip_sidecar("observations.fork.go_tip", obs_paths["fork.go_tip"], "go", nodes_by_impl["go"]["rpc_endpoint"], go_fork["height"], go_fork["hash"])
    block_sidecar("observations.fork.go_block", obs_paths["fork.go_block"], "go", nodes_by_impl["go"]["rpc_endpoint"], go_fork["height"], go_fork["hash"])
    mine1 = mine_sidecar("observations.fork.rust_mine_1", obs_paths["fork.rust_mine_1"], "rust", nodes_by_impl["rust"]["rpc_endpoint"])
    req(mine1.get("height") == go_fork["height"], "rust fork first mine height is not parallel to go fork")
    block_sidecar("observations.fork.rust_block_1", obs_paths["fork.rust_block_1"], "rust", nodes_by_impl["rust"]["rpc_endpoint"], mine1["height"], mine1["block_hash"])
    mine2 = mine_sidecar("observations.fork.rust_mine_2", obs_paths["fork.rust_mine_2"], "rust", nodes_by_impl["rust"]["rpc_endpoint"])
    req(mine2.get("height") == rust_win["height"] and mine2.get("block_hash") == rust_win["hash"], "rust winning mine sidecar mismatch")
    tip_sidecar("observations.fork.rust_tip", obs_paths["fork.rust_tip"], "rust", nodes_by_impl["rust"]["rpc_endpoint"], rust_win["height"], rust_win["hash"])
    block_sidecar("observations.fork.rust_block_2", obs_paths["fork.rust_block_2"], "rust", nodes_by_impl["rust"]["rpc_endpoint"], rust_win["height"], rust_win["hash"])
    tip_sidecar("observations.reorg.go_tip", obs_paths["reorg.go_tip"], "go", nodes_by_impl["go"]["rpc_endpoint"], final_go["height"], final_go["hash"])
    tip_sidecar("observations.reorg.rust_tip", obs_paths["reorg.rust_tip"], "rust", nodes_by_impl["rust"]["rpc_endpoint"], final_rust["height"], final_rust["hash"])
    block_sidecar("observations.reorg.go_reorg_parent_block", obs_paths["reorg.go_reorg_parent_block"], "go", nodes_by_impl["go"]["rpc_endpoint"], mine1["height"], mine1["block_hash"])
    block_sidecar("observations.reorg.go_tip_block", obs_paths["reorg.go_tip_block"], "go", nodes_by_impl["go"]["rpc_endpoint"], final_go["height"], final_go["hash"])
    block_sidecar("observations.reorg.rust_tip_block", obs_paths["reorg.rust_tip_block"], "rust", nodes_by_impl["rust"]["rpc_endpoint"], final_rust["height"], final_rust["hash"])
    final = data.get("final_verification")
    req(isinstance(final, dict) and final.get("producer_side") is True and final.get("process_identity_rechecked") is True and final.get("peer_snapshots_rechecked") is True, "partition final verification is incomplete")
if tx_mode:
    req(sorted((p.get("name"), p.get("implementation"), p.get("endpoint"), p.get("started_at")) for p in marker.get("participants", []) if isinstance(p, dict)) == sorted((n["name"], n["implementation"], n["rpc_endpoint"], n["started_at"]) for n in nodes), "legacy marker participants are not bound to report nodes")
if tx_mode:
    tx_path = exact_object(data.get("tx_path"), {"submitted_at", "observed_at", "tx_id"}, "tx_path")
    txid = tx_path.get("tx_id")
    if go_submit_mode:
        req(tx_path == {"submitted_at": "node-go", "observed_at": ["node-rust"], "tx_id": txid}, "tx_path identity mismatch")
        submit_label, accept_label = "go_submit", "rust_accept"
        submit_impl, accept_impl = "go", "rust"
        submit_obj = exact_object(data.get("go_submit"), {"get_tx_path", "rpc_endpoint", "tx_hex", "tx_status_path", "txid"}, "go_submit")
        accept_obj = exact_object(data.get("rust_accept"), {"get_tx_path", "raw_hex", "rpc_endpoint", "tx_status_path", "txid"}, "rust_accept")
    else:
        req(tx_path == {"submitted_at": "node-rust", "observed_at": ["node-go"], "tx_id": txid}, "tx_path identity mismatch")
        submit_label, accept_label = "rust_submit", "go_accept"
        submit_impl, accept_impl = "rust", "go"
        submit_obj = exact_object(data.get("rust_submit"), {"get_tx_path", "rpc_endpoint", "tx_hex", "tx_status_path", "txid"}, "rust_submit")
        accept_obj = exact_object(data.get("go_accept"), {"get_tx_path", "raw_hex", "rpc_endpoint", "tx_status_path", "txid"}, "go_accept")
    req(isinstance(txid, str) and re.fullmatch(r"[0-9a-f]{64}", txid), "txid is malformed")
    txhex = submit_obj.get("tx_hex")
    req(isinstance(txhex, str) and 2 <= len(txhex) <= MAX_TX_HEX_CHARS and len(txhex) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", txhex), "tx_hex is malformed or unbounded")
    req(parse_txid_from_hex(txhex) == txid, "tx_hex txid mismatch")
    req(submit_obj.get("txid") == txid and accept_obj.get("txid") == txid, "tx report txid mismatch")
    req(accept_obj.get("raw_hex") == txhex, "tx report raw transaction mismatch")
    req(submit_obj.get("rpc_endpoint") == nodes_by_impl[submit_impl]["rpc_endpoint"] and accept_obj.get("rpc_endpoint") == nodes_by_impl[accept_impl]["rpc_endpoint"], "tx report rpc endpoint mismatch")
    submit_status = artifact_file(f"{submit_label}.tx_status_path", submit_obj.get("tx_status_path"), artifact_root)
    submit_get = artifact_file(f"{submit_label}.get_tx_path", submit_obj.get("get_tx_path"), artifact_root)
    accept_status = artifact_file(f"{accept_label}.tx_status_path", accept_obj.get("tx_status_path"), artifact_root)
    accept_get = artifact_file(f"{accept_label}.get_tx_path", accept_obj.get("get_tx_path"), artifact_root)
    req(len({submit_status, submit_get, accept_status, accept_get}) == 4, "tx sidecar paths are not pairwise distinct")
    tx_sidecars(load_json_file(f"{submit_label}.tx_status", submit_status), load_json_file(f"{submit_label}.get_tx", submit_get), txid, txhex, submit_label, submit_impl, nodes_by_impl[submit_impl]["rpc_endpoint"], f"/tx_status?txid={txid}", f"/get_tx?txid={txid}")
    tx_sidecars(load_json_file(f"{accept_label}.tx_status", accept_status), load_json_file(f"{accept_label}.get_tx", accept_get), txid, txhex, accept_label, accept_impl, nodes_by_impl[accept_impl]["rpc_endpoint"], f"/tx_status?txid={txid}", f"/get_tx?txid={txid}")
    if live and not converge_mode:
        tx_sidecars(tx_rpc(nodes_by_impl[submit_impl]["rpc_endpoint"], f"/tx_status?txid={txid}", f"{submit_label}.tx_status", submit_impl), tx_rpc(nodes_by_impl[submit_impl]["rpc_endpoint"], f"/get_tx?txid={txid}", f"{submit_label}.get_tx", submit_impl), txid, txhex, f"{submit_label}.live", submit_impl, nodes_by_impl[submit_impl]["rpc_endpoint"], f"/tx_status?txid={txid}", f"/get_tx?txid={txid}")
        tx_sidecars(tx_rpc(nodes_by_impl[accept_impl]["rpc_endpoint"], f"/tx_status?txid={txid}", f"{accept_label}.tx_status", accept_impl), tx_rpc(nodes_by_impl[accept_impl]["rpc_endpoint"], f"/get_tx?txid={txid}", f"{accept_label}.get_tx", accept_impl), txid, txhex, f"{accept_label}.live", accept_impl, nodes_by_impl[accept_impl]["rpc_endpoint"], f"/tx_status?txid={txid}", f"/get_tx?txid={txid}")
    if converge_mode:
        mine_label, converge_label = ("rust_mine", "go_converge") if go_submit_mode else ("go_mine", "rust_converge")
        mine_impl, converge_impl = ("rust", "go") if go_submit_mode else ("go", "rust")
        mine_node, converge_node = ("node-rust", "node-go") if go_submit_mode else ("node-go", "node-rust")
        mine = exact_object(data.get(mine_label), {"block_hash", "block_path", "class", "height", "mine_next_path", "mined_by", "raw_hex", "rpc_endpoint", "tx_count", "txid"}, mine_label)
        converge = exact_object(data.get(converge_label), {"block_hash", "block_path", "class", "converged_at", "height", "raw_hex", "rpc_endpoint", "tip_path", "txid"}, converge_label)
        req(mine.get("class") == "mined_included" and mine.get("mined_by") == mine_node, f"{mine_label} is not {mine_node} mined_included")
        req(converge.get("class") == "canonical_block_found" and converge.get("converged_at") == converge_node, f"{converge_label} is not {converge_node} canonical_block_found")
        req(mine.get("txid") == txid and converge.get("txid") == txid and mine.get("raw_hex") == txhex and converge.get("raw_hex") == txhex, "mined/converged tx identity differs from submitted tx")
        req(mine.get("rpc_endpoint") == nodes_by_impl[mine_impl]["rpc_endpoint"] and converge.get("rpc_endpoint") == nodes_by_impl[converge_impl]["rpc_endpoint"], "mined/converged RPC endpoints are not bound to expected nodes")
        height, block_hash = mine.get("height"), mine.get("block_hash")
        req(isinstance(height, int) and not isinstance(height, bool) and height >= 1, f"{mine_label}.height is malformed")
        req(isinstance(block_hash, str) and re.fullmatch(r"[0-9a-f]{64}", block_hash), f"{mine_label}.block_hash is malformed")
        req(isinstance(mine.get("tx_count"), int) and not isinstance(mine.get("tx_count"), bool) and mine["tx_count"] >= 2, f"{mine_label}.tx_count does not prove coinbase plus submitted tx")
        req(converge.get("height") == height and converge.get("block_hash") == block_hash, f"{converge_label} does not match {mine_label} height/hash")
        mine_next_path = artifact_file(f"{mine_label}.mine_next_path", mine.get("mine_next_path"), artifact_root)
        mine_block_path = artifact_file(f"{mine_label}.block_path", mine.get("block_path"), artifact_root)
        converge_tip_path = artifact_file(f"{converge_label}.tip_path", converge.get("tip_path"), artifact_root)
        converge_block_path = artifact_file(f"{converge_label}.block_path", converge.get("block_path"), artifact_root)
        req(len({mine_next_path, mine_block_path, converge_tip_path, converge_block_path}) == 4, "converge sidecar paths are not pairwise distinct")
        mine_next = load_json_file(f"{mine_label}.mine_next", mine_next_path)
        req(set(mine_next) == {"block_hash", "height", "implementation", "mined", "nonce", "request_path", "rpc_endpoint", "timestamp", "tx_count"}, f"{mine_label}.mine_next keys mismatch: {sorted(mine_next)}")
        req(mine_next.get("implementation") == mine_impl and mine_next.get("rpc_endpoint") == nodes_by_impl[mine_impl]["rpc_endpoint"] and mine_next.get("request_path") == "/mine_next", f"{mine_label} mine_next sidecar identity mismatch")
        req(mine_next.get("mined") is True and mine_next.get("height") == height and mine_next.get("block_hash") == block_hash and mine_next.get("tx_count") == mine["tx_count"], f"{mine_label} mine_next sidecar does not match report")
        verify_block_inclusion_sidecar(f"{mine_label}.block_path", mine_block_path, txhex, txid, height, block_hash, mine["tx_count"], mine_impl, nodes_by_impl[mine_impl]["rpc_endpoint"], f"/get_block?height={height}")
        verify_block_inclusion_sidecar(f"{converge_label}.block_path", converge_block_path, txhex, txid, height, block_hash, mine["tx_count"], converge_impl, nodes_by_impl[converge_impl]["rpc_endpoint"], f"/get_block?height={height}")
        tip = load_json_file(f"{converge_label}.tip", converge_tip_path)
        req(set(tip) == {"best_known_height", "has_tip", "height", "implementation", "in_ibd", "request_path", "rpc_endpoint", "tip_hash"}, f"{converge_label}.tip keys mismatch: {sorted(tip)}")
        req(tip.get("implementation") == converge_impl and tip.get("rpc_endpoint") == nodes_by_impl[converge_impl]["rpc_endpoint"] and tip.get("request_path") == "/get_tip", f"{converge_label} tip sidecar identity mismatch")
        req(tip.get("has_tip") is True and tip.get("height") == height and tip.get("tip_hash") == block_hash, f"{converge_label} tip sidecar does not match {mine_label} block")
    validate_raw_samples(data, tx_mode, go_submit_mode, converge_mode, txid, block_hash if converge_mode else None, height if converge_mode else None)
else:
    validate_raw_samples(data, tx_mode, go_submit_mode, converge_mode)
if not partition_mode:
    connectivity = data.get("peer_connectivity")
    req(isinstance(connectivity, dict), "PASS report missing peer_connectivity object")
    req(all(connectivity.get(f) is True for f in ("go_to_rust", "rust_to_go", "bidirectional_observed")), "peer_connectivity booleans are not all true")
    req(isinstance(links := connectivity.get("counterpart_links"), dict), "PASS report missing counterpart_links")
    go_expected, rust_expected = links.get("go_peer_snapshot_expected_addr"), links.get("rust_peer_snapshot_expected_addr")
    req(all(ep(links.get(f)) for f in ("go_peer_snapshot_expected_addr", "rust_peer_snapshot_expected_addr", "rust_outbound_local_addr", "rust_outbound_remote_addr")), "counterpart link endpoint is malformed")
    req(rust_expected == nodes_by_impl["go"]["p2p_endpoint"] and links.get("rust_outbound_remote_addr") == rust_expected and links.get("rust_outbound_local_addr") == go_expected and links.get("rust_outbound_pid") == nodes_by_impl["rust"]["pid"], "peer evidence is not bound to expected counterpart endpoints")
    req(isinstance(go_expected, str) and go_expected not in {rust_expected, nodes_by_impl["rust"]["p2p_endpoint"], nodes_by_impl["go"]["rpc_endpoint"], nodes_by_impl["rust"]["rpc_endpoint"]}, "go peer evidence is not a rust outbound peer address")
    if live:
        eventually(lambda: f"{go_expected}->{rust_expected}" in lsof_lines(nodes_by_impl["rust"]["pid"], "ESTABLISHED"), "rust outbound TCP link is not live and rust-owned")
    final = data.get("final_verification")
    req(isinstance(final, dict) and all(final.get(f) is True for f in ("producer_side", "process_identity_rechecked", "rust_outbound_link_rechecked", "peer_snapshots_rechecked")), "PASS report missing producer-side final verification")
    req(final.get("rust_outbound_pid") == nodes_by_impl["rust"]["pid"] and final.get("rust_outbound_local_addr") == go_expected and final.get("rust_outbound_remote_addr") == rust_expected, "final verification is not bound to peer evidence")
    for field, expected_addr in (("go_peer_snapshot", go_expected), ("rust_peer_snapshot", rust_expected)):
        stored = snapshot_norm(connectivity.get(field), expected_addr)
        if live:
            endpoint = nodes_by_impl["go" if field.startswith("go_") else "rust"]["rpc_endpoint"]
            eventually(lambda endpoint=endpoint, stored=stored, expected_addr=expected_addr: (fresh := peers(endpoint)) is not None and stored == snapshot_norm(fresh, expected_addr, False), f"{field} differs from live exact peer set")
print(f"PASS: {scenario} report {'accepted' if live else 'structurally accepted'} {path}" + ("" if live else "; live proof not checked"))
PY
}
[[ "${MESH_TIMEOUT}" =~ ^[0-9]{1,3}$ ]] || { echo "MESH_TIMEOUT must be an integer in [1, 600]" >&2; exit 2; }; MESH_TIMEOUT="$((10#${MESH_TIMEOUT}))"; (( MESH_TIMEOUT >= 1 && MESH_TIMEOUT <= 600 )) || { echo "MESH_TIMEOUT must be an integer in [1, 600]" >&2; exit 2; }; export MESH_TIMEOUT
if [[ -n "${CHECK_REPORT_MODE}" ]]; then need_tool python3; [[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }; [[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }; CHECK_EXPECTED_MODE=public; (( RUST_RESTART_MODE == 1 )) && CHECK_EXPECTED_MODE=rust-restart; (( PARTITION_HEAL_REORG_MODE == 1 )) && CHECK_EXPECTED_MODE=partition-heal-reorg; check_report "${CHECK_REPORT}" "${CHECK_REPORT_MODE}" "${CHECK_EXPECTED_MODE}"; exit 0; fi
if (( TX_PATH_MODE >= 1 )); then validate_deterministic_tx_fee; fi
need_tool python3; [[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }; [[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init mixed-client-mesh
GO_NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"; RUST_NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-rust"
GO_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-go"; RUST_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-rust"
GO_LOG="node-go.log"; RUST_LOG="node-rust.log"; RUST_RESTART_LOG="node-rust-restart.log"; PARTITION_PROXY_LOG="partition-proxy.log"; REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mixed-client-mesh-report.json"; LEGACY_SCHEMA_MARKER_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mixed-client-mesh-legacy-schema-marker.json"
GO_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-peers.json"; RUST_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-peers.json"
RUST_PRE_RESTART_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-pre-restart-tip.json"; GO_RESTART_MINE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-restart-mine-next.json"; GO_RESTART_TARGET_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-restart-target-tip.json"; RUST_CATCH_UP_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-catch-up-tip.json"
GO_SUBMIT_STATUS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-tx-status.json"; GO_SUBMIT_GET_TX_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-get-tx.json"; RUST_STATUS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-tx-status.json"; RUST_GET_TX_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-get-tx.json"
RUST_SUBMIT_STATUS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-submit-tx-status.json"; RUST_SUBMIT_GET_TX_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-submit-get-tx.json"; GO_ACCEPT_STATUS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-accept-tx-status.json"; GO_ACCEPT_GET_TX_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-accept-get-tx.json"
RUST_MINE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-mine-next.json"; RUST_MINE_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-mined-block.json"; GO_CONVERGE_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-converge-tip.json"; GO_CONVERGE_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-converge-block.json"
GO_MINE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-mine-next.json"; GO_MINE_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-mined-block.json"; RUST_CONVERGE_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-converge-tip.json"; RUST_CONVERGE_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-converge-block.json"
TXGEN_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-txgen"; KEYGEN_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.go"; KEYGEN_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.json"; BLOCK_CHECK_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/block-check.go"; MINE_LOG="mine-go.log"
PARTITION_PROXY_SCRIPT="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-proxy.py"; PARTITION_PROXY_STATE="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-proxy.state"
PARTITION_PRE_GO_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-pre-go-peers.json"; PARTITION_PRE_RUST_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-pre-rust-peers.json"; PARTITION_COMMON_GO_MINE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-common-go-mine.json"; PARTITION_COMMON_GO_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-common-go-block.json"; PARTITION_COMMON_RUST_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-common-rust-tip.json"; PARTITION_COMMON_RUST_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-common-rust-block.json"
PARTITION_DROP_GO_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-drop-go-peers.json"; PARTITION_DROP_RUST_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-drop-rust-peers.json"; PARTITION_FORK_GO_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-fork-go-peers.json"; PARTITION_FORK_RUST_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-fork-rust-peers.json"; PARTITION_GO_MINE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-go-mine.json"; PARTITION_GO_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-go-tip.json"; PARTITION_GO_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-go-block.json"
PARTITION_RUST_MINE1_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-rust-mine-1.json"; PARTITION_RUST_MINE2_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-rust-mine-2.json"; PARTITION_RUST_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-rust-tip.json"; PARTITION_RUST_BLOCK1_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-rust-block-1.json"; PARTITION_RUST_BLOCK2_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-rust-block-2.json"; PARTITION_HEAL_GO_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-heal-go-peers.json"; PARTITION_HEAL_RUST_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-heal-rust-peers.json"
PARTITION_FINAL_GO_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-final-go-tip.json"; PARTITION_FINAL_RUST_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-final-rust-tip.json"; PARTITION_GO_REORG_PARENT_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-go-reorg-parent-block.json"; PARTITION_FINAL_GO_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-final-go-block.json"; PARTITION_FINAL_RUST_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-final-rust-block.json"
GO_PID="" RUST_PID="" GO_RPC_ADDR="" RUST_RPC_ADDR="" GO_P2P_ADDR="" RUST_P2P_ADDR="" GO_STARTED_AT_UTC="" RUST_STARTED_AT_UTC="" GO_COMM="" RUST_COMM="" RUST_TO_GO_LOCAL_ADDR="" GO_CMD="" RUST_CMD="" GO_ARGV_JSON="" RUST_ARGV_JSON="" FINAL_PROCESS_IDENTITY_RECHECKED="" FINAL_RUST_OUTBOUND_LINK_RECHECKED="" FINAL_PEER_SNAPSHOTS_RECHECKED="" PROCESS_IDENTITY_REASON="" START_REASON="" BUILD_REASON="" TX_REASON="" TX_ID="" TX_HEX="" TX_FROM_KEY_FILE="" TX_FROM_KEY_DIR="" TX_TO_KEY="" RUST_MINE_HEIGHT="" RUST_MINE_HASH="" RUST_MINE_TX_COUNT="" GO_MINE_HEIGHT="" GO_MINE_HASH="" GO_MINE_TX_COUNT="" PROPAGATION_SAMPLE_START_SECONDS="" PROPAGATION_SAMPLE_SECONDS="" CONVERGENCE_SAMPLE_SECONDS="" RUST_RESTART_REASON="" RUST_RESTART_TIP_TSV="" OLD_RUST_PID="" OLD_RUST_RPC_ADDR="" OLD_RUST_P2P_ADDR="" OLD_RUST_STARTED_AT_UTC="" OLD_RUST_ARGV_JSON="" PRE_RESTART_RUST_HEIGHT="" PRE_RESTART_RUST_TIP="" PRE_RESTART_RUST_HAS_TIP="" GO_RESTART_TARGET_HEIGHT="" GO_RESTART_TARGET_TIP="" GO_RESTART_TARGET_HAS_TIP="" GO_RESTART_TARGET_TX_COUNT="" POST_RESTART_RUST_HEIGHT="" POST_RESTART_RUST_TIP="" POST_RESTART_RUST_HAS_TIP="" OLD_RUST_PID_STOPPED="" RUST_RESTART_SAME_DATADIR="" RUST_RESTART_PEER_RECONNECTED="" PARTITION_PROXY_PID="" PARTITION_PROXY_ADDR="" PARTITION_PRE_GO_PEER_ADDR="" PARTITION_HEAL_GO_PEER_ADDR="" PARTITION_COMMON_HEIGHT="" PARTITION_COMMON_HASH="" PARTITION_GO_FORK_HEIGHT="" PARTITION_GO_FORK_HASH="" PARTITION_RUST_WIN_HEIGHT="" PARTITION_RUST_WIN_HASH="" PARTITION_FINAL_GO_HEIGHT="" PARTITION_FINAL_GO_HASH="" PARTITION_FINAL_RUST_HEIGHT="" PARTITION_FINAL_RUST_HASH="" PARTITION_REORG_TOTAL="" PARTITION_REORG_DEPTH="" PARTITION_REASON=""
mkdir -p -- "${GO_DIR}" "${RUST_DIR}"
run_fips_preflight_before_captured_dev_env() { [[ "${RUBIN_OPENSSL_FIPS_MODE:-off}" != "only" || "${RUBIN_OPENSSL_SKIP_FIPS_GUARD:-0}" == "1" ]] && return 0; echo "Running FIPS-only preflight before captured dev-env command streams" >&2; "${DEV_ENV}" -- "${REPO_ROOT}/scripts/crypto/openssl/fips-preflight.sh" >&2; }
bounded() { perl -e 'alarm shift @ARGV; exec @ARGV; die "exec failed: $!\n"' 5 "$@"; }
bounded_mesh() { perl -e 'alarm shift @ARGV; exec @ARGV; die "exec failed: $!\n"' "${MESH_TIMEOUT}" "$@"; }
argv_cmd() { local out="" arg q; for arg; do printf -v q "%q" "$arg"; out+="${out:+ }${q}"; done; printf '%s\n' "${out}"; }; argv_json() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@"; }
loopback_endpoint() { local endpoint="${1:-}" port; [[ "${endpoint}" =~ ^127[.]0[.]0[.]1:([0-9]{1,5})$ ]] || return 1; port="${BASH_REMATCH[1]}"; (( 10#${port} >= 1 && 10#${port} <= 65535 )); }
disable_xtrace_for_secret() { case "$-" in *x*) set +x; return 0 ;; *) return 1 ;; esac; }
restore_xtrace_after_secret() { [[ "${1:-0}" == "1" ]] && set -x; return 0; }
cleanup_tx_from_key_file() {
  local xtrace_was_enabled=0
  case "$-" in *x*) set +x; xtrace_was_enabled=1 ;; esac
  local secret_file="${TX_FROM_KEY_FILE:-}" secret_dir="${TX_FROM_KEY_DIR:-}" cleanup_status=0
  if [[ -n "${secret_file}" ]]; then rm -f -- "${secret_file}" || cleanup_status=$?; TX_FROM_KEY_FILE=""; fi
  if [[ -n "${secret_dir}" ]]; then rm -f -- "${secret_dir}/keygen-public.json" "${secret_dir}/from-key.hex" || cleanup_status=$?; rmdir -- "${secret_dir}" || cleanup_status=$?; TX_FROM_KEY_DIR=""; fi
  restore_xtrace_after_secret "${xtrace_was_enabled}"
  return "${cleanup_status}"
}
rubin_process_exit_trap_with_tx_secret_cleanup() {
  local status=$? cleanup_status=0
  cleanup_tx_from_key_file || cleanup_status=$?
  rubin_process_cleanup "${status}" || cleanup_status=$?
  [[ "${status}" != "0" ]] && exit "${status}"
  exit "${cleanup_status}"
}
trap rubin_process_exit_trap_with_tx_secret_cleanup EXIT
check_report_reason_token() {
  local msg
  msg="$(cat)"
  python3 - "${msg}" <<'PY'
import sys
msg = " ".join(x[5:].strip() for x in sys.argv[1].splitlines() if x.startswith("FAIL:"))
rules = [
    ("partition-heal-reorg validation requires", "partition_reorg_scenario_required"),
    ("public partition-heal-reorg check-report-live is unsupported", "public_partition_check_report_live_unsupported"),
    ("public partition-heal-reorg check-report is unsupported", "public_partition_check_report_unsupported"),
    ("partition report run_id missing", "partition_run_id_missing"),
    ("partition report run_id mismatch", "partition_run_id_mismatch"),
    ("partition report artifact_created_at_utc invalid", "partition_artifact_created_at_invalid"),
    ("partition proof booleans are not all true", "partition_proof_booleans_invalid"),
    ("partition proxy endpoints are malformed", "partition_proxy_endpoint_invalid"),
    ("partition proxy pid is malformed", "partition_proxy_pid_invalid"),
    ("partition fork tips do not prove Rust winning branch", "partition_fork_winner_invalid"),
    ("partition final tips are not the Rust winning tip", "partition_final_tip_not_winner"),
    ("partition final verification is incomplete", "partition_final_verification_invalid"),
    ("partition observation sidecar paths are not pairwise distinct", "partition_sidecar_paths_not_distinct"),
    ("pre-partition common mine height is not the fork parent", "partition_common_parent_invalid"),
    ("go fork mine sidecar mismatch", "partition_go_mine_sidecar_invalid"),
    ("rust fork first mine height is not parallel to go fork", "partition_rust_parallel_fork_invalid"),
    ("rust winning mine sidecar mismatch", "partition_rust_winning_mine_invalid"),
    ("sidecar identity mismatch", "partition_sidecar_identity_mismatch"),
    ("does not match expected tip", "partition_tip_sidecar_invalid"),
    ("does not match expected block", "partition_block_sidecar_invalid"),
    ("block payload checker unavailable", "partition_block_payload_checker_unavailable"),
    ("block payload check timeout", "partition_block_payload_check_timeout"),
    ("block payload check output too large", "partition_block_payload_check_output_too_large"),
    ("block payload checker malformed output", "partition_block_payload_checker_malformed"),
    ("block payload checker root is not an object", "partition_block_payload_checker_malformed"),
    ("block payload check failed", "partition_block_payload_invalid"),
    ("parsed block hash mismatch", "partition_block_hash_mismatch"),
    ("malformed mine result", "partition_mine_sidecar_invalid"),
    ("does not prove partitioned peer state", "partition_peer_state_not_changed"),
    ("does not prove expected connected peer", "partition_peer_state_not_restored"),
    ("partition go reorg metrics do not prove reorg", "partition_reorg_metrics_invalid"),
    ("report top-level keys mismatch", "report_top_level_keys_mismatch"),
    ("rust restart validation requires", "rust_restart_scenario_required"),
    ("rust_restart reused the stopped pid", "rust_restart_same_pid"),
    ("rust_restart.old_pid aliases", "rust_restart_old_pid_aliases_final_node"),
    ("rust_restart does not prove old process stopped", "rust_restart_old_process_not_stopped"),
    ("rust_restart peer reconnect was not observed", "rust_restart_peer_reconnect_missing"),
    ("rust_restart.pre_restart_height is not an integer", "rust_restart_pre_restart_height_invalid"),
    ("rust_restart.catch_up_height is not an integer", "rust_restart_catch_up_height_invalid"),
    ("rust_restart.go_target_height is not an integer", "rust_restart_go_target_height_invalid"),
    ("rust_restart catch_up_height mismatch", "rust_restart_catch_up_height_mismatch"),
    ("rust_restart go target did not advance", "rust_restart_go_target_not_advanced"),
    ("rust_restart catch-up height does not match go target", "rust_restart_catch_up_height_not_go_target"),
    ("rust_restart catch-up tip does not match go target", "rust_restart_catch_up_tip_not_go_target"),
    ("rust_restart go target mine_next sidecar", "rust_restart_go_target_mine_next_invalid"),
    ("rust_restart.go_target_tip_path", "rust_restart_go_target_tip_sidecar_invalid"),
    ("rust_restart.new_pid is not the final rust node pid", "rust_restart_new_pid_not_final"),
    ("rust_restart old endpoints are malformed", "rust_restart_old_endpoints_malformed"),
    ("rust_restart new endpoints are not bound", "rust_restart_new_endpoints_mismatch"),
    ("rust_restart timestamps are not bound", "rust_restart_timestamps_mismatch"),
    ("rust_restart does not prove same datadir restart", "rust_restart_datadir_mismatch"),
    ("rust_restart datadir is not bound", "rust_restart_datadir_not_bound"),
    ("restart report run_id missing", "rust_restart_run_id_missing"),
    ("restart report run_id mismatch", "rust_restart_run_id_mismatch"),
    ("restart report artifact_created_at_utc invalid", "rust_restart_artifact_created_at_invalid"),
    ("rust_restart pre_restart_height mismatch", "rust_restart_pre_restart_height_mismatch"),
    ("rust_restart tip flags are not booleans", "rust_restart_tip_flags_invalid"),
    ("rust_restart pre-restart tip is not proven", "rust_restart_pre_tip_not_proven"),
    ("rust_restart catch-up tip is not proven", "rust_restart_catch_up_tip_not_proven"),
    ("rust_restart go target tip is not proven", "rust_restart_go_target_tip_not_proven"),
    ("rust_restart.go_target_tip is malformed", "rust_restart_go_target_tip_malformed"),
    ("rust_restart.go_target_tx_count is malformed", "rust_restart_go_target_tx_count_invalid"),
    ("rust_restart.pre_restart_tip is malformed", "rust_restart_pre_tip_malformed"),
    ("rust_restart.catch_up_tip is malformed", "rust_restart_catch_up_tip_malformed"),
    ("rust_restart.pre_restart_tip_path", "rust_restart_pre_restart_tip_sidecar_invalid"),
    ("rust_restart.pre_restart_tip does not match", "rust_restart_pre_tip_flag_mismatch"),
    ("rust_restart.go_target_mine_next_path", "rust_restart_go_target_mine_next_invalid"),
    ("rust_restart.catch_up_tip_path", "rust_restart_catch_up_tip_sidecar_invalid"),
    ("rust_restart.catch_up_tip does not match", "rust_restart_catch_up_tip_flag_mismatch"),
    ("rust_restart same-height catch-up tip mismatch", "rust_restart_same_height_tip_mismatch"),
    ("rust_restart old argv mismatch", "rust_restart_old_argv_mismatch"),
    ("rust_restart new argv mismatch", "rust_restart_new_argv_mismatch"),
    ("restart.stopped_node must be node-rust", "rust_restart_stopped_node_invalid"),
    ("restart.pre_restart_height is not an integer", "rust_restart_pre_restart_height_invalid"),
    ("restart.catch_up_height is not an integer", "rust_restart_catch_up_height_invalid"),
    ("below pre_restart_height", "rust_restart_catch_up_below_pre_restart"),
    ("legacy marker restart object is not bound", "rust_restart_legacy_marker_mismatch"),
    ("public restart check-report-live is unsupported", "public_restart_check_report_live_unsupported"),
    ("public restart check-report is unsupported", "public_restart_check_report_unsupported"),
    ("public tx-path check-report-live is unsupported", "public_tx_path_check_report_live_unsupported"),
    ("public tx-path check-report is unsupported", "public_tx_path_check_report_unsupported"),
    ("same-run producer evidence is required", "tx_path_requires_same_run_producer_evidence"),
    ("report path is required", "report_path_required"),
    ("report is not a regular file", "report_not_regular_file"),
    ("report is empty", "report_empty"),
    ("report is too large", "report_too_large"),
    ("report read failed", "report_read_failed"),
    ("report malformed JSON", "report_malformed_json"),
    ("live peer snapshot malformed JSON", "live_peer_snapshot_malformed_json"),
    ("differs from live exact peer set", "live_peer_snapshot_mismatch"),
    ("live listeners are not pid-owned", "live_listener_not_pid_owned"),
    ("rust outbound TCP link is not live and rust-owned", "rust_outbound_link_not_live"),
    ("argv_unavailable", "argv_unavailable"),
    ("live process argv/executable does not match report", "argv_mismatch"),
    ("lsof_timeout", "lsof_timeout"),
    ("lsof_unavailable", "lsof_unavailable"),
    ("lsof_failed", "lsof_failed"),
    ("pid_exe_failed", "pid_exe_failed"),
    ("pid_exe_unavailable", "pid_exe_unavailable"),
    ("node keys mismatch", "process_identity_invalid"),
    ("argv", "argv_mismatch"),
    ("same pid", "same_pid"),
    ("process_comm", "process_identity_invalid"),
    ("process_alive", "process_identity_invalid"),
    ("process-backed", "process_identity_invalid"),
    ("peer snapshot", "peer_snapshot_invalid"),
    ("legacy marker", "legacy_marker_invalid"),
    ("failure/schema-marker", "pass_report_has_failure_fields"),
    ("failure_reason", "pass_report_has_failure_fields"),
    ("raw_samples.propagation", "propagation_samples_invalid"),
    ("raw_samples.convergence", "convergence_samples_invalid"),
    ("root is not an object", "report_root_invalid"),
]
print(next((token for pattern, token in rules if pattern in msg), "unknown"))
PY
}
tx_report_reason_token() {
  local msg
  msg="$(cat)"
  python3 - "${msg}" <<'PY'
import re, sys
msg = "\n".join(line[5:].strip() if line.startswith("FAIL:") else line for line in sys.argv[1].splitlines())
rules = [("raw_samples.propagation", "propagation_samples_invalid"), ("raw_samples.convergence", "convergence_samples_invalid"), ("rust_mine is not node-rust mined_included", "rust_mine_class_invalid"), ("go_mine is not node-go mined_included", "go_mine_class_invalid"), ("go_converge is not node-go canonical_block_found", "go_converge_class_invalid"), ("rust_converge is not node-rust canonical_block_found", "rust_converge_class_invalid"), ("mined/converged RPC endpoints are not bound", "converge_rpc_endpoint_mismatch"), ("rust_mine.height is malformed", "rust_mine_height_invalid"), ("go_mine.height is malformed", "go_mine_height_invalid"), ("rust_mine.block_hash is malformed", "rust_mine_hash_invalid"), ("go_mine.block_hash is malformed", "go_mine_hash_invalid"), ("sidecar identity mismatch", "converge_sidecar_identity_mismatch"), ("converge sidecar paths are not pairwise distinct", "converge_sidecar_paths_not_distinct"), ("submitted txid missing from parsed block txids", "block_missing_submitted_txid"), ("parse block_hex failed", "block_hex_parse_failed"), ("parsed block hash mismatch", "block_hash_mismatch"), ("parsed block tx_count mismatch", "block_tx_count_mismatch"), ("basic block validation failed", "block_basic_validation_failed"), ("inclusion check timeout", "block_inclusion_timeout"), ("inclusion check failed", "block_inclusion_failed"), ("mined/converged tx identity differs", "converged_tx_identity_mismatch"), ("go_converge does not match rust_mine", "go_converge_height_hash_mismatch"), ("rust_converge does not match go_mine", "rust_converge_height_hash_mismatch"), ("rust_mine.tx_count", "rust_mine_tx_count_invalid"), ("go_mine.tx_count", "go_mine_tx_count_invalid"), ("mine_next sidecar does not match", "mine_sidecar_invalid"), ("sidecar height/hash/canonical mismatch", "block_sidecar_invalid"), ("block_hex is missing", "block_sidecar_invalid"), ("tip sidecar does not match", "converge_tip_invalid"), ("tx parser consumed mismatch", "tx_parser_consumed_mismatch"), ("tx parser timeout", "tx_parser_timeout"), ("tx parser unavailable", "tx_parser_unavailable"), ("tx parser output too large", "tx_parser_output_too_large"), ("tx parser malformed output", "tx_parser_malformed_output"), ("tx parser root is not an object", "tx_parser_root_invalid"), ("tx parser did not produce txid", "tx_parser_missing_txid"), ("tx parser failed", "tx_parser_failed"), ("tx_hex is malformed or unbounded", "tx_hex_malformed_or_unbounded"), ("txid is malformed", "txid_malformed"), ("tx report rpc endpoint mismatch", "tx_report_rpc_endpoint_mismatch"), ("capture identity mismatch", "tx_capture_identity_mismatch"), ("tx sidecar paths are not pairwise distinct", "tx_sidecar_paths_not_distinct"), ("scenario mismatch", "scenario_mismatch"), ("verdict mismatch", "verdict_mismatch"), ("artifact_root mismatch", "artifact_root_mismatch"), ("tx_path identity mismatch", "tx_path_identity_mismatch"), ("tx report txid mismatch", "tx_identity_mismatch"), ("tx report raw transaction mismatch", "raw_tx_mismatch")]
for needle, token in rules:
    if needle in msg:
        print(token)
        sys.exit(0)
label_rules = [
    ("root is not an object", "root_invalid"),
    ("malformed JSON", "malformed_json"),
    ("read failed", "read_failed"),
    ("is not an object", "object_invalid"),
    ("keys mismatch", "keys_mismatch"),
    ("path mismatch", "path_mismatch"),
    ("file is missing", "file_missing"),
    ("is outside artifact_root", "outside_artifact_root"),
    ("is not pending", "not_pending"),
    ("txid mismatch", "txid_mismatch"),
    ("did not find tx", "not_found"),
    ("raw_hex mismatch", "raw_hex_mismatch"),
]
for label, text in re.findall(r"(?:tx report self-validation: )?([A-Za-z0-9_.]+) ([^\n]+)", msg):
    safe_label = re.sub(r"[^A-Za-z0-9]+", "_", label).strip("_").lower()
    for needle, token in label_rules:
        if needle in text:
            print(f"{safe_label}_{token}")
            sys.exit(0)
print("unclassified")
PY
}
combined_report_reason_token() {
  local msg token
  msg="$(cat)"
  token="$(tx_report_reason_token <<<"${msg}")"
  if [[ "${token}" == "unclassified" ]]; then token="$(check_report_reason_token <<<"${msg}")"; fi
  [[ "${token}" == "unknown" || "${token}" == "unclassified" ]] && token=tx_report_validation_failed; printf '%s\n' "${token}"
}
rpc_json() {
  local method="$1" addr="$2" path="$3"
  python3 - "${method}" "${addr}" "${path}" <<'PY'
import socket, sys, urllib.error, urllib.request
method, addr, path = sys.argv[1:4]
req = urllib.request.Request(f"http://{addr}{path}", method=method)
try:
    with urllib.request.urlopen(req, timeout=5) as resp: print(resp.read(1000001).decode("utf-8"), end="")
except urllib.error.HTTPError as exc:
    try:
        print(exc.read(1000001).decode("utf-8"), end="")
    except UnicodeDecodeError:
        sys.exit(23)
    sys.exit(22)
except UnicodeDecodeError:
    sys.exit(23)
except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
    print(f"request failed: {getattr(exc, 'reason', exc)}", end="")
    sys.exit(1)
PY
}
capture_rpc_sidecar() {
  local impl="$1" method="$2" addr="$3" path="$4" out="$5" preserve_http_error="${6:-}" status=0; local tmp="${out}.raw"
  rpc_json "${method}" "${addr}" "${path}" >"${tmp}" || status=$?
  (( status == 0 )) || {
    if [[ "${status}" -eq 22 && "${preserve_http_error}" == preserve-http-error ]]; then
      return 21
    fi
    rm -f -- "${tmp}"
    case "${status}" in 22) return 21 ;; 23) return 23 ;; *) return 22 ;; esac
  }
  python3 - "${impl}" "${addr}" "${path}" "${tmp}" "${out}" <<'PY'
import json, os, sys
impl, addr, request_path, src, dst = sys.argv[1:6]
try:
    with open(src, encoding="utf-8") as f:
        data = json.load(f)
except OSError:
    sys.exit(24)
except (json.JSONDecodeError, UnicodeDecodeError):
    sys.exit(23)
if not isinstance(data, dict):
    sys.exit(25)
data.update({"implementation": impl, "request_path": request_path, "rpc_endpoint": addr})
tmp = dst + ".tmp"
try:
    with open(tmp, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, sort_keys=True); f.write("\n")
    os.replace(tmp, dst)
except OSError:
    sys.exit(26)
finally:
    try: os.remove(src)
    except OSError: pass
PY
}
capture_tx_rpc_sidecar() { capture_rpc_sidecar "$1" GET "$2" "$3" "$4"; }
pid_comm() { local pid="$1" raw comm status=0 err="${RUBIN_PROCESS_ARTIFACT_ROOT}/ps.err"; raw="$(bounded ps -ww -p "${pid}" -o comm= 2>"${err}")" || status=$?; (( status == 142 )) && return 3; [[ ${status} -eq 0 || ! -s "${err}" ]] || return 2; comm="$(sed -n '1p' <<<"${raw}")" || return 4; [[ -n "${comm}" ]] || return 1; basename -- "${comm}"; }
pid_listens_on() {
  local pid="$1" endpoint="$2" out err status=0
  out="$(bounded lsof -nP -a -p "${pid}" -iTCP -sTCP:LISTEN -Fn 2>"${RUBIN_PROCESS_ARTIFACT_ROOT}/lsof-listen.err")" || status=$?; err="$(<"${RUBIN_PROCESS_ARTIFACT_ROOT}/lsof-listen.err")"
  (( status == 142 )) && return 3
  (( status == 0 || (${#out} == 0 && ${#err} == 0) )) || return 2
  (( status == 0 )) && grep -F -x -q -- "n${endpoint}" <<<"${out}" && return 0
  return 1
}
p2p_addr_for_pid() {
  local pid="$1" rpc_addr="$2" timeout="$3"
  python3 - "${pid}" "${rpc_addr}" "${timeout}" <<'PY'
import re, subprocess, sys, time
pid, rpc_addr, timeout = sys.argv[1], sys.argv[2], int(sys.argv[3])
deadline = time.time() + timeout
while time.time() < deadline:
    try: proc = subprocess.run(["lsof", "-nP", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-Fn"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    except subprocess.TimeoutExpired: sys.exit(43)
    if proc.returncode != 0:
        if proc.stdout.strip() or proc.stderr.strip(): sys.exit(42)
        time.sleep(1); continue
    addrs = sorted({line[1:].strip() for line in proc.stdout.splitlines() if line.startswith("n") and line[1:].strip() != rpc_addr and re.fullmatch(r"127\.0\.0\.1:[0-9]+", line[1:].strip())})
    if len(addrs) == 1: print(addrs[0]); sys.exit(0)
    if len(addrs) > 1:
        print(f"ambiguous p2p listen addresses for pid={pid}: {addrs}", file=sys.stderr)
        sys.exit(44)
    time.sleep(1)
print(f"timeout resolving p2p listen address for pid={pid}", file=sys.stderr)
sys.exit(45)
PY
}
extract_log_addr() {
  local log_file="$1" prefix="$2" path addr
  path="$(_rubin_process_resolve_log "${log_file}")" || return 1
  addr="$(sed -n "s/.*${prefix}//p" "${path}" | tail -n 1 | tr -d '[:space:]')" || return 1
  [[ -n "${addr}" ]] || return 1; printf '%s\n' "${addr}"
}
build_go_node() { BUILD_REASON=""; echo "Building Go rubin-node binary" >&2; "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${GO_NODE_BIN}" ./cmd/rubin-node || { BUILD_REASON=go_build_failed; return 1; }; [[ -x "${GO_NODE_BIN}" ]] || { BUILD_REASON=go_binary_missing_or_not_executable; return 1; }; }
build_go_txgen() { BUILD_REASON=""; echo "Building Go rubin-txgen binary" >&2; "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" build -o "${TXGEN_BIN}" ./cmd/rubin-txgen || { BUILD_REASON=go_txgen_build_failed; return 1; }; [[ -x "${TXGEN_BIN}" ]] || { BUILD_REASON=go_txgen_missing_or_not_executable; return 1; }; }
build_rust_node() {
  local host_triple cargo_target_dir cargo_log cargo_bin rc
  BUILD_REASON=""
  echo "Building Rust rubin-node binary" >&2
  run_fips_preflight_before_captured_dev_env || { BUILD_REASON=rust_fips_preflight_failed; return 1; }
  host_triple="$(RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- rustc -vV | awk '/^host:/ {print $2}')" || { BUILD_REASON=rust_host_triple_failed; return 1; }
  [[ -n "${host_triple}" ]] || { BUILD_REASON=rust_host_triple_missing; return 1; }
  cargo_target_dir="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-target"; cargo_log="${RUBIN_PROCESS_ARTIFACT_ROOT}/cargo-build.jsonl"
  RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- cargo build --manifest-path "${RUST_WORKSPACE_ROOT}/Cargo.toml" --release --locked -p rubin-node --target "${host_triple}" --target-dir "${cargo_target_dir}" --message-format=json-render-diagnostics >"${cargo_log}" || { BUILD_REASON=rust_cargo_build_failed; return 1; }
  cargo_bin="$(python3 - "${cargo_log}" <<'PY'
import json, sys
selected = None
with open(sys.argv[1], encoding="utf-8") as f:
    for line_no, raw in enumerate(f, 1):
        line = raw.strip()
        if not line: continue
        if not line.startswith("{"): sys.exit(2)
        try: ev = json.loads(line)
        except json.JSONDecodeError: sys.exit(2)
        if ev.get("reason") != "compiler-artifact": continue
        target = ev.get("target") or {}
        if target.get("name") == "rubin-node" and "bin" in (target.get("kind") or []) and ev.get("executable"): selected = ev["executable"]
if selected is None: sys.exit(3)
print(selected)
PY
  )" || { rc=$?; [[ ${rc} -eq 2 ]] && BUILD_REASON=rust_cargo_json_malformed || BUILD_REASON=rust_cargo_artifact_missing; return 1; }
  [[ -x "${cargo_bin}" ]] || { BUILD_REASON=rust_cargo_artifact_missing; return 1; }
  cp -- "${cargo_bin}" "${RUST_NODE_BIN}" || { BUILD_REASON=rust_binary_copy_failed; return 1; }
  [[ -x "${RUST_NODE_BIN}" ]] || { BUILD_REASON=rust_binary_not_executable; return 1; }
}
write_keygen() {
  cat >"${KEYGEN_GO}" <<'EOF'
package main
import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)
func main() {
	dir := os.Args[1]
	from, err := consensus.NewMLDSA87Keypair(); if err != nil { panic(err) }
	defer from.Close()
	to, err := consensus.NewMLDSA87Keypair(); if err != nil { panic(err) }
	defer to.Close()
	der, err := from.PrivateKeyDER(); if err != nil { panic(err) }
	fromAddress := hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(from.PubkeyBytes()))
	path := filepath.Join(dir, "from-key.hex")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(der)+"\n"), 0o600); err != nil { panic(err) }
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"private_key_file": path, "from_address_hex": fromAddress, "to_address_hex": hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(to.PubkeyBytes())), "mine_address_hex": fromAddress}); err != nil { panic(err) }
}
EOF
}
keygen_material_reason() {
  case "$1" in
    2) printf '%s\n' go_submit_keygen_stdout_too_large ;;
    3) printf '%s\n' go_submit_keygen_material_malformed_json ;;
    4) printf '%s\n' go_submit_keygen_material_root_invalid ;;
    5) printf '%s\n' go_submit_keygen_material_keys_mismatch ;;
    6) printf '%s\n' go_submit_keygen_material_string_invalid ;;
    7) printf '%s\n' go_submit_keygen_private_path_invalid ;;
    8) printf '%s\n' go_submit_keygen_private_path_mismatch ;;
    9) printf '%s\n' go_submit_keygen_private_file_invalid ;;
    10) printf '%s\n' go_submit_keygen_private_file_mode_invalid ;;
    11) printf '%s\n' go_submit_keygen_address_malformed ;;
    12) printf '%s\n' go_submit_keygen_from_mine_mismatch ;;
    13) printf '%s\n' go_submit_keygen_to_matches_from ;;
    14) printf '%s\n' go_submit_keygen_material_temp_write_failed ;;
    15) printf '%s\n' go_submit_keygen_material_temp_cleanup_failed ;;
    *) printf '%s\n' go_submit_keygen_material_malformed ;;
  esac
}
tx_secret_tmp_parent() {
  local parent="${1:-/tmp}"
  [[ -n "${parent}" ]] || parent="/tmp"
  (cd -- "${parent}" && pwd -P)
}
make_tx_secret_dir() {
  local tmp_parent
  tmp_parent="$(tx_secret_tmp_parent "${1:-/tmp}")" || return 1
  mktemp -d "${tmp_parent%/}/rubin-txgen-from-key.XXXXXX"
}
keygen_material_byte_len() {
  LC_ALL=C printf '%s' "$1" | wc -c | tr -d '[:space:]'
}
parse_keygen_material() {
  local raw="$1" raw_file="${TX_FROM_KEY_DIR}/keygen-public.json" raw_bytes rc=0
  raw_bytes="$(keygen_material_byte_len "${raw}")" || return 2
  [[ "${raw_bytes}" =~ ^[0-9]+$ && "${raw_bytes}" -le 4096 ]] || return 2
  (umask 077 && printf '%s' "${raw}" >"${raw_file}") || { rm -f -- "${raw_file}" 2>/dev/null || true; return 14; }
  if python3 - "${TX_FROM_KEY_DIR}" "${raw_file}" <<'PY'
import json
import re
import stat
import sys
from pathlib import Path

expected_keys = {"private_key_file", "from_address_hex", "to_address_hex", "mine_address_hex"}
try:
    with open(sys.argv[2], "rb") as f:
        raw = f.read(4097)
except OSError:
    sys.exit(7)
if len(raw) > 4096:
    sys.exit(2)
try:
    data = json.loads(raw.decode("utf-8"))
except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
    sys.exit(3)
if not isinstance(data, dict):
    sys.exit(4)
if set(data) != expected_keys:
    sys.exit(5)
for value in data.values():
    if not isinstance(value, str) or not value or "\x00" in value or any(ord(ch) < 32 for ch in value):
        sys.exit(6)
try:
    secret_dir = Path(sys.argv[1]).resolve(strict=True)
    private_path = Path(data["private_key_file"])
    if not private_path.is_absolute():
        sys.exit(7)
    private_path = private_path.resolve(strict=False)
except (OSError, RuntimeError):
    sys.exit(7)
if private_path != (secret_dir / "from-key.hex"):
    sys.exit(8)
try:
    st = private_path.stat()
except OSError:
    sys.exit(9)
if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > 1_000_000:
    sys.exit(9)
if stat.S_IMODE(st.st_mode) != 0o600:
    sys.exit(10)
addr_re = re.compile(r"01[0-9a-f]{64}")
from_addr = data["from_address_hex"]
to_addr = data["to_address_hex"]
mine_addr = data["mine_address_hex"]
if not all(addr_re.fullmatch(v) for v in (from_addr, to_addr, mine_addr)):
    sys.exit(11)
if from_addr != mine_addr:
    sys.exit(12)
if to_addr == from_addr:
    sys.exit(13)
print(private_path)
print(to_addr)
print(mine_addr)
PY
  then rc=0; else rc=$?; fi
  rm -f -- "${raw_file}" || return 15
  return "${rc}"
}
prepare_tx_chainstate() {
  local keygen_public_json keygen_fields_raw mine_address keygen_raw="${KEYGEN_JSON}.raw" keygen_err="${KEYGEN_JSON}.stderr" xtrace_was_enabled=0 status=0 rc=0
  trap 'rm -f -- "${keygen_raw}" "${keygen_err}" >/dev/null 2>&1 || true; trap - RETURN' RETURN
  TX_REASON=""
  build_go_txgen || { TX_REASON="${BUILD_REASON:-go_txgen_build_failed}"; return 1; }
  write_keygen || { TX_REASON=go_submit_keygen_write_failed; return 1; }
  if disable_xtrace_for_secret; then xtrace_was_enabled=1; fi
  TX_FROM_KEY_DIR="$(make_tx_secret_dir "${TMPDIR:-/tmp}")" || { restore_xtrace_after_secret "${xtrace_was_enabled}"; TX_REASON=go_submit_keygen_tempdir_failed; return 1; }
  chmod 700 "${TX_FROM_KEY_DIR}" || { status=$?; cleanup_tx_from_key_file || true; restore_xtrace_after_secret "${xtrace_was_enabled}"; TX_REASON=go_submit_keygen_tempdir_failed; return "${status}"; }
  bounded_mesh /usr/bin/env RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${KEYGEN_GO}" "${TX_FROM_KEY_DIR}" >"${keygen_raw}" 2>"${keygen_err}" || { status=$?; cleanup_tx_from_key_file || true; restore_xtrace_after_secret "${xtrace_was_enabled}"; [[ ${status} -eq 142 ]] && TX_REASON=go_submit_keygen_timeout || TX_REASON=go_submit_keygen_failed; return "${status}"; }
  keygen_public_json="$(cat -- "${keygen_raw}")" || { cleanup_tx_from_key_file || true; restore_xtrace_after_secret "${xtrace_was_enabled}"; TX_REASON=go_submit_keygen_material_malformed_json; return 1; }
  keygen_fields_raw="$(parse_keygen_material "${keygen_public_json}")" || { rc=$?; cleanup_tx_from_key_file || true; restore_xtrace_after_secret "${xtrace_was_enabled}"; TX_REASON="$(keygen_material_reason "${rc}")"; return 1; }
  rm -f -- "${keygen_raw}" "${keygen_err}" || { cleanup_tx_from_key_file || true; restore_xtrace_after_secret "${xtrace_was_enabled}"; TX_REASON=go_submit_keygen_cleanup_failed; return 1; }
  [[ "$(printf '%s\n' "${keygen_fields_raw}" | sed -n '$=')" == "3" ]] || { cleanup_tx_from_key_file || true; restore_xtrace_after_secret "${xtrace_was_enabled}"; TX_REASON=go_submit_keygen_material_malformed; return 1; }
  TX_FROM_KEY_FILE="$(printf '%s\n' "${keygen_fields_raw}" | sed -n '1p')"
  TX_TO_KEY="$(printf '%s\n' "${keygen_fields_raw}" | sed -n '2p')"
  mine_address="$(printf '%s\n' "${keygen_fields_raw}" | sed -n '3p')"
  restore_xtrace_after_secret "${xtrace_was_enabled}"
  python3 - "${KEYGEN_JSON}" "${mine_address}" "${TX_TO_KEY}" <<'PY' || { cleanup_tx_from_key_file || true; TX_REASON=go_submit_keygen_material_malformed; return 1; }
import json, sys
public = {"mine_address_hex": sys.argv[2], "to_address_hex": sys.argv[3]}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(public, f, indent=2, sort_keys=True)
    f.write("\n")
PY
  rm -f -- "${KEYGEN_GO}" || { cleanup_tx_from_key_file || true; TX_REASON=go_submit_keygen_cleanup_failed; return 1; }
  echo "Mining mature chainstate for mixed-client evidence" >&2
  bounded_mesh "${GO_NODE_BIN}" --network devnet --datadir "${GO_DIR}" --mine-address "${mine_address}" --mine-blocks 101 --mine-exit >"$(_rubin_process_resolve_log "${MINE_LOG}")" 2>&1 || { status=$?; cleanup_tx_from_key_file || true; [[ ${status} -eq 142 ]] && TX_REASON=go_submit_mine_timeout || TX_REASON=go_submit_mine_failed; return 1; }
  cp -R -- "${GO_DIR}/." "${RUST_DIR}/" || { cleanup_tx_from_key_file || true; TX_REASON=go_submit_chainstate_copy_failed; return 1; }
}
prepare_restart_chainstate() {
  TX_REASON=""
  RUST_RESTART_REASON=""
  prepare_tx_chainstate || { RUST_RESTART_REASON="$(rust_restart_prepare_reason "${TX_REASON:-}")"; return 1; }
  cleanup_tx_from_key_file || { RUST_RESTART_REASON=rust_restart_chainstate_secret_cleanup_failed; return 1; }
}
rust_restart_prepare_reason() {
  case "${1:-}" in
    "") printf '%s\n' rust_restart_chainstate_prepare_failed ;;
    go_submit_keygen_*) printf 'rust_restart_keygen_%s\n' "${1#go_submit_keygen_}" ;;
    go_submit_mine_*) printf 'rust_restart_chainstate_mine_%s\n' "${1#go_submit_mine_}" ;;
    go_submit_chainstate_copy_failed) printf '%s\n' rust_restart_chainstate_copy_failed ;;
    go_submit_*) printf 'rust_restart_chainstate_%s\n' "${1#go_submit_}" ;;
    *) printf 'rust_restart_%s\n' "${1}" ;;
  esac
}
partition_prepare_reason() {
  case "${1:-}" in
    "") printf '%s\n' partition_chainstate_prepare_failed ;;
    go_submit_keygen_*) printf 'partition_keygen_%s\n' "${1#go_submit_keygen_}" ;;
    go_submit_mine_*) printf 'partition_chainstate_mine_%s\n' "${1#go_submit_mine_}" ;;
    go_submit_chainstate_copy_failed) printf '%s\n' partition_chainstate_copy_failed ;;
    go_submit_*) printf 'partition_chainstate_%s\n' "${1#go_submit_}" ;;
    *) printf 'partition_%s\n' "${1}" ;;
  esac
}
tx_path_prepare_reason() {
  local reason="${1:-}" mode="${2:-0}"
  if [[ "${mode}" == "3" && "${reason}" == go_submit_* ]]; then
    printf 'rust_submit_%s\n' "${reason#go_submit_}"
    return 0
  fi
  printf '%s\n' "${reason}"
}
parse_txid() {
  python3 - "${DEV_ENV}" "${GO_MODULE_ROOT}" "${TX_HEX}" <<'PY'
import json, os, subprocess, sys
dev_env, go_module_root, txhex = sys.argv[1:4]
request = json.dumps({"op": "parse_tx", "tx_hex": txhex}) + "\n"
try:
    proc = subprocess.run([dev_env, "--", "go", "-C", go_module_root, "run", "./cmd/rubin-consensus-cli"], check=False, env={**os.environ, "RUBIN_OPENSSL_SKIP_FIPS_GUARD": "1"}, input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
except subprocess.TimeoutExpired:
    sys.exit(2)
except OSError:
    sys.exit(3)
stdout, stderr = proc.stdout or "", proc.stderr or ""
if len(stdout) > 100000 or len(stderr) > 100000:
    sys.exit(8)
if proc.returncode != 0:
    sys.exit(4)
try:
    data = json.loads(stdout)
except (json.JSONDecodeError, UnicodeDecodeError):
    sys.exit(5)
if not isinstance(data, dict):
    sys.exit(6)
txid = data.get("txid")
if data.get("ok") is not True or not isinstance(txid, str) or len(txid) != 64 or any(c not in "0123456789abcdef" for c in txid):
    sys.exit(7)
if data.get("consumed") != len(txhex) // 2:
    sys.exit(9)
print(txid)
PY
}
txid_parse_reason() {
  local rc="$1" label="${2:-go_submit}"
  case "${rc}" in
    2) printf '%s\n' "${label}_txid_parse_timeout" ;;
    3) printf '%s\n' "${label}_txid_parser_unavailable" ;;
    4) printf '%s\n' "${label}_txid_parser_failed" ;;
    5) printf '%s\n' "${label}_txid_parser_malformed_output" ;;
    6) printf '%s\n' "${label}_txid_parser_root_invalid" ;;
    7) printf '%s\n' "${label}_txid_missing_or_malformed" ;;
    8) printf '%s\n' "${label}_txid_parser_output_too_large" ;;
    9) printf '%s\n' "${label}_txid_parser_consumed_mismatch" ;;
    *) printf '%s\n' "${label}_txid_parse_failed" ;;
  esac
}
tx_capture_reason() { local label="$1" rc="$2"; case "${rc}" in 21) printf '%s\n' "${label}_http_error" ;; 22) printf '%s\n' "${label}_rpc_failed" ;; 23) printf '%s\n' "${label}_malformed_json" ;; 24) printf '%s\n' "${label}_capture_read_failed" ;; 25) printf '%s\n' "${label}_invalid_shape" ;; 26) printf '%s\n' "${label}_artifact_write_failed" ;; *) printf '%s\n' "${label}_capture_failed" ;; esac; }
tx_sidecar_reason() {
  local label="$1" rc="$2"
  case "${rc}" in
    11) printf '%s\n' "${label}_sidecar_malformed_json" ;;
    12) printf '%s\n' "${label}_status_txid_mismatch" ;;
    13) printf '%s\n' "${label}_status_not_pending" ;;
    14) printf '%s\n' "${label}_get_tx_not_found" ;;
    15) printf '%s\n' "${label}_get_txid_mismatch" ;;
    16) printf '%s\n' "${label}_raw_hex_mismatch" ;;
    17) printf '%s\n' "${label}_sidecar_read_failed" ;;
    18) printf '%s\n' "${label}_status_keys_mismatch" ;;
    19) printf '%s\n' "${label}_get_tx_keys_mismatch" ;;
    20) printf '%s\n' "${label}_capture_identity_mismatch" ;;
    *) printf '%s\n' "${label}_identity_unverified" ;;
  esac
}
verify_tx_sidecars() {
  local label="$1" impl="$2" endpoint="$3" txid="$4" txhex="$5" status_request="$6" get_request="$7" status_path="$8" get_path="$9"
  python3 - "${label}" "${impl}" "${endpoint}" "${txid}" "${txhex}" "${status_request}" "${get_request}" "${status_path}" "${get_path}" <<'PY'
import json
import sys
label, impl, endpoint, txid, txhex, status_request, get_request, status_path, get_path = sys.argv[1:10]
def fail(code: int, message: str) -> None:
    print(f"{label}: {message}", file=sys.stderr)
    sys.exit(code)
def load_json(path: str, kind: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as exc:
        fail(17, f"{kind}_read_failed: {exc}")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        fail(11, f"{kind}_malformed_json: {exc}")
    if not isinstance(data, dict):
        fail(11, f"{kind}_root_not_object")
    return data
status = load_json(status_path, "tx_status")
got = load_json(get_path, "get_tx")
if set(status) != {"implementation", "request_path", "rpc_endpoint", "status", "txid"}:
    fail(18, f"tx_status_keys_mismatch: {sorted(status)}")
if status.get("implementation") != impl or status.get("rpc_endpoint") != endpoint or status.get("request_path") != status_request:
    fail(20, "tx_status_capture_identity_mismatch")
status_txid = status.get("txid")
status_value = status.get("status")
if status_value != "pending":
    fail(13, f"tx_status_not_pending: {status_value!r}")
if status_txid != txid:
    fail(12, f"tx_status_txid_mismatch: {status_txid!r}")
got_keys = set(got)
found = got.get("found")
if found is not True:
    if found is not False:
        fail(19, f"get_tx_found_invalid: {found!r}")
    if got_keys != {"found", "implementation", "request_path", "rpc_endpoint", "txid"}:
        fail(19, f"get_tx_keys_mismatch: {sorted(got)}")
    if got.get("implementation") != impl or got.get("rpc_endpoint") != endpoint or got.get("request_path") != get_request:
        fail(20, "get_tx_capture_identity_mismatch")
    if got.get("txid") != txid:
        fail(15, f"get_tx_txid_mismatch: {got.get('txid')!r}")
    fail(14, f"get_tx_not_found: {found!r}")
if got_keys != {"found", "implementation", "raw_hex", "request_path", "rpc_endpoint", "txid"}:
    fail(19, f"get_tx_keys_mismatch: {sorted(got)}")
if got.get("implementation") != impl or got.get("rpc_endpoint") != endpoint or got.get("request_path") != get_request:
    fail(20, "get_tx_capture_identity_mismatch")
if got.get("txid") != txid:
    fail(15, f"get_tx_txid_mismatch: {got.get('txid')!r}")
if got.get("raw_hex") != txhex:
    fail(16, "get_tx_raw_hex_mismatch")
PY
}
submit_go_tx() {
  local -a argv=("${TXGEN_BIN}" --datadir "${GO_DIR}" --from-key-file "${TX_FROM_KEY_FILE}" --to-key "${TX_TO_KEY}" --amount 1 --fee "${DETERMINISTIC_TX_FEE}" --submit-to "${GO_RPC_ADDR}")
  local status=0 cleanup_status=0 rc=0
  TX_REASON=""
  [[ -n "${TX_FROM_KEY_FILE}" && -f "${TX_FROM_KEY_FILE}" && -n "${TX_TO_KEY}" ]] || { cleanup_tx_from_key_file || true; TX_REASON=go_submit_keygen_material_malformed; return 1; }
  TX_HEX="$(bounded_mesh "${argv[@]}")" || status=$?
  PROPAGATION_SAMPLE_START_SECONDS="${SECONDS}"
  cleanup_tx_from_key_file || cleanup_status=$?
  (( cleanup_status == 0 )) || { TX_REASON=go_submit_keygen_cleanup_failed; return 1; }
  (( status == 0 )) || { [[ ${status} -eq 142 ]] && TX_REASON=go_submit_txgen_timeout || TX_REASON=go_submit_txgen_failed; return 1; }
  [[ "${TX_HEX}" =~ ^[0-9a-f]+$ && ${#TX_HEX} -le 20000 && $(( ${#TX_HEX} % 2 )) -eq 0 ]] || { TX_REASON=go_submit_tx_hex_malformed_or_unbounded; return 1; }
  TX_ID="$(parse_txid)" || { rc=$?; TX_REASON="$(txid_parse_reason "${rc}")"; return 1; }
  capture_tx_rpc_sidecar go "${GO_RPC_ADDR}" "/tx_status?txid=${TX_ID}" "${GO_SUBMIT_STATUS_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason go_submit_tx_status "${rc}")"; return 1; }
  capture_tx_rpc_sidecar go "${GO_RPC_ADDR}" "/get_tx?txid=${TX_ID}" "${GO_SUBMIT_GET_TX_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason go_submit_get_tx "${rc}")"; return 1; }
  verify_tx_sidecars go_submit go "${GO_RPC_ADDR}" "${TX_ID}" "${TX_HEX}" "/tx_status?txid=${TX_ID}" "/get_tx?txid=${TX_ID}" "${GO_SUBMIT_STATUS_JSON}" "${GO_SUBMIT_GET_TX_JSON}" || { rc=$?; TX_REASON="$(tx_sidecar_reason go_submit "${rc}")"; return 1; }
}
submit_rust_tx() {
  local -a argv=("${TXGEN_BIN}" --datadir "${RUST_DIR}" --from-key-file "${TX_FROM_KEY_FILE}" --to-key "${TX_TO_KEY}" --amount 1 --fee "${DETERMINISTIC_TX_FEE}" --submit-to "${RUST_RPC_ADDR}")
  local status=0 cleanup_status=0 rc=0
  TX_REASON=""
  [[ -n "${TX_FROM_KEY_FILE}" && -f "${TX_FROM_KEY_FILE}" && -n "${TX_TO_KEY}" ]] || { cleanup_tx_from_key_file || true; TX_REASON=rust_submit_keygen_material_malformed; return 1; }
  TX_HEX="$(bounded_mesh "${argv[@]}")" || status=$?
  PROPAGATION_SAMPLE_START_SECONDS="${SECONDS}"
  cleanup_tx_from_key_file || cleanup_status=$?
  (( cleanup_status == 0 )) || { TX_REASON=rust_submit_keygen_cleanup_failed; return 1; }
  (( status == 0 )) || { [[ ${status} -eq 142 ]] && TX_REASON=rust_submit_txgen_timeout || TX_REASON=rust_submit_txgen_failed; return 1; }
  [[ "${TX_HEX}" =~ ^[0-9a-f]+$ && ${#TX_HEX} -le 20000 && $(( ${#TX_HEX} % 2 )) -eq 0 ]] || { TX_REASON=rust_submit_tx_hex_malformed_or_unbounded; return 1; }
  TX_ID="$(parse_txid)" || { rc=$?; TX_REASON="$(txid_parse_reason "${rc}" rust_submit)"; return 1; }
  capture_tx_rpc_sidecar rust "${RUST_RPC_ADDR}" "/tx_status?txid=${TX_ID}" "${RUST_SUBMIT_STATUS_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason rust_submit_tx_status "${rc}")"; return 1; }
  capture_tx_rpc_sidecar rust "${RUST_RPC_ADDR}" "/get_tx?txid=${TX_ID}" "${RUST_SUBMIT_GET_TX_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason rust_submit_get_tx "${rc}")"; return 1; }
  verify_tx_sidecars rust_submit rust "${RUST_RPC_ADDR}" "${TX_ID}" "${TX_HEX}" "/tx_status?txid=${TX_ID}" "/get_tx?txid=${TX_ID}" "${RUST_SUBMIT_STATUS_JSON}" "${RUST_SUBMIT_GET_TX_JSON}" || { rc=$?; TX_REASON="$(tx_sidecar_reason rust_submit "${rc}")"; return 1; }
}
wait_rust_accept() {
  local deadline rc=0 last_retry_reason="" start_seconds="${PROPAGATION_SAMPLE_START_SECONDS:-${SECONDS}}"
  TX_REASON=""
  deadline=$((SECONDS + MESH_TIMEOUT))
  while (( SECONDS < deadline )); do
    if capture_tx_rpc_sidecar rust "${RUST_RPC_ADDR}" "/tx_status?txid=${TX_ID}" "${RUST_STATUS_JSON}"; then
      if capture_tx_rpc_sidecar rust "${RUST_RPC_ADDR}" "/get_tx?txid=${TX_ID}" "${RUST_GET_TX_JSON}"; then
        if verify_tx_sidecars rust_accept rust "${RUST_RPC_ADDR}" "${TX_ID}" "${TX_HEX}" "/tx_status?txid=${TX_ID}" "/get_tx?txid=${TX_ID}" "${RUST_STATUS_JSON}" "${RUST_GET_TX_JSON}" >/dev/null 2>&1; then
          PROPAGATION_SAMPLE_SECONDS=$((SECONDS - start_seconds))
          return 0
        else
          rc=$?
        fi
        case "${rc}" in
          13|14) last_retry_reason="$(tx_sidecar_reason rust_accept "${rc}")" ;;
          *) TX_REASON="$(tx_sidecar_reason rust_accept "${rc}")"; return 1 ;;
        esac
      else rc=$?; TX_REASON="$(tx_capture_reason rust_accept_get_tx "${rc}")"; fi
    else
      rc=$?; TX_REASON="$(tx_capture_reason rust_accept_tx_status "${rc}")"
    fi
    sleep 1
  done
  [[ -n "${last_retry_reason}" ]] && TX_REASON="rust_accept_timeout_last_${last_retry_reason#rust_accept_}" || TX_REASON="${TX_REASON:-rust_accept_pending_timeout}"
  return 1
}
wait_go_accept() {
  local deadline rc=0 last_retry_reason="" start_seconds="${PROPAGATION_SAMPLE_START_SECONDS:-${SECONDS}}"
  TX_REASON=""
  deadline=$((SECONDS + MESH_TIMEOUT))
  while (( SECONDS < deadline )); do
    if capture_tx_rpc_sidecar go "${GO_RPC_ADDR}" "/tx_status?txid=${TX_ID}" "${GO_ACCEPT_STATUS_JSON}"; then
      if capture_tx_rpc_sidecar go "${GO_RPC_ADDR}" "/get_tx?txid=${TX_ID}" "${GO_ACCEPT_GET_TX_JSON}"; then
        if verify_tx_sidecars go_accept go "${GO_RPC_ADDR}" "${TX_ID}" "${TX_HEX}" "/tx_status?txid=${TX_ID}" "/get_tx?txid=${TX_ID}" "${GO_ACCEPT_STATUS_JSON}" "${GO_ACCEPT_GET_TX_JSON}" >/dev/null 2>&1; then
          PROPAGATION_SAMPLE_SECONDS=$((SECONDS - start_seconds))
          return 0
        else
          rc=$?
        fi
        case "${rc}" in
          13|14) last_retry_reason="$(tx_sidecar_reason go_accept "${rc}")" ;;
          *) TX_REASON="$(tx_sidecar_reason go_accept "${rc}")"; return 1 ;;
        esac
      else rc=$?; TX_REASON="$(tx_capture_reason go_accept_get_tx "${rc}")"; fi
    else
      rc=$?; TX_REASON="$(tx_capture_reason go_accept_tx_status "${rc}")"
    fi
    sleep 1
  done
  [[ -n "${last_retry_reason}" ]] && TX_REASON="go_accept_timeout_last_${last_retry_reason#go_accept_}" || TX_REASON="${TX_REASON:-go_accept_pending_timeout}"
  return 1
}
write_block_check_go() {
  cat >"${BLOCK_CHECK_GO}" <<'EOF'
package main
import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)
type blockResp struct {
	Hash string `json:"hash"`
	Height uint64 `json:"height"`
	Canonical bool `json:"canonical"`
	BlockHex string `json:"block_hex"`
}
func die(v any) { fmt.Fprintln(os.Stderr, v); os.Exit(1) }
func main() {
	respPath := flag.String("block-response", "", "")
	txHex := flag.String("tx-hex", "", "")
	txidHex := flag.String("txid", "", "")
	heightRaw := flag.String("height", "", "")
	hashHex := flag.String("hash", "", "")
	txCountRaw := flag.String("tx-count", "", "")
	flag.Parse()
	wantHeight, err := strconv.ParseUint(*heightRaw, 10, 64); if err != nil { die("bad height") }
	wantTxCount, err := strconv.ParseUint(*txCountRaw, 10, 64); if err != nil { die("bad tx_count") }
	raw, err := os.ReadFile(*respPath); if err != nil { die("read block response: " + err.Error()) }
	var resp blockResp; if err := json.Unmarshal(raw, &resp); err != nil { die("decode block response: " + err.Error()) }
	if resp.Height != wantHeight || strings.ToLower(resp.Hash) != strings.ToLower(*hashHex) || !resp.Canonical { die("block response height/hash/canonical mismatch") }
	txBytes, err := hex.DecodeString(strings.TrimSpace(*txHex)); if err != nil { die("decode tx_hex: " + err.Error()) }
	_, wantTxid, _, consumed, err := consensus.ParseTx(txBytes); if err != nil || consumed != len(txBytes) { die("parse tx_hex failed") }
	if hex.EncodeToString(wantTxid[:]) != strings.ToLower(*txidHex) { die("tx_hex txid mismatch") }
	blockBytes, err := hex.DecodeString(strings.TrimSpace(resp.BlockHex)); if err != nil { die("decode block_hex: " + err.Error()) }
	pb, err := consensus.ParseBlockBytes(blockBytes); if err != nil { die("parse block_hex failed: " + err.Error()) }
	gotHash, err := consensus.BlockHash(pb.HeaderBytes); if err != nil || hex.EncodeToString(gotHash[:]) != strings.ToLower(*hashHex) { die("parsed block hash mismatch") }
	if pb.TxCount != wantTxCount { die("parsed block tx_count mismatch") }
	if _, err := consensus.ValidateBlockBasicAtHeight(blockBytes, nil, nil, wantHeight); err != nil { die("basic block validation failed: " + err.Error()) }
	for i, got := range pb.Txids { if i > 0 && got == wantTxid { return } }
	die("submitted txid missing from parsed block txids")
}
EOF
}
block_inclusion_failure_reason() {
  local label="$1" output="$2"
  case "${output}" in
    *"read block response:"*) printf '%s\n' "${label}_block_response_read_failed" ;;
    *"decode block response:"*) printf '%s\n' "${label}_block_response_malformed_json" ;;
    *"block response height/hash/canonical mismatch"*) printf '%s\n' "${label}_block_sidecar_mismatch" ;;
    *"decode tx_hex:"*|*"parse tx_hex failed"*) printf '%s\n' "${label}_tx_hex_parse_failed" ;;
    *"tx_hex txid mismatch"*) printf '%s\n' "${label}_txid_mismatch" ;;
    *"decode block_hex:"*|*"parse block_hex failed:"*) printf '%s\n' "${label}_block_hex_parse_failed" ;;
    *"parsed block hash mismatch"*) printf '%s\n' "${label}_block_hash_mismatch" ;;
    *"parsed block tx_count mismatch"*) printf '%s\n' "${label}_block_tx_count_mismatch" ;;
    *"basic block validation failed:"*) printf '%s\n' "${label}_block_basic_validation_failed" ;;
    *"submitted txid missing from parsed block txids"*) printf '%s\n' "${label}_block_missing_submitted_txid" ;;
    *) printf '%s\n' "${label}_inclusion_failed" ;;
  esac
}
verify_block_inclusion() {
  local label="$1" block_path="$2" height="$3" block_hash="$4" tx_count="$5" output
  [[ -s "${BLOCK_CHECK_GO}" ]] || write_block_check_go || { TX_REASON="${label}_block_check_write_failed"; return 1; }
  output="$(bounded_mesh /usr/bin/env RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${BLOCK_CHECK_GO}" --block-response "${block_path}" --tx-hex "${TX_HEX}" --txid "${TX_ID}" --height "${height}" --hash "${block_hash}" --tx-count "${tx_count}" 2>&1)" || {
    local status=$?
    printf '%s\n' "${label} inclusion check failed: ${output}" >&2
    if [[ "${status}" -eq 142 ]]; then
      TX_REASON="${label}_inclusion_timeout"
    else
      TX_REASON="$(block_inclusion_failure_reason "${label}" "${output}")"
    fi
    return 1
  }
}
parse_mine_next_response() {
  python3 - "$1" <<'PY'
import json, re, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError, UnicodeDecodeError):
    sys.exit(13)
if not isinstance(data, dict):
    sys.exit(13)
height, block_hash, tx_count = data.get("height"), data.get("block_hash"), data.get("tx_count")
if data.get("mined") is not True:
    sys.exit(14)
if not isinstance(height, int) or isinstance(height, bool) or height < 1:
    sys.exit(13)
if not isinstance(block_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", block_hash):
    sys.exit(13)
if not isinstance(tx_count, int) or isinstance(tx_count, bool) or tx_count < 2:
    sys.exit(16)
print(height, block_hash, tx_count, sep="\t")
PY
}
parse_restart_mine_next_response() {
  python3 - "$1" <<'PY'
import json, re, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError, UnicodeDecodeError):
    sys.exit(13)
if not isinstance(data, dict) or data.get("mined") is not True:
    sys.exit(14)
height = data.get("height")
block_hash = data.get("block_hash")
tx_count = data.get("tx_count")
if not isinstance(height, int) or isinstance(height, bool) or height < 0:
    sys.exit(13)
if not isinstance(block_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", block_hash):
    sys.exit(13)
if not isinstance(tx_count, int) or isinstance(tx_count, bool) or tx_count < 1:
    sys.exit(16)
print(height, block_hash, tx_count, sep="\t")
PY
}
mine_next_http_error_reason() {
  local label="${2:-rust_mine}"
  python3 - "$1" "${label}" <<'PY'
import json
import sys
label = sys.argv[2]
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError, UnicodeDecodeError):
    print(f"{label}_http_error_body_malformed")
    sys.exit(0)
if not isinstance(data, dict):
    print(f"{label}_http_error_body_malformed")
    sys.exit(0)
err = data.get("error")
if not isinstance(err, str) or not err:
    print(f"{label}_http_error")
elif err == "live mining unavailable":
    print(f"{label}_live_mining_unavailable")
elif err == "rpc unavailable":
    print(f"{label}_rpc_unavailable")
elif err == "sync engine unavailable":
    print(f"{label}_sync_unavailable")
elif err == "tx pool unavailable":
    print(f"{label}_tx_pool_unavailable")
elif err == "POST required":
    print(f"{label}_method_rejected")
else:
    print(f"{label}_rejected")
PY
}
rust_mine_including_tx() {
  local parsed rc=0
  TX_REASON=""
  capture_rpc_sidecar rust POST "${RUST_RPC_ADDR}" /mine_next "${RUST_MINE_JSON}" preserve-http-error || {
    rc=$?
    if [[ "${rc}" -eq 21 ]]; then
      TX_REASON="$(mine_next_http_error_reason "${RUST_MINE_JSON}.raw")"
      rm -f -- "${RUST_MINE_JSON}.raw"
    else
      TX_REASON="$(tx_capture_reason rust_mine "${rc}")"
    fi
    return 1
  }
  parsed="$(parse_mine_next_response "${RUST_MINE_JSON}")" || { rc=$?; case "${rc}" in 13) TX_REASON=rust_mine_malformed_rpc_body ;; 14) TX_REASON=rust_mine_unavailable ;; 16) TX_REASON=rust_mine_tx_count_invalid ;; *) TX_REASON=rust_mine_unknown_failure ;; esac; return 1; }
  IFS=$'\t' read -r RUST_MINE_HEIGHT RUST_MINE_HASH RUST_MINE_TX_COUNT <<<"${parsed}" || { TX_REASON=rust_mine_malformed_rpc_body; return 1; }
  capture_rpc_sidecar rust GET "${RUST_RPC_ADDR}" "/get_block?height=${RUST_MINE_HEIGHT}" "${RUST_MINE_BLOCK_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason rust_mine_get_block "${rc}")"; return 1; }
  verify_block_inclusion rust_mine "${RUST_MINE_BLOCK_JSON}" "${RUST_MINE_HEIGHT}" "${RUST_MINE_HASH}" "${RUST_MINE_TX_COUNT}"
}
go_mine_including_tx() {
  local parsed rc=0
  TX_REASON=""
  capture_rpc_sidecar go POST "${GO_RPC_ADDR}" /mine_next "${GO_MINE_JSON}" preserve-http-error || {
    rc=$?
    if [[ "${rc}" -eq 21 ]]; then
      TX_REASON="$(mine_next_http_error_reason "${GO_MINE_JSON}.raw" go_mine)"
      rm -f -- "${GO_MINE_JSON}.raw"
    else
      TX_REASON="$(tx_capture_reason go_mine "${rc}")"
    fi
    return 1
  }
  parsed="$(parse_mine_next_response "${GO_MINE_JSON}")" || { rc=$?; case "${rc}" in 13) TX_REASON=go_mine_malformed_rpc_body ;; 14) TX_REASON=go_mine_unavailable ;; 16) TX_REASON=go_mine_tx_count_invalid ;; *) TX_REASON=go_mine_unknown_failure ;; esac; return 1; }
  IFS=$'\t' read -r GO_MINE_HEIGHT GO_MINE_HASH GO_MINE_TX_COUNT <<<"${parsed}" || { TX_REASON=go_mine_malformed_rpc_body; return 1; }
  capture_rpc_sidecar go GET "${GO_RPC_ADDR}" "/get_block?height=${GO_MINE_HEIGHT}" "${GO_MINE_BLOCK_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason go_mine_get_block "${rc}")"; return 1; }
  verify_block_inclusion go_mine "${GO_MINE_BLOCK_JSON}" "${GO_MINE_HEIGHT}" "${GO_MINE_HASH}" "${GO_MINE_TX_COUNT}"
}
tip_matches() {
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys
path, height_raw, block_hash = sys.argv[1:4]
try:
    height = int(height_raw)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
    sys.exit(2)
if not isinstance(data, dict):
    sys.exit(2)
sys.exit(0 if data.get("has_tip") is True and data.get("height") == height and data.get("tip_hash") == block_hash else 1)
PY
}
wait_go_converge_to_rust_mined_block() {
  local deadline tmp rc=0 saw_valid_tip=false start_seconds="${SECONDS}"
  TX_REASON=""
  deadline=$((SECONDS + MESH_TIMEOUT)); tmp="${GO_CONVERGE_TIP_JSON}.tmp"
  while (( SECONDS < deadline )); do
    if capture_rpc_sidecar go GET "${GO_RPC_ADDR}" /get_tip "${tmp}"; then
      if tip_matches "${tmp}" "${RUST_MINE_HEIGHT}" "${RUST_MINE_HASH}"; then
        CONVERGENCE_SAMPLE_SECONDS=$((SECONDS - start_seconds))
        mv -- "${tmp}" "${GO_CONVERGE_TIP_JSON}" || { TX_REASON=go_converge_artifact_write_failed; return 1; }
        capture_rpc_sidecar go GET "${GO_RPC_ADDR}" "/get_block?height=${RUST_MINE_HEIGHT}" "${GO_CONVERGE_BLOCK_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason go_converge_get_block "${rc}")"; return 1; }
        verify_block_inclusion go_converge "${GO_CONVERGE_BLOCK_JSON}" "${RUST_MINE_HEIGHT}" "${RUST_MINE_HASH}" "${RUST_MINE_TX_COUNT}" || return 1
        return 0
      else
        rc=$?
        (( rc == 2 )) && { rm -f -- "${tmp}"; TX_REASON=go_converge_malformed_rpc_body; return 1; }
        saw_valid_tip=true
        TX_REASON=""
      fi
    else
      rc=$?
      [[ "${saw_valid_tip}" == "true" ]] || TX_REASON="$(tx_capture_reason go_converge_tip "${rc}")"
    fi
    sleep 1
  done
  rm -f -- "${tmp}"
  [[ "${saw_valid_tip}" == "true" ]] && TX_REASON=go_converge_timeout || TX_REASON="${TX_REASON:-go_converge_timeout}"
  return 1
}
wait_rust_converge_to_go_mined_block() {
  local deadline tmp rc=0 saw_valid_tip=false start_seconds="${SECONDS}"
  TX_REASON=""
  deadline=$((SECONDS + MESH_TIMEOUT)); tmp="${RUST_CONVERGE_TIP_JSON}.tmp"
  while (( SECONDS < deadline )); do
    if capture_rpc_sidecar rust GET "${RUST_RPC_ADDR}" /get_tip "${tmp}"; then
      if tip_matches "${tmp}" "${GO_MINE_HEIGHT}" "${GO_MINE_HASH}"; then
        CONVERGENCE_SAMPLE_SECONDS=$((SECONDS - start_seconds))
        mv -- "${tmp}" "${RUST_CONVERGE_TIP_JSON}" || { TX_REASON=rust_converge_artifact_write_failed; return 1; }
        capture_rpc_sidecar rust GET "${RUST_RPC_ADDR}" "/get_block?height=${GO_MINE_HEIGHT}" "${RUST_CONVERGE_BLOCK_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason rust_converge_get_block "${rc}")"; return 1; }
        verify_block_inclusion rust_converge "${RUST_CONVERGE_BLOCK_JSON}" "${GO_MINE_HEIGHT}" "${GO_MINE_HASH}" "${GO_MINE_TX_COUNT}" || return 1
        return 0
      else
        rc=$?
        (( rc == 2 )) && { rm -f -- "${tmp}"; TX_REASON=rust_converge_malformed_rpc_body; return 1; }
        saw_valid_tip=true
        TX_REASON=""
      fi
    else
      rc=$?
      [[ "${saw_valid_tip}" == "true" ]] || TX_REASON="$(tx_capture_reason rust_converge_tip "${rc}")"
    fi
    sleep 1
  done
  rm -f -- "${tmp}"
  [[ "${saw_valid_tip}" == "true" ]] && TX_REASON=rust_converge_timeout || TX_REASON="${TX_REASON:-rust_converge_timeout}"
  return 1
}
write_outputs() {
  local verdict="$1" reason="${2:-}"
  export REPORT_JSON LEGACY_SCHEMA_MARKER_JSON verdict reason GO_PID RUST_PID GO_RPC_ADDR RUST_RPC_ADDR \
    GO_P2P_ADDR RUST_P2P_ADDR GO_STARTED_AT_UTC RUST_STARTED_AT_UTC GO_COMM RUST_COMM \
    GO_NODE_BIN RUST_NODE_BIN GO_CMD RUST_CMD GO_ARGV_JSON RUST_ARGV_JSON GO_PEERS_JSON RUST_PEERS_JSON \
    GO_PROCESS_ALIVE RUST_PROCESS_ALIVE GO_RPC_PROCESS_BACKED RUST_RPC_PROCESS_BACKED GO_P2P_PROCESS_BACKED RUST_P2P_PROCESS_BACKED \
    RUST_TO_GO_LOCAL_ADDR FINAL_PROCESS_IDENTITY_RECHECKED FINAL_RUST_OUTBOUND_LINK_RECHECKED FINAL_PEER_SNAPSHOTS_RECHECKED \
    RUBIN_PROCESS_ARTIFACT_ROOT RUST_DIR TX_PATH_MODE TX_ID TX_HEX GO_SUBMIT_STATUS_JSON GO_SUBMIT_GET_TX_JSON RUST_STATUS_JSON RUST_GET_TX_JSON \
    RUST_SUBMIT_STATUS_JSON RUST_SUBMIT_GET_TX_JSON GO_ACCEPT_STATUS_JSON GO_ACCEPT_GET_TX_JSON \
    RUST_MINE_JSON RUST_MINE_BLOCK_JSON GO_CONVERGE_TIP_JSON GO_CONVERGE_BLOCK_JSON RUST_MINE_HEIGHT RUST_MINE_HASH RUST_MINE_TX_COUNT \
    GO_MINE_JSON GO_MINE_BLOCK_JSON RUST_CONVERGE_TIP_JSON RUST_CONVERGE_BLOCK_JSON GO_MINE_HEIGHT GO_MINE_HASH GO_MINE_TX_COUNT \
    PROPAGATION_SAMPLE_SECONDS CONVERGENCE_SAMPLE_SECONDS RUST_RESTART_MODE OLD_RUST_PID OLD_RUST_RPC_ADDR OLD_RUST_P2P_ADDR \
    OLD_RUST_STARTED_AT_UTC OLD_RUST_ARGV_JSON PRE_RESTART_RUST_HEIGHT PRE_RESTART_RUST_TIP PRE_RESTART_RUST_HAS_TIP \
    GO_RESTART_MINE_JSON GO_RESTART_TARGET_TIP_JSON GO_RESTART_TARGET_HEIGHT GO_RESTART_TARGET_TIP GO_RESTART_TARGET_HAS_TIP GO_RESTART_TARGET_TX_COUNT \
    RUST_PRE_RESTART_TIP_JSON RUST_CATCH_UP_TIP_JSON POST_RESTART_RUST_HEIGHT POST_RESTART_RUST_TIP POST_RESTART_RUST_HAS_TIP OLD_RUST_PID_STOPPED \
    RUST_RESTART_SAME_DATADIR RUST_RESTART_PEER_RECONNECTED PARTITION_HEAL_REORG_MODE PARTITION_PROXY_PID PARTITION_PROXY_ADDR \
    PARTITION_PRE_GO_PEER_ADDR PARTITION_HEAL_GO_PEER_ADDR PARTITION_COMMON_HEIGHT PARTITION_COMMON_HASH PARTITION_GO_FORK_HEIGHT PARTITION_GO_FORK_HASH \
    PARTITION_RUST_WIN_HEIGHT PARTITION_RUST_WIN_HASH PARTITION_FINAL_GO_HEIGHT PARTITION_FINAL_GO_HASH PARTITION_FINAL_RUST_HEIGHT PARTITION_FINAL_RUST_HASH \
    PARTITION_REORG_TOTAL PARTITION_REORG_DEPTH PARTITION_PRE_GO_PEERS_JSON PARTITION_PRE_RUST_PEERS_JSON PARTITION_COMMON_GO_MINE_JSON \
    PARTITION_COMMON_GO_BLOCK_JSON PARTITION_COMMON_RUST_TIP_JSON PARTITION_COMMON_RUST_BLOCK_JSON PARTITION_DROP_GO_PEERS_JSON \
    PARTITION_DROP_RUST_PEERS_JSON PARTITION_FORK_GO_PEERS_JSON PARTITION_FORK_RUST_PEERS_JSON PARTITION_GO_MINE_JSON PARTITION_GO_TIP_JSON \
    PARTITION_GO_BLOCK_JSON PARTITION_RUST_MINE1_JSON PARTITION_RUST_MINE2_JSON PARTITION_RUST_TIP_JSON PARTITION_RUST_BLOCK1_JSON \
    PARTITION_RUST_BLOCK2_JSON PARTITION_HEAL_GO_PEERS_JSON PARTITION_HEAL_RUST_PEERS_JSON PARTITION_FINAL_GO_TIP_JSON \
    PARTITION_FINAL_RUST_TIP_JSON PARTITION_GO_REORG_PARENT_BLOCK_JSON PARTITION_FINAL_GO_BLOCK_JSON PARTITION_FINAL_RUST_BLOCK_JSON
  python3 - <<'PY'
import json, os
from datetime import datetime, timezone
from pathlib import Path
e = os.environ
verdict = e["verdict"]
reason = (e.get("reason") or "").strip()
def read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"count": 0, "peers": []}
nodes = []
for impl, name, pid_key, rpc_key, p2p_key, started_key, comm_key, bin_key, cmd_key, argv_key in (
    ("go", "node-go", "GO_PID", "GO_RPC_ADDR", "GO_P2P_ADDR", "GO_STARTED_AT_UTC", "GO_COMM", "GO_NODE_BIN", "GO_CMD", "GO_ARGV_JSON"),
    ("rust", "node-rust", "RUST_PID", "RUST_RPC_ADDR", "RUST_P2P_ADDR", "RUST_STARTED_AT_UTC", "RUST_COMM", "RUST_NODE_BIN", "RUST_CMD", "RUST_ARGV_JSON"),
):
    pid_raw = (e.get(pid_key) or "").strip()
    prefix = impl.upper()
    node = {
        "name": name,
        "implementation": impl,
        "pid": int(pid_raw) if pid_raw.isdigit() else None,
        "command": e.get(cmd_key) or "",
        "command_argv": json.loads(e.get(argv_key) or "[]"),
        "binary": e.get(bin_key) or "",
        "rpc_endpoint": e.get(rpc_key) or None,
        "p2p_endpoint": e.get(p2p_key) or None,
        "started_at": e.get(started_key) or None,
        "process_comm": e.get(comm_key) or None,
        "process_alive": verdict == "PASS" and e.get(f"{prefix}_PROCESS_ALIVE") == "true",
        "rpc_endpoint_process_backed": verdict == "PASS" and e.get(f"{prefix}_RPC_PROCESS_BACKED") == "true",
        "p2p_endpoint_process_backed": verdict == "PASS" and e.get(f"{prefix}_P2P_PROCESS_BACKED") == "true",
    }
    nodes.append(node)
go_snapshot, rust_snapshot = read_json(e["GO_PEERS_JSON"]), read_json(e["RUST_PEERS_JSON"])
tx_path_mode = e.get("TX_PATH_MODE")
tx_mode = tx_path_mode in {"1", "2", "3"}
go_submit_mode = tx_path_mode in {"1", "2"}
rust_submit_mode = tx_path_mode == "3"
converge_mode = tx_path_mode in {"2", "3"}
restart_mode = e.get("RUST_RESTART_MODE") == "1"
partition_mode = e.get("PARTITION_HEAL_REORG_MODE") == "1"
if restart_mode:
    scenario = "mixed_client_rust_restart"
elif partition_mode:
    scenario = "mixed_client_partition_heal_reorg"
elif tx_path_mode == "2":
    scenario = "mixed_client_go_submit_rust_mine_go_converge"
elif tx_path_mode == "3":
    scenario = "mixed_client_rust_submit_go_mine_rust_converge"
elif tx_path_mode == "1":
    scenario = "mixed_client_go_submit_rust_accept"
else:
    scenario = "mixed_client_mesh"
def nonnegative_number(raw):
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    return int(value) if value.is_integer() else value
def sample_bucket(direction, elapsed_raw, sample_kind, txid="", block_hash="", height_raw=""):
    if direction is None:
        return {
            "classification": "not_requested",
            "path_direction": None,
            "reason": f"{sample_kind}_sample_not_requested_by_scenario",
            "samples": [],
            "unit": "seconds",
        }
    elapsed = nonnegative_number(elapsed_raw)
    if elapsed is None:
        return {
            "classification": "no_data",
            "path_direction": direction,
            "reason": f"{sample_kind}_sample_missing_elapsed_seconds",
            "samples": [],
            "unit": "seconds",
        }
    source_impl, target_impl = direction.split("->")
    sample = {
        "classification": "observed",
        "elapsed": elapsed,
        "path_direction": direction,
        "source": f"node-{source_impl}",
        "target": f"node-{target_impl}",
        "tx_id": txid,
        "unit": "seconds",
    }
    if sample_kind == "convergence":
        sample["block_hash"] = block_hash
        sample["height"] = int(height_raw)
    return {
        "classification": "observed",
        "path_direction": direction,
        "reason": None,
        "samples": [sample],
        "unit": "seconds",
    }
def build_raw_samples():
    propagation_direction = None
    convergence_direction = None
    convergence_hash = ""
    convergence_height = ""
    if tx_mode:
        if go_submit_mode:
            propagation_direction = "go->rust"
            if converge_mode:
                convergence_direction = "rust->go"
                convergence_hash = e["RUST_MINE_HASH"]
                convergence_height = e["RUST_MINE_HEIGHT"]
        elif rust_submit_mode:
            propagation_direction = "rust->go"
            if converge_mode:
                convergence_direction = "go->rust"
                convergence_hash = e["GO_MINE_HASH"]
                convergence_height = e["GO_MINE_HEIGHT"]
    return {
        "schema_version": "rubin-devnet-process-soak-raw-samples-v1",
        "semantics": "raw samples only; no SLO threshold or pass claim",
        "propagation": sample_bucket(propagation_direction, e.get("PROPAGATION_SAMPLE_SECONDS"), "propagation", e.get("TX_ID", "")),
        "convergence": sample_bucket(convergence_direction, e.get("CONVERGENCE_SAMPLE_SECONDS"), "convergence", e.get("TX_ID", ""), convergence_hash, convergence_height),
    }
if partition_mode:
    peer_connectivity = {
        "go_to_rust": False,
        "rust_to_go": False,
        "bidirectional_observed": False,
        "counterpart_links": {"go_peer_snapshot_expected_addr": None, "rust_peer_snapshot_expected_addr": None, "rust_outbound_local_addr": None, "rust_outbound_remote_addr": None, "rust_outbound_pid": None},
        "go_peer_snapshot": go_snapshot,
        "rust_peer_snapshot": rust_snapshot,
    }
    final_verification = {"producer_side": verdict == "PASS", "process_identity_rechecked": e.get("FINAL_PROCESS_IDENTITY_RECHECKED") == "true", "rust_outbound_link_rechecked": False, "peer_snapshots_rechecked": e.get("FINAL_PEER_SNAPSHOTS_RECHECKED") == "true", "rust_outbound_pid": None, "rust_outbound_local_addr": None, "rust_outbound_remote_addr": None}
else:
    peer_connectivity = {
        "go_to_rust": verdict == "PASS",
        "rust_to_go": verdict == "PASS",
        "bidirectional_observed": verdict == "PASS",
        "counterpart_links": {"go_peer_snapshot_expected_addr": e.get("RUST_TO_GO_LOCAL_ADDR") or None, "rust_peer_snapshot_expected_addr": e.get("GO_P2P_ADDR") or None, "rust_outbound_local_addr": e.get("RUST_TO_GO_LOCAL_ADDR") or None, "rust_outbound_remote_addr": e.get("GO_P2P_ADDR") or None, "rust_outbound_pid": int(e["RUST_PID"]) if e.get("RUST_PID", "").isdigit() else None},
        "go_peer_snapshot": go_snapshot,
        "rust_peer_snapshot": rust_snapshot,
    }
    final_verification = {"producer_side": verdict == "PASS", "process_identity_rechecked": e.get("FINAL_PROCESS_IDENTITY_RECHECKED") == "true", "rust_outbound_link_rechecked": e.get("FINAL_RUST_OUTBOUND_LINK_RECHECKED") == "true", "peer_snapshots_rechecked": e.get("FINAL_PEER_SNAPSHOTS_RECHECKED") == "true", "rust_outbound_pid": int(e["RUST_PID"]) if e.get("RUST_PID", "").isdigit() else None, "rust_outbound_local_addr": e.get("RUST_TO_GO_LOCAL_ADDR") or None, "rust_outbound_remote_addr": e.get("GO_P2P_ADDR") or None}
if restart_mode:
    legacy_purpose = "schema-valid legacy artifact only; not the Rust restart report verdict"
    legacy_reason = "existing mixed_client_evidence_v1 PASS requires tx_path; Rust restart PASS lives in this report"
elif partition_mode:
    legacy_purpose = "schema-valid legacy artifact only; not the partition/heal/reorg report verdict"
    legacy_reason = "existing mixed_client_evidence_v1 PASS requires tx_path; partition/heal/reorg PASS lives in this report"
else:
    legacy_purpose = "schema-valid legacy artifact only; not the mesh report verdict"
    legacy_reason = "existing mixed_client_evidence_v1 PASS requires tx_path; mesh process/connectivity PASS lives in this report"
report = {
    **({"artifact_created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "run_id": Path(e["RUBIN_PROCESS_ARTIFACT_ROOT"]).name} if restart_mode or partition_mode else {}),
    "scenario": scenario,
    "verdict": verdict,
    "artifact_root": e["RUBIN_PROCESS_ARTIFACT_ROOT"],
    "nodes": nodes,
    "peer_connectivity": peer_connectivity,
    "raw_samples": build_raw_samples(),
    "final_verification": final_verification,
    "legacy_schema_compatibility": {
        "authoritative": False,
        "marker_path": e["LEGACY_SCHEMA_MARKER_JSON"],
        "purpose": legacy_purpose,
        "reason": legacy_reason,
    },
}
if tx_mode and verdict == "PASS":
    tx_path = {"submitted_at": "node-rust", "observed_at": ["node-go"], "tx_id": e["TX_ID"]} if rust_submit_mode else {"submitted_at": "node-go", "observed_at": ["node-rust"], "tx_id": e["TX_ID"]}
    report["tx_path"] = tx_path
    if go_submit_mode:
        report["go_submit"] = {"txid": e["TX_ID"], "tx_hex": e["TX_HEX"], "rpc_endpoint": e["GO_RPC_ADDR"], "tx_status_path": e["GO_SUBMIT_STATUS_JSON"], "get_tx_path": e["GO_SUBMIT_GET_TX_JSON"]}
        report["rust_accept"] = {"txid": e["TX_ID"], "raw_hex": e["TX_HEX"], "rpc_endpoint": e["RUST_RPC_ADDR"], "tx_status_path": e["RUST_STATUS_JSON"], "get_tx_path": e["RUST_GET_TX_JSON"]}
    else:
        report["rust_submit"] = {"txid": e["TX_ID"], "tx_hex": e["TX_HEX"], "rpc_endpoint": e["RUST_RPC_ADDR"], "tx_status_path": e["RUST_SUBMIT_STATUS_JSON"], "get_tx_path": e["RUST_SUBMIT_GET_TX_JSON"]}
        report["go_accept"] = {"txid": e["TX_ID"], "raw_hex": e["TX_HEX"], "rpc_endpoint": e["GO_RPC_ADDR"], "tx_status_path": e["GO_ACCEPT_STATUS_JSON"], "get_tx_path": e["GO_ACCEPT_GET_TX_JSON"]}
    if tx_path_mode == "2":
        report["rust_mine"] = {"block_hash": e["RUST_MINE_HASH"], "block_path": e["RUST_MINE_BLOCK_JSON"], "class": "mined_included", "height": int(e["RUST_MINE_HEIGHT"]), "mine_next_path": e["RUST_MINE_JSON"], "mined_by": "node-rust", "raw_hex": e["TX_HEX"], "rpc_endpoint": e["RUST_RPC_ADDR"], "tx_count": int(e["RUST_MINE_TX_COUNT"]), "txid": e["TX_ID"]}
        report["go_converge"] = {"block_hash": e["RUST_MINE_HASH"], "block_path": e["GO_CONVERGE_BLOCK_JSON"], "class": "canonical_block_found", "converged_at": "node-go", "height": int(e["RUST_MINE_HEIGHT"]), "raw_hex": e["TX_HEX"], "rpc_endpoint": e["GO_RPC_ADDR"], "tip_path": e["GO_CONVERGE_TIP_JSON"], "txid": e["TX_ID"]}
    elif tx_path_mode == "3":
        report["go_mine"] = {"block_hash": e["GO_MINE_HASH"], "block_path": e["GO_MINE_BLOCK_JSON"], "class": "mined_included", "height": int(e["GO_MINE_HEIGHT"]), "mine_next_path": e["GO_MINE_JSON"], "mined_by": "node-go", "raw_hex": e["TX_HEX"], "rpc_endpoint": e["GO_RPC_ADDR"], "tx_count": int(e["GO_MINE_TX_COUNT"]), "txid": e["TX_ID"]}
        report["rust_converge"] = {"block_hash": e["GO_MINE_HASH"], "block_path": e["RUST_CONVERGE_BLOCK_JSON"], "class": "canonical_block_found", "converged_at": "node-rust", "height": int(e["GO_MINE_HEIGHT"]), "raw_hex": e["TX_HEX"], "rpc_endpoint": e["RUST_RPC_ADDR"], "tip_path": e["RUST_CONVERGE_TIP_JSON"], "txid": e["TX_ID"]}
if restart_mode and verdict == "PASS":
    restart = {
        "stopped_node": "node-rust",
        "pre_restart_height": int(e["PRE_RESTART_RUST_HEIGHT"]),
        "catch_up_height": int(e["POST_RESTART_RUST_HEIGHT"]),
    }
    report["restart"] = restart
    report["rust_restart"] = {
        "datadir": e["RUST_DIR"],
        "old_pid": int(e["OLD_RUST_PID"]),
        "old_rpc_endpoint": e["OLD_RUST_RPC_ADDR"],
        "old_p2p_endpoint": e["OLD_RUST_P2P_ADDR"],
        "old_started_at": e["OLD_RUST_STARTED_AT_UTC"],
        "old_command_argv": json.loads(e.get("OLD_RUST_ARGV_JSON") or "[]"),
        "old_pid_stopped": e.get("OLD_RUST_PID_STOPPED") == "true",
        "new_pid": int(e["RUST_PID"]),
        "new_rpc_endpoint": e["RUST_RPC_ADDR"],
        "new_p2p_endpoint": e["RUST_P2P_ADDR"],
        "new_started_at": e["RUST_STARTED_AT_UTC"],
        "new_command_argv": json.loads(e.get("RUST_ARGV_JSON") or "[]"),
        "pre_restart_height": int(e["PRE_RESTART_RUST_HEIGHT"]),
        "pre_restart_tip": e.get("PRE_RESTART_RUST_TIP") or None,
        "pre_restart_has_tip": e.get("PRE_RESTART_RUST_HAS_TIP") == "true",
        "pre_restart_tip_path": e["RUST_PRE_RESTART_TIP_JSON"],
        "go_target_height": int(e["GO_RESTART_TARGET_HEIGHT"]),
        "go_target_tip": e.get("GO_RESTART_TARGET_TIP") or None,
        "go_target_has_tip": e.get("GO_RESTART_TARGET_HAS_TIP") == "true",
        "go_target_tx_count": int(e["GO_RESTART_TARGET_TX_COUNT"]),
        "go_target_mine_next_path": e["GO_RESTART_MINE_JSON"],
        "go_target_tip_path": e["GO_RESTART_TARGET_TIP_JSON"],
        "catch_up_height": int(e["POST_RESTART_RUST_HEIGHT"]),
        "catch_up_tip": e.get("POST_RESTART_RUST_TIP") or None,
        "catch_up_has_tip": e.get("POST_RESTART_RUST_HAS_TIP") == "true",
        "catch_up_tip_path": e["RUST_CATCH_UP_TIP_JSON"],
        "same_datadir": e.get("RUST_RESTART_SAME_DATADIR") == "true",
        "peer_reconnect_observed": e.get("RUST_RESTART_PEER_RECONNECTED") == "true",
    }
if partition_mode and verdict == "PASS":
    tip = lambda height_key, hash_key: {"height": int(e[height_key]), "hash": e[hash_key]}
    report["proof"] = {
        "partition_proxy_pid": int(e["PARTITION_PROXY_PID"]),
        "partition_proxy_endpoint": e["PARTITION_PROXY_ADDR"],
        "pre_partition_go_peer_addr": e["PARTITION_PRE_GO_PEER_ADDR"],
        "heal_go_peer_addr": e["PARTITION_HEAL_GO_PEER_ADDR"],
        "partition_changed_peer_state": True,
        "fork_diverged": True,
        "heal_restored_peer_state": True,
        "reorg_converged": True,
        "process_identity_rechecked_after_heal": e.get("FINAL_PROCESS_IDENTITY_RECHECKED") == "true",
        "go_reorg_metrics": {
            "rubin_node_reorg_total": int(e["PARTITION_REORG_TOTAL"]),
            "rubin_node_last_reorg_depth": int(e["PARTITION_REORG_DEPTH"]),
        },
        "go_partition_tip": tip("PARTITION_GO_FORK_HEIGHT", "PARTITION_GO_FORK_HASH"),
        "rust_winning_tip": tip("PARTITION_RUST_WIN_HEIGHT", "PARTITION_RUST_WIN_HASH"),
        "final_go_tip": tip("PARTITION_FINAL_GO_HEIGHT", "PARTITION_FINAL_GO_HASH"),
        "final_rust_tip": tip("PARTITION_FINAL_RUST_HEIGHT", "PARTITION_FINAL_RUST_HASH"),
    }
    report["observations"] = {
        "pre_partition": {
            "go_peer_snapshot": e["PARTITION_PRE_GO_PEERS_JSON"],
            "rust_peer_snapshot": e["PARTITION_PRE_RUST_PEERS_JSON"],
            "common_go_mine": e["PARTITION_COMMON_GO_MINE_JSON"],
            "common_go_block": e["PARTITION_COMMON_GO_BLOCK_JSON"],
            "common_rust_tip": e["PARTITION_COMMON_RUST_TIP_JSON"],
            "common_rust_block": e["PARTITION_COMMON_RUST_BLOCK_JSON"],
        },
        "partition": {
            "go_peer_snapshot": e["PARTITION_DROP_GO_PEERS_JSON"],
            "rust_peer_snapshot": e["PARTITION_DROP_RUST_PEERS_JSON"],
        },
        "fork": {
            "go_peer_snapshot": e["PARTITION_FORK_GO_PEERS_JSON"],
            "rust_peer_snapshot": e["PARTITION_FORK_RUST_PEERS_JSON"],
            "go_mine": e["PARTITION_GO_MINE_JSON"],
            "go_tip": e["PARTITION_GO_TIP_JSON"],
            "go_block": e["PARTITION_GO_BLOCK_JSON"],
            "rust_mine_1": e["PARTITION_RUST_MINE1_JSON"],
            "rust_mine_2": e["PARTITION_RUST_MINE2_JSON"],
            "rust_tip": e["PARTITION_RUST_TIP_JSON"],
            "rust_block_1": e["PARTITION_RUST_BLOCK1_JSON"],
            "rust_block_2": e["PARTITION_RUST_BLOCK2_JSON"],
        },
        "heal": {
            "go_peer_snapshot": e["PARTITION_HEAL_GO_PEERS_JSON"],
            "rust_peer_snapshot": e["PARTITION_HEAL_RUST_PEERS_JSON"],
        },
        "reorg": {
            "go_tip": e["PARTITION_FINAL_GO_TIP_JSON"],
            "rust_tip": e["PARTITION_FINAL_RUST_TIP_JSON"],
            "go_reorg_parent_block": e["PARTITION_GO_REORG_PARENT_BLOCK_JSON"],
            "go_tip_block": e["PARTITION_FINAL_GO_BLOCK_JSON"],
            "rust_tip_block": e["PARTITION_FINAL_RUST_BLOCK_JSON"],
        },
    }
if verdict != "PASS":
    report["failure_reason"] = reason or "mixed-client mesh did not produce PASS evidence"
with open(e["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
if verdict != "PASS" and reason:
    legacy_marker_reason = reason
elif restart_mode:
    legacy_marker_reason = "mixed-client Rust restart PASS is recorded in sibling report; existing schema v1 PASS requires tx_path proof owned by RUB-22/RUB-23"
elif partition_mode:
    legacy_marker_reason = "mixed-client partition/heal/reorg PASS is recorded in sibling report; existing schema v1 PASS requires tx_path proof owned by RUB-22/RUB-23"
else:
    legacy_marker_reason = "mixed-client mesh process/connectivity PASS is recorded in sibling report; existing schema v1 PASS requires tx_path proof owned by RUB-22/RUB-23"
legacy_schema_marker = {
    "schema_version": "rubin-mixed-client-devnet-evidence-v1",
    "evidence_type": "mixed_client_process_soak",
    "scenario": "mixed_client_mesh_schema_marker",
    "verdict": "PASS" if tx_mode and verdict == "PASS" else "FAIL",
    "participants": [
        {"name": "node-go", "implementation": "go", **({"endpoint": e["GO_RPC_ADDR"], "started_at": e["GO_STARTED_AT_UTC"]} if e.get("GO_RPC_ADDR") and e.get("GO_STARTED_AT_UTC") else {})},
        {"name": "node-rust", "implementation": "rust", **({"endpoint": e["RUST_RPC_ADDR"], "started_at": e["RUST_STARTED_AT_UTC"]} if e.get("RUST_RPC_ADDR") and e.get("RUST_STARTED_AT_UTC") else {})},
    ],
}
if tx_mode and verdict == "PASS":
    legacy_schema_marker["tx_path"] = tx_path
elif restart_mode and verdict == "PASS":
    legacy_schema_marker["restart"] = restart
    legacy_schema_marker["failure_reason"] = legacy_marker_reason
else:
    legacy_schema_marker["failure_reason"] = legacy_marker_reason
with open(e["LEGACY_SCHEMA_MARKER_JSON"], "w", encoding="utf-8") as f:
    json.dump(legacy_schema_marker, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}
finish_no_data() {
  local reason="$1"
  cleanup_tx_from_key_file || true
  write_outputs "NO_DATA" "${reason}" || { echo "FAIL_REPORT_WRITE_FAILED: ${reason}" >&2; exit 1; }
  run_validator "${LEGACY_SCHEMA_MARKER_JSON}" >&2 || { echo "FAIL_REPORT_VALIDATION_FAILED: ${reason}; report=${REPORT_JSON} legacy_schema_marker=${LEGACY_SCHEMA_MARKER_JSON}" >&2; exit 1; }
  echo "NO_DATA: ${reason}; report=${REPORT_JSON} legacy_schema_marker=${LEGACY_SCHEMA_MARKER_JSON}" >&2
  exit 1
}
wait_peer_snapshot() {
  local label="$1" addr="$2" out="$3" timeout="$4" expected="$5" deadline tmp
  deadline=$((SECONDS + timeout)); PEER_SNAPSHOT_REASON=""
  tmp="${out}.tmp"
  while (( SECONDS < deadline )); do
    if rpc_json GET "${addr}" /peers >"${tmp}" 2>"${tmp}.err"; then
      PEER_SNAPSHOT_REASON=""
      if python3 - "${tmp}" "${expected}" <<'PY' >/dev/null 2>&1
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    try:
        data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        sys.exit(4)
if not isinstance(data, dict):
    sys.exit(5)
expected, peers, count = sys.argv[2], data.get("peers"), data.get("count")
def ep(v): return isinstance(v, str) and v.count(":") == 1 and v.startswith("127.0.0.1:") and (p := v.rsplit(":", 1)[-1]).isdigit() and 1 <= len(p) <= 5 and 1 <= int(p) <= 65535
shape = isinstance(count, int) and not isinstance(count, bool) and isinstance(peers, list) and count == len(peers) and all(isinstance(p, dict) and ep(p.get("addr")) and isinstance(p.get("handshake_complete"), bool) for p in peers) and len({p.get("addr") for p in peers}) == len(peers)
has_expected_complete = isinstance(peers, list) and any(isinstance(p, dict) and p.get("addr") == expected and p.get("handshake_complete") is True for p in peers)
has_expected_incomplete = isinstance(peers, list) and any(isinstance(p, dict) and p.get("addr") == expected and p.get("handshake_complete") is False for p in peers)
sys.exit(0 if shape and has_expected_complete and count == 1 else 3 if shape and has_expected_complete else 5 if not shape else 6 if has_expected_incomplete else 7)
PY
      then mv -- "${tmp}" "${out}" || { PEER_SNAPSHOT_REASON=peer_snapshot_artifact_write_failed; rm -f -- "${tmp}" "${tmp}.err"; return 1; }; return 0
      else rc=$?; [[ ${rc} -eq 3 ]] && PEER_SNAPSHOT_REASON=unexpected_peer_snapshot_peer; [[ ${rc} -eq 4 ]] && PEER_SNAPSHOT_REASON=peer_snapshot_malformed_json; [[ ${rc} -eq 5 ]] && PEER_SNAPSHOT_REASON=peer_snapshot_invalid_shape; [[ ${rc} -eq 6 ]] && PEER_SNAPSHOT_REASON=peer_snapshot_handshake_incomplete; [[ ${rc} -eq 7 ]] && PEER_SNAPSHOT_REASON=peer_snapshot_expected_peer_absent; fi
    else rc=$?; [[ ${rc} -eq 23 ]] && PEER_SNAPSHOT_REASON=peer_snapshot_malformed_json || PEER_SNAPSHOT_REASON=peer_snapshot_rpc_failed; fi
    sleep 1
  done
  if [[ "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_rpc_failed || -s "${tmp}.err" ]]; then PEER_SNAPSHOT_REASON=peer_snapshot_rpc_failed; elif [[ "${PEER_SNAPSHOT_REASON:-}" == unexpected_peer_snapshot_peer || "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_malformed_json || "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_invalid_shape || "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_handshake_incomplete || "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_expected_peer_absent ]]; then :; elif [[ -s "${tmp}" ]] && ! python3 -m json.tool "${tmp}" >/dev/null 2>&1; then PEER_SNAPSHOT_REASON=peer_snapshot_malformed_json; else PEER_SNAPSHOT_REASON="${label}_peer_snapshot_missing_endpoint"; fi
  rm -f -- "${tmp}" "${tmp}.err"
  echo "timeout waiting for ${label} /peers completed handshake: ${PEER_SNAPSHOT_REASON}" >&2
  return 1
}
wait_rust_to_go_link() {
  local missing="$1" ambiguous="$2" deadline raw out status err_file err
  deadline=$((SECONDS + MESH_TIMEOUT)); err_file="${RUBIN_PROCESS_ARTIFACT_ROOT}/lsof-established.err"
  while (( SECONDS < deadline )); do
    status=0; raw="$(bounded lsof -nP -a -p "${RUST_PID}" -iTCP -sTCP:ESTABLISHED -Fn 2>"${err_file}")" || status=$?; err="$(<"${err_file}")"
    (( status == 142 )) && finish_no_data "lsof_timeout"; (( status == 0 || (${#raw} == 0 && ${#err} == 0) )) || finish_no_data "lsof_failed"
    out="$(REMOTE_ADDR="${GO_P2P_ADDR}" perl -ne 'BEGIN{$r=$ENV{REMOTE_ADDR}} chomp; s/^n// or next; print "$1\n" if /^(127[.]0[.]0[.]1:[0-9]+)->\Q$r\E$/' <<<"${raw}")" || finish_no_data "perl_failed"
    out="$(sort -u <<<"${out}")" || finish_no_data "sort_failed"
    [[ "${out}" != *$'\n'* ]] || finish_no_data "${ambiguous}"; [[ -z "${out}" ]] || { RUST_TO_GO_LOCAL_ADDR="${out}"; return 0; }
    sleep 1
  done; finish_no_data "${missing}"
}
verify_process_identity() {
  local label="$1" impl="$2" pid="$3" rpc_addr="$4" p2p_addr="$5" expected_comm="$6" reason_prefix="$7" comm rc
  PROCESS_IDENTITY_REASON=""
  rubin_process_is_alive "${pid}" || { PROCESS_IDENTITY_REASON="${reason_prefix}_process_not_alive"; echo "${label} pid is not alive: ${pid}" >&2; return 1; }
  comm="$(pid_comm "${pid}")" || { rc=$?; case "${rc}" in 2) PROCESS_IDENTITY_REASON="${reason_prefix}_ps_failed" ;; 3) PROCESS_IDENTITY_REASON="${reason_prefix}_ps_timeout" ;; 4) PROCESS_IDENTITY_REASON="${reason_prefix}_sed_failed" ;; *) PROCESS_IDENTITY_REASON="${reason_prefix}_comm_unavailable" ;; esac; echo "${label} process comm unavailable: ${pid}" >&2; return 1; }
  [[ "${comm}" == "${expected_comm}" ]] || { PROCESS_IDENTITY_REASON="${reason_prefix}_comm_mismatch"; echo "${label} process comm=${comm}, want ${expected_comm}" >&2; return 1; }
  pid_listens_on "${pid}" "${rpc_addr}" || { rc=$?; case "${rc}" in 2) PROCESS_IDENTITY_REASON="${reason_prefix}_lsof_failed" ;; 3) PROCESS_IDENTITY_REASON="${reason_prefix}_lsof_timeout" ;; *) PROCESS_IDENTITY_REASON="${reason_prefix}_rpc_endpoint_not_process_backed" ;; esac; echo "${label} rpc endpoint is not process-backed: ${rpc_addr}" >&2; return 1; }
  pid_listens_on "${pid}" "${p2p_addr}" || { rc=$?; case "${rc}" in 2) PROCESS_IDENTITY_REASON="${reason_prefix}_lsof_failed" ;; 3) PROCESS_IDENTITY_REASON="${reason_prefix}_lsof_timeout" ;; *) PROCESS_IDENTITY_REASON="${reason_prefix}_p2p_endpoint_not_process_backed" ;; esac; echo "${label} p2p endpoint is not process-backed: ${p2p_addr}" >&2; return 1; }
  [[ "${impl}" == "go" ]] && { GO_COMM="${comm}"; GO_PROCESS_ALIVE=true; GO_RPC_PROCESS_BACKED=true; GO_P2P_PROCESS_BACKED=true; return 0; }
  [[ "${impl}" == "rust" ]] && { RUST_COMM="${comm}"; RUST_PROCESS_ALIVE=true; RUST_RPC_PROCESS_BACKED=true; RUST_P2P_PROCESS_BACKED=true; return 0; }
  return 1
}
parse_restart_tip_sidecar() {
  python3 - "$1" <<'PY'
import json
import re
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
except (OSError, json.JSONDecodeError, UnicodeDecodeError):
    sys.exit(2)
if not isinstance(data, dict):
    sys.exit(2)
has_tip = data.get("has_tip")
height = data.get("height")
best_known_height = data.get("best_known_height")
tip_hash = data.get("tip_hash")
if not isinstance(has_tip, bool):
    sys.exit(4)
if has_tip:
    if not isinstance(height, int) or isinstance(height, bool) or height < 0:
        sys.exit(3)
    if not isinstance(tip_hash, str) or re.fullmatch(r"[0-9a-f]{64}", tip_hash) is None:
        sys.exit(5)
else:
    sys.exit(6)
print(height, tip_hash, "true" if has_tip else "false", sep="|")
PY
}
restart_tip_reason() {
  local label="$1" rc="$2"
  case "${rc}" in
    2) printf '%s\n' "${label}_tip_malformed_json" ;;
    3) printf '%s\n' "${label}_height_invalid" ;;
    4) printf '%s\n' "${label}_has_tip_invalid" ;;
    5) printf '%s\n' "${label}_tip_hash_invalid" ;;
    6) printf '%s\n' "${label}_tip_absent" ;;
    *) printf '%s\n' "${label}_tip_parse_failed" ;;
  esac
}
rust_restart_start_reason() {
  case "${1:-}" in
    rust_launch_failed) printf '%s\n' rust_restart_launch_failed ;;
    rust_p2p_log_wait_failed) printf '%s\n' rust_restart_p2p_log_wait_failed ;;
    rust_rpc_log_wait_failed) printf '%s\n' rust_restart_rpc_log_wait_failed ;;
    rust_p2p_addr_extract_failed) printf '%s\n' rust_restart_p2p_addr_extract_failed ;;
    rust_p2p_addr_malformed) printf '%s\n' rust_restart_p2p_addr_malformed ;;
    rust_rpc_addr_extract_failed) printf '%s\n' rust_restart_rpc_addr_extract_failed ;;
    rust_rpc_addr_malformed) printf '%s\n' rust_restart_rpc_addr_malformed ;;
    rust_rpc_ready_timeout) printf '%s\n' rust_restart_rpc_ready_timeout ;;
    "") printf '%s\n' rust_restart_process_not_ready ;;
    *) printf '%s\n' "rust_restart_${1}" ;;
  esac
}
capture_restart_tip() {
  local label="$1" impl="$2" addr="$3" out="$4" parsed rc=0
  RUST_RESTART_TIP_TSV=""
  capture_rpc_sidecar "${impl}" GET "${addr}" /get_tip "${out}" || { rc=$?; RUST_RESTART_REASON="$(tx_capture_reason "${label}" "${rc}")"; return 1; }
  parsed="$(parse_restart_tip_sidecar "${out}")" || { rc=$?; RUST_RESTART_REASON="$(restart_tip_reason "${label}" "${rc}")"; return 1; }
  RUST_RESTART_TIP_TSV="${parsed}"
}
go_restart_mine_target() {
  local parsed rc=0 target_height target_tip target_has_tip
  RUST_RESTART_REASON=""
  capture_rpc_sidecar go POST "${GO_RPC_ADDR}" /mine_next "${GO_RESTART_MINE_JSON}" preserve-http-error || {
    rc=$?
    if [[ "${rc}" -eq 21 ]]; then
      RUST_RESTART_REASON="$(mine_next_http_error_reason "${GO_RESTART_MINE_JSON}.raw" go_restart_mine)"
      rm -f -- "${GO_RESTART_MINE_JSON}.raw"
    else
      RUST_RESTART_REASON="$(tx_capture_reason go_restart_mine "${rc}")"
    fi
    return 1
  }
  parsed="$(parse_restart_mine_next_response "${GO_RESTART_MINE_JSON}")" || { rc=$?; case "${rc}" in 13) RUST_RESTART_REASON=go_restart_mine_malformed_rpc_body ;; 14) RUST_RESTART_REASON=go_restart_mine_unavailable ;; 16) RUST_RESTART_REASON=go_restart_mine_tx_count_invalid ;; *) RUST_RESTART_REASON=go_restart_mine_unknown_failure ;; esac; return 1; }
  IFS=$'\t' read -r GO_RESTART_TARGET_HEIGHT GO_RESTART_TARGET_TIP GO_RESTART_TARGET_TX_COUNT <<<"${parsed}" || { RUST_RESTART_REASON=go_restart_mine_malformed_rpc_body; return 1; }
  if (( GO_RESTART_TARGET_HEIGHT <= PRE_RESTART_RUST_HEIGHT )); then
    RUST_RESTART_REASON=go_restart_target_not_advanced
    return 1
  fi
  capture_restart_tip go_restart_target go "${GO_RPC_ADDR}" "${GO_RESTART_TARGET_TIP_JSON}" || return 1
  IFS='|' read -r target_height target_tip target_has_tip <<<"${RUST_RESTART_TIP_TSV}" || { RUST_RESTART_REASON=go_restart_target_tip_parse_failed; return 1; }
  if (( target_height != GO_RESTART_TARGET_HEIGHT )) || [[ "${target_tip}" != "${GO_RESTART_TARGET_TIP}" || "${target_has_tip}" != "true" ]]; then
    RUST_RESTART_REASON=go_restart_target_tip_mismatch
    return 1
  fi
  GO_RESTART_TARGET_HAS_TIP="${target_has_tip}"
}
wait_rust_restart_catch_up() {
  local deadline tmp height tip has_tip
  RUST_RESTART_REASON=""
  deadline=$((SECONDS + MESH_TIMEOUT)); tmp="${RUST_CATCH_UP_TIP_JSON}.tmp"
  while (( SECONDS < deadline )); do
    if capture_restart_tip rust_restart_catch_up rust "${RUST_RPC_ADDR}" "${tmp}"; then
      IFS='|' read -r height tip has_tip <<<"${RUST_RESTART_TIP_TSV}" || { RUST_RESTART_REASON=rust_restart_catch_up_tip_parse_failed; rm -f -- "${tmp}"; return 1; }
      if (( height < GO_RESTART_TARGET_HEIGHT )); then
        RUST_RESTART_REASON=rust_restart_catch_up_below_go_target
      elif (( height > GO_RESTART_TARGET_HEIGHT )); then
        RUST_RESTART_REASON=rust_restart_catch_up_above_go_target
        rm -f -- "${tmp}"
        return 1
      elif [[ "${tip}" != "${GO_RESTART_TARGET_TIP}" ]]; then
        RUST_RESTART_REASON=rust_restart_catch_up_tip_mismatch
        rm -f -- "${tmp}"
        return 1
      else
        mv -- "${tmp}" "${RUST_CATCH_UP_TIP_JSON}" || { RUST_RESTART_REASON=rust_restart_catch_up_artifact_write_failed; rm -f -- "${tmp}"; return 1; }
        POST_RESTART_RUST_HEIGHT="${height}"
        POST_RESTART_RUST_TIP="${tip}"
        POST_RESTART_RUST_HAS_TIP="${has_tip}"
        return 0
      fi
    fi
    sleep 1
  done
  rm -f -- "${tmp}"
  RUST_RESTART_REASON="${RUST_RESTART_REASON:-rust_restart_catch_up_timeout}"
  return 1
}
write_partition_proxy() {
  cat >"${PARTITION_PROXY_SCRIPT}" <<'PY'
#!/usr/bin/env python3
import os, select, socket, sys, threading, time

state_path = sys.argv[1]
active = set()
lock = threading.Lock()

def read_target():
    try:
        raw = open(state_path, encoding="utf-8").read().strip()
    except OSError:
        return None
    if raw == "drop":
        return None
    if raw.startswith("allow "):
        host, port = raw.split()[1].rsplit(":", 1)
        return host, int(port)
    return None

def close(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass

def close_all():
    with lock:
        sockets = list(active)
        active.clear()
    for sock in sockets:
        close(sock)

def relay(left, right):
    with lock:
        active.add(left)
        active.add(right)
    try:
        while True:
            readable, _, _ = select.select([left, right], [], [], 0.5)
            for src in readable:
                try:
                    data = src.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                dst = right if src is left else left
                try:
                    dst.sendall(data)
                except OSError:
                    return
    finally:
        with lock:
            active.discard(left)
            active.discard(right)
        close(left)
        close(right)

def watcher():
    previous = object()
    while True:
        current = read_target()
        if current != previous:
            close_all()
            previous = current
        time.sleep(0.2)

listener = socket.create_server(("127.0.0.1", 0), reuse_port=False)
listener.listen()
host, port = listener.getsockname()
print(f"partition-proxy: listening={host}:{port}", flush=True)
threading.Thread(target=watcher, daemon=True).start()
while True:
    client, _ = listener.accept()
    target = read_target()
    if target is None:
        close(client)
        continue
    try:
        upstream = socket.create_connection(target, timeout=5)
    except OSError:
        close(client)
        continue
    threading.Thread(target=relay, args=(client, upstream), daemon=True).start()
PY
  chmod 700 "${PARTITION_PROXY_SCRIPT}"
}
set_partition_proxy_state() {
  case "${1:-}" in
    allow) printf 'allow %s\n' "${GO_P2P_ADDR}" >"${PARTITION_PROXY_STATE}" ;;
    drop) printf 'drop\n' >"${PARTITION_PROXY_STATE}" ;;
    *) return 1 ;;
  esac
}
start_partition_proxy() {
  PARTITION_REASON=""
  write_partition_proxy || { PARTITION_REASON=partition_proxy_script_write_failed; return 1; }
  set_partition_proxy_state allow || { PARTITION_REASON=partition_proxy_state_write_failed; return 1; }
  rubin_process_start "${PARTITION_PROXY_LOG}" python3 -u "${PARTITION_PROXY_SCRIPT}" "${PARTITION_PROXY_STATE}" || { PARTITION_REASON=partition_proxy_launch_failed; return 1; }
  PARTITION_PROXY_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${PARTITION_PROXY_LOG}" "partition-proxy: listening=" 30 "${PARTITION_PROXY_PID}" || { PARTITION_REASON=partition_proxy_log_wait_failed; return 1; }
  PARTITION_PROXY_ADDR="$(extract_log_addr "${PARTITION_PROXY_LOG}" "partition-proxy: listening=")" || { PARTITION_REASON=partition_proxy_addr_extract_failed; return 1; }
  loopback_endpoint "${PARTITION_PROXY_ADDR}" || { PARTITION_REASON=partition_proxy_addr_malformed; return 1; }
  RUST_BOOTSTRAP_PEER_ADDR="${PARTITION_PROXY_ADDR}"
}
proxy_go_local_addr() {
  local missing="$1" ambiguous="$2" deadline raw out status err_file err
  deadline=$((SECONDS + MESH_TIMEOUT)); err_file="${RUBIN_PROCESS_ARTIFACT_ROOT}/lsof-partition-proxy-established.err"
  while (( SECONDS < deadline )); do
    status=0; raw="$(bounded lsof -nP -a -p "${PARTITION_PROXY_PID}" -iTCP -sTCP:ESTABLISHED -Fn 2>"${err_file}")" || status=$?; err="$(<"${err_file}")"
    (( status == 142 )) && finish_no_data "lsof_timeout"; (( status == 0 || (${#raw} == 0 && ${#err} == 0) )) || finish_no_data "lsof_failed"
    out="$(REMOTE_ADDR="${GO_P2P_ADDR}" perl -ne 'BEGIN{$r=$ENV{REMOTE_ADDR}} chomp; s/^n// or next; print "$1\n" if /^(127[.]0[.]0[.]1:[0-9]+)->\Q$r\E$/' <<<"${raw}")" || finish_no_data "perl_failed"
    out="$(sort -u <<<"${out}")" || finish_no_data "sort_failed"
    [[ "${out}" != *$'\n'* ]] || finish_no_data "${ambiguous}"
    [[ -z "${out}" ]] || { printf '%s\n' "${out}"; return 0; }
    sleep 1
  done
  finish_no_data "${missing}"
}
wait_peer_snapshot_state() {
  local label="$1" addr="$2" out="$3" timeout="$4" expected="${5:-}" want="${6:-connected}" deadline tmp
  deadline=$((SECONDS + timeout)); tmp="${out}.tmp"; PEER_SNAPSHOT_REASON=""
  while (( SECONDS < deadline )); do
    if rpc_json GET "${addr}" /peers >"${tmp}" 2>"${tmp}.err"; then
      if python3 - "${tmp}" "${expected}" "${want}" <<'PY' >/dev/null 2>&1
import json, sys
path, expected, want = sys.argv[1:4]
try:
    data = json.load(open(path, encoding="utf-8"))
except (OSError, json.JSONDecodeError, UnicodeDecodeError):
    sys.exit(4)
peers, count = data.get("peers"), data.get("count")
def ep(v): return isinstance(v, str) and v.startswith("127.0.0.1:") and (p := v.rsplit(":", 1)[-1]).isdigit() and 1 <= int(p) <= 65535
if not isinstance(count, int) or isinstance(count, bool) or not isinstance(peers, list) or count != len(peers) or not all(isinstance(p, dict) and ep(p.get("addr")) and isinstance(p.get("handshake_complete"), bool) for p in peers) or len({p.get("addr") for p in peers}) != len(peers):
    sys.exit(5)
complete = [p["addr"] for p in peers if p.get("handshake_complete") is True]
if want == "empty":
    sys.exit(0 if count == 0 and complete == [] else 6)
sys.exit(0 if count == 1 and complete == [expected] else 7)
PY
      then mv -- "${tmp}" "${out}" || { PEER_SNAPSHOT_REASON=peer_snapshot_artifact_write_failed; rm -f -- "${tmp}" "${tmp}.err"; return 1; }; return 0
      else rc=$?; [[ ${rc} -eq 4 ]] && PEER_SNAPSHOT_REASON=peer_snapshot_malformed_json; [[ ${rc} -eq 5 ]] && PEER_SNAPSHOT_REASON=peer_snapshot_invalid_shape; [[ ${rc} -eq 6 ]] && PEER_SNAPSHOT_REASON=peer_snapshot_not_empty; [[ ${rc} -eq 7 ]] && PEER_SNAPSHOT_REASON=peer_snapshot_expected_peer_absent; fi
    else rc=$?; [[ ${rc} -eq 23 ]] && PEER_SNAPSHOT_REASON=peer_snapshot_malformed_json || PEER_SNAPSHOT_REASON=peer_snapshot_rpc_failed; fi
    sleep 1
  done
  rm -f -- "${tmp}" "${tmp}.err"
  PEER_SNAPSHOT_REASON="${PEER_SNAPSHOT_REASON:-${label}_peer_snapshot_timeout}"
  echo "timeout waiting for ${label} /peers ${want}: ${PEER_SNAPSHOT_REASON}" >&2
  return 1
}
parse_partition_mine_result() { parse_restart_mine_next_response "$1"; }
partition_capture_tip() {
  local label="$1" impl="$2" addr="$3" out="$4" parsed rc=0
  capture_rpc_sidecar "${impl}" GET "${addr}" /get_tip "${out}" || { rc=$?; PARTITION_REASON="$(tx_capture_reason "${label}" "${rc}")"; return 1; }
  parsed="$(parse_restart_tip_sidecar "${out}")" || { rc=$?; PARTITION_REASON="$(restart_tip_reason "${label}" "${rc}")"; return 1; }
  printf '%s\n' "${parsed}"
}
partition_mine() {
  local label="$1" impl="$2" addr="$3" mine_out="$4" block_out="$5" parsed rc=0 height block_hash tx_count
  capture_rpc_sidecar "${impl}" POST "${addr}" /mine_next "${mine_out}" preserve-http-error || { rc=$?; [[ "${rc}" -eq 21 ]] && PARTITION_REASON="$(mine_next_http_error_reason "${mine_out}.raw" "${label}")" || PARTITION_REASON="$(tx_capture_reason "${label}" "${rc}")"; rm -f -- "${mine_out}.raw"; return 1; }
  parsed="$(parse_partition_mine_result "${mine_out}")" || { rc=$?; case "${rc}" in 13) PARTITION_REASON="${label}_malformed_rpc_body" ;; 14) PARTITION_REASON="${label}_unavailable" ;; 16) PARTITION_REASON="${label}_tx_count_invalid" ;; *) PARTITION_REASON="${label}_unknown_failure" ;; esac; return 1; }
  IFS=$'\t' read -r height block_hash tx_count <<<"${parsed}" || { PARTITION_REASON="${label}_malformed_rpc_body"; return 1; }
  capture_rpc_sidecar "${impl}" GET "${addr}" "/get_block?height=${height}" "${block_out}" || { rc=$?; PARTITION_REASON="$(tx_capture_reason "${label}_get_block" "${rc}")"; return 1; }
  printf '%s\t%s\t%s\n' "${height}" "${block_hash}" "${tx_count}"
}
wait_tip_to_match() {
  local label="$1" impl="$2" addr="$3" height="$4" block_hash="$5" out="$6" deadline tmp
  deadline=$((SECONDS + MESH_TIMEOUT)); tmp="${out}.tmp"; PARTITION_REASON=""
  while (( SECONDS < deadline )); do
    if partition_capture_tip "${label}" "${impl}" "${addr}" "${tmp}" >/dev/null; then
      if tip_matches "${tmp}" "${height}" "${block_hash}"; then
        mv -- "${tmp}" "${out}" || { PARTITION_REASON="${label}_artifact_write_failed"; rm -f -- "${tmp}"; return 1; }
        return 0
      fi
    fi
    sleep 1
  done
  rm -f -- "${tmp}"
  PARTITION_REASON="${label}_timeout"
  return 1
}
capture_go_reorg_metrics() {
  local metrics_file="${RUBIN_PROCESS_ARTIFACT_ROOT}/partition-go-metrics.prom"
  rpc_json GET "${GO_RPC_ADDR}" /metrics >"${metrics_file}" || { PARTITION_REASON=partition_go_metrics_rpc_failed; return 1; }
  python3 - "${metrics_file}" <<'PY'
import re, sys
vals = {}
for raw in open(sys.argv[1], encoding="utf-8"):
    m = re.fullmatch(r"(rubin_node_reorg_total|rubin_node_last_reorg_depth)\s+([0-9]+)(?:\.0*)?\s*", raw.strip())
    if m:
        vals[m.group(1)] = int(m.group(2))
if vals.get("rubin_node_reorg_total", 0) < 1 or vals.get("rubin_node_last_reorg_depth", 0) < 1:
    sys.exit(1)
print(vals["rubin_node_reorg_total"], vals["rubin_node_last_reorg_depth"], sep="\t")
PY
}
run_partition_heal_reorg_scenario() {
  local parsed
  PARTITION_REASON=""
  wait_peer_snapshot_state node-rust-pre-partition "${RUST_RPC_ADDR}" "${PARTITION_PRE_RUST_PEERS_JSON}" "${MESH_TIMEOUT}" "${PARTITION_PROXY_ADDR}" connected || { PARTITION_REASON="${PEER_SNAPSHOT_REASON:-partition_pre_rust_peer_missing_proxy}"; return 1; }
  PARTITION_PRE_GO_PEER_ADDR="$(proxy_go_local_addr partition_pre_proxy_to_go_missing partition_pre_proxy_to_go_ambiguous)" || return 1
  wait_peer_snapshot_state node-go-pre-partition "${GO_RPC_ADDR}" "${PARTITION_PRE_GO_PEERS_JSON}" "${MESH_TIMEOUT}" "${PARTITION_PRE_GO_PEER_ADDR}" connected || { PARTITION_REASON="${PEER_SNAPSHOT_REASON:-partition_pre_go_peer_missing_proxy}"; return 1; }
  parsed="$(partition_mine partition_common_go_mine go "${GO_RPC_ADDR}" "${PARTITION_COMMON_GO_MINE_JSON}" "${PARTITION_COMMON_GO_BLOCK_JSON}")" || return 1
  IFS=$'\t' read -r PARTITION_COMMON_HEIGHT PARTITION_COMMON_HASH _ <<<"${parsed}" || { PARTITION_REASON=partition_common_mine_parse_failed; return 1; }
  wait_tip_to_match partition_common_rust_tip rust "${RUST_RPC_ADDR}" "${PARTITION_COMMON_HEIGHT}" "${PARTITION_COMMON_HASH}" "${PARTITION_COMMON_RUST_TIP_JSON}" || return 1
  capture_rpc_sidecar rust GET "${RUST_RPC_ADDR}" "/get_block?height=${PARTITION_COMMON_HEIGHT}" "${PARTITION_COMMON_RUST_BLOCK_JSON}" || { PARTITION_REASON=partition_common_rust_block_capture_failed; return 1; }
  set_partition_proxy_state drop || { PARTITION_REASON=partition_proxy_drop_state_failed; return 1; }
  wait_peer_snapshot_state node-rust-partition "${RUST_RPC_ADDR}" "${PARTITION_DROP_RUST_PEERS_JSON}" "${MESH_TIMEOUT}" "" empty || { PARTITION_REASON="${PEER_SNAPSHOT_REASON:-partition_rust_peer_not_empty}"; return 1; }
  wait_peer_snapshot_state node-go-partition "${GO_RPC_ADDR}" "${PARTITION_DROP_GO_PEERS_JSON}" "${MESH_TIMEOUT}" "" empty || { PARTITION_REASON="${PEER_SNAPSHOT_REASON:-partition_go_peer_not_empty}"; return 1; }
  submit_go_tx || { PARTITION_REASON="${TX_REASON:-partition_go_submit_failed}"; return 1; }
  parsed="$(partition_mine partition_go_mine go "${GO_RPC_ADDR}" "${PARTITION_GO_MINE_JSON}" "${PARTITION_GO_BLOCK_JSON}")" || return 1
  IFS=$'\t' read -r PARTITION_GO_FORK_HEIGHT PARTITION_GO_FORK_HASH _ <<<"${parsed}" || { PARTITION_REASON=partition_go_mine_parse_failed; return 1; }
  wait_tip_to_match partition_go_tip go "${GO_RPC_ADDR}" "${PARTITION_GO_FORK_HEIGHT}" "${PARTITION_GO_FORK_HASH}" "${PARTITION_GO_TIP_JSON}" || return 1
  parsed="$(partition_mine partition_rust_mine_1 rust "${RUST_RPC_ADDR}" "${PARTITION_RUST_MINE1_JSON}" "${PARTITION_RUST_BLOCK1_JSON}")" || return 1
  IFS=$'\t' read -r PARTITION_RUST_FORK_HEIGHT PARTITION_RUST_FORK_HASH _ <<<"${parsed}" || { PARTITION_REASON=partition_rust_mine_parse_failed; return 1; }
  [[ "${PARTITION_RUST_FORK_HEIGHT}" == "${PARTITION_GO_FORK_HEIGHT}" && "${PARTITION_RUST_FORK_HASH}" != "${PARTITION_GO_FORK_HASH}" ]] || { PARTITION_REASON=partition_fork_not_diverged; return 1; }
  parsed="$(partition_mine partition_rust_mine_2 rust "${RUST_RPC_ADDR}" "${PARTITION_RUST_MINE2_JSON}" "${PARTITION_RUST_BLOCK2_JSON}")" || return 1
  IFS=$'\t' read -r PARTITION_RUST_WIN_HEIGHT PARTITION_RUST_WIN_HASH _ <<<"${parsed}" || { PARTITION_REASON=partition_rust_mine_parse_failed; return 1; }
  (( PARTITION_RUST_WIN_HEIGHT > PARTITION_GO_FORK_HEIGHT )) || { PARTITION_REASON=partition_rust_branch_not_heavier; return 1; }
  wait_tip_to_match partition_rust_tip rust "${RUST_RPC_ADDR}" "${PARTITION_RUST_WIN_HEIGHT}" "${PARTITION_RUST_WIN_HASH}" "${PARTITION_RUST_TIP_JSON}" || return 1
  wait_peer_snapshot_state node-rust-fork "${RUST_RPC_ADDR}" "${PARTITION_FORK_RUST_PEERS_JSON}" "${MESH_TIMEOUT}" "" empty || { PARTITION_REASON="${PEER_SNAPSHOT_REASON:-partition_fork_rust_peer_not_empty}"; return 1; }
  wait_peer_snapshot_state node-go-fork "${GO_RPC_ADDR}" "${PARTITION_FORK_GO_PEERS_JSON}" "${MESH_TIMEOUT}" "" empty || { PARTITION_REASON="${PEER_SNAPSHOT_REASON:-partition_fork_go_peer_not_empty}"; return 1; }
  set_partition_proxy_state allow || { PARTITION_REASON=partition_proxy_heal_state_failed; return 1; }
  wait_peer_snapshot_state node-rust-heal "${RUST_RPC_ADDR}" "${PARTITION_HEAL_RUST_PEERS_JSON}" "${MESH_TIMEOUT}" "${PARTITION_PROXY_ADDR}" connected || { PARTITION_REASON="${PEER_SNAPSHOT_REASON:-partition_heal_rust_peer_missing_proxy}"; return 1; }
  PARTITION_HEAL_GO_PEER_ADDR="$(proxy_go_local_addr partition_heal_proxy_to_go_missing partition_heal_proxy_to_go_ambiguous)" || return 1
  wait_peer_snapshot_state node-go-heal "${GO_RPC_ADDR}" "${PARTITION_HEAL_GO_PEERS_JSON}" "${MESH_TIMEOUT}" "${PARTITION_HEAL_GO_PEER_ADDR}" connected || { PARTITION_REASON="${PEER_SNAPSHOT_REASON:-partition_heal_go_peer_missing_proxy}"; return 1; }
  wait_tip_to_match partition_final_go_tip go "${GO_RPC_ADDR}" "${PARTITION_RUST_WIN_HEIGHT}" "${PARTITION_RUST_WIN_HASH}" "${PARTITION_FINAL_GO_TIP_JSON}" || return 1
  wait_tip_to_match partition_final_rust_tip rust "${RUST_RPC_ADDR}" "${PARTITION_RUST_WIN_HEIGHT}" "${PARTITION_RUST_WIN_HASH}" "${PARTITION_FINAL_RUST_TIP_JSON}" || return 1
  capture_rpc_sidecar go GET "${GO_RPC_ADDR}" "/get_block?height=${PARTITION_RUST_WIN_HEIGHT}" "${PARTITION_FINAL_GO_BLOCK_JSON}" || { PARTITION_REASON=partition_final_go_block_capture_failed; return 1; }
  capture_rpc_sidecar rust GET "${RUST_RPC_ADDR}" "/get_block?height=${PARTITION_RUST_WIN_HEIGHT}" "${PARTITION_FINAL_RUST_BLOCK_JSON}" || { PARTITION_REASON=partition_final_rust_block_capture_failed; return 1; }
  capture_rpc_sidecar go GET "${GO_RPC_ADDR}" "/get_block?height=${PARTITION_RUST_FORK_HEIGHT}" "${PARTITION_GO_REORG_PARENT_BLOCK_JSON}" || { PARTITION_REASON=partition_go_reorg_parent_capture_failed; return 1; }
  parsed="$(capture_go_reorg_metrics)" || return 1
  IFS=$'\t' read -r PARTITION_REORG_TOTAL PARTITION_REORG_DEPTH <<<"${parsed}" || { PARTITION_REASON=partition_go_metrics_parse_failed; return 1; }
  PARTITION_FINAL_GO_HEIGHT="${PARTITION_RUST_WIN_HEIGHT}"; PARTITION_FINAL_GO_HASH="${PARTITION_RUST_WIN_HASH}"
  PARTITION_FINAL_RUST_HEIGHT="${PARTITION_RUST_WIN_HEIGHT}"; PARTITION_FINAL_RUST_HASH="${PARTITION_RUST_WIN_HASH}"
  FINAL_PROCESS_IDENTITY_RECHECKED=true
  FINAL_PEER_SNAPSHOTS_RECHECKED=true
}
start_rust_node_with_log() {
  local rust_log="$1"
  local peer_addr="${RUST_BOOTSTRAP_PEER_ADDR:-${GO_P2P_ADDR}}"
  local -a argv=("${RUST_NODE_BIN}" --network devnet --datadir "${RUST_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --peer "${peer_addr}")
  START_REASON=""
  RUST_CMD="$(argv_cmd "${argv[@]}")"; RUST_ARGV_JSON="$(argv_json "${argv[@]}")"
  rubin_process_start "${rust_log}" "${argv[@]}" || { START_REASON=rust_launch_failed; return 1; }; RUST_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${rust_log}" "p2p: listening=" 60 "${RUST_PID}" || { START_REASON=rust_p2p_log_wait_failed; return 1; }
  rubin_process_wait_for_log "${rust_log}" "rpc: listening=" 60 "${RUST_PID}" || { START_REASON=rust_rpc_log_wait_failed; return 1; }
  RUST_P2P_ADDR="$(extract_log_addr "${rust_log}" "p2p: listening=")" || { START_REASON=rust_p2p_addr_extract_failed; return 1; }; loopback_endpoint "${RUST_P2P_ADDR}" || { START_REASON=rust_p2p_addr_malformed; return 1; }
  RUST_RPC_ADDR="$(rubin_process_extract_rpc_addr "${rust_log}")" || { START_REASON=rust_rpc_addr_extract_failed; return 1; }; loopback_endpoint "${RUST_RPC_ADDR}" || { START_REASON=rust_rpc_addr_malformed; return 1; }
  rubin_process_wait_for_rpc_ready "${RUST_RPC_ADDR}" 30 || { START_REASON=rust_rpc_ready_timeout; return 1; }; RUST_STARTED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
start_rust_node() { start_rust_node_with_log "${RUST_LOG}"; }
clear_current_rust_process_evidence() {
  RUST_PID=""
  RUST_RPC_ADDR=""
  RUST_P2P_ADDR=""
  RUST_STARTED_AT_UTC=""
  RUST_COMM=""
  RUST_CMD=""
  RUST_ARGV_JSON=""
  RUST_TO_GO_LOCAL_ADDR=""
  RUST_PROCESS_ALIVE=false
  RUST_RPC_PROCESS_BACKED=false
  RUST_P2P_PROCESS_BACKED=false
  FINAL_PROCESS_IDENTITY_RECHECKED=""
  FINAL_RUST_OUTBOUND_LINK_RECHECKED=""
  FINAL_PEER_SNAPSHOTS_RECHECKED=""
  rm -f -- "${RUST_PEERS_JSON}" || { RUST_RESTART_REASON=rust_restart_stale_peer_snapshot_cleanup_failed; return 1; }
}
unregister_managed_pid() {
  local managed_pid="${1:-}" kept=() pid
  [[ -n "${managed_pid}" ]] || return 1
  for pid in "${RUBIN_PROCESS_PIDS[@]}"; do
    [[ "${pid}" == "${managed_pid}" ]] || kept+=("${pid}")
  done
  RUBIN_PROCESS_PIDS=("${kept[@]}")
  for pid in "${RUBIN_PROCESS_PIDS[@]}"; do
    [[ "${pid}" != "${managed_pid}" ]] || return 1
  done
}
run_rust_restart_scenario() {
  RUST_RESTART_REASON=""
  capture_restart_tip rust_restart_pre rust "${RUST_RPC_ADDR}" "${RUST_PRE_RESTART_TIP_JSON}" || return 1
  IFS='|' read -r PRE_RESTART_RUST_HEIGHT PRE_RESTART_RUST_TIP PRE_RESTART_RUST_HAS_TIP <<<"${RUST_RESTART_TIP_TSV}" || { RUST_RESTART_REASON=rust_restart_pre_tip_parse_failed; return 1; }
  OLD_RUST_PID="${RUST_PID}"
  OLD_RUST_RPC_ADDR="${RUST_RPC_ADDR}"
  OLD_RUST_P2P_ADDR="${RUST_P2P_ADDR}"
  OLD_RUST_STARTED_AT_UTC="${RUST_STARTED_AT_UTC}"
  OLD_RUST_ARGV_JSON="${RUST_ARGV_JSON}"
  rubin_process_stop_pid "${OLD_RUST_PID}" || { RUST_RESTART_REASON=rust_restart_stop_failed; return 1; }
  if rubin_process_is_alive "${OLD_RUST_PID}"; then RUST_RESTART_REASON=rust_restart_old_pid_still_alive; return 1; fi
  unregister_managed_pid "${OLD_RUST_PID}" || { RUST_RESTART_REASON=rust_restart_old_pid_unregister_failed; return 1; }
  OLD_RUST_PID_STOPPED=true
  go_restart_mine_target || return 1
  START_REASON=""
  clear_current_rust_process_evidence || return 1
  start_rust_node_with_log "${RUST_RESTART_LOG}" || { RUST_RESTART_REASON="$(rust_restart_start_reason "${START_REASON:-}")"; return 1; }
  [[ "${RUST_PID}" != "${OLD_RUST_PID}" ]] || { RUST_RESTART_REASON=rust_restart_same_pid_reused; return 1; }
  verify_process_identity node-rust-restart rust "${RUST_PID}" "${RUST_RPC_ADDR}" "${RUST_P2P_ADDR}" rubin-node-rust rust_restart_process_identity || { RUST_RESTART_REASON="${PROCESS_IDENTITY_REASON:-rust_restart_process_identity_unverified}"; return 1; }
  wait_peer_snapshot node-rust-restart "${RUST_RPC_ADDR}" "${RUST_PEERS_JSON}" "${MESH_TIMEOUT}" "${GO_P2P_ADDR}" || { RUST_RESTART_REASON="${PEER_SNAPSHOT_REASON:-rust_restart_peer_snapshot_missing_go_endpoint}"; return 1; }
  wait_rust_to_go_link rust_restart_to_go_tcp_link_missing rust_restart_to_go_tcp_link_ambiguous || return 1
  wait_peer_snapshot node-go-after-rust-restart "${GO_RPC_ADDR}" "${GO_PEERS_JSON}" "${MESH_TIMEOUT}" "${RUST_TO_GO_LOCAL_ADDR}" || { RUST_RESTART_REASON="${PEER_SNAPSHOT_REASON:-go_after_rust_restart_peer_snapshot_missing_rust_endpoint}"; return 1; }
  verify_process_identity node-go-after-rust-restart go "${GO_PID}" "${GO_RPC_ADDR}" "${GO_P2P_ADDR}" rubin-node-go go_after_rust_restart_process_identity || { RUST_RESTART_REASON="${PROCESS_IDENTITY_REASON:-go_after_rust_restart_process_identity_unverified}"; return 1; }
  verify_process_identity node-rust-after-restart rust "${RUST_PID}" "${RUST_RPC_ADDR}" "${RUST_P2P_ADDR}" rubin-node-rust rust_after_restart_process_identity || { RUST_RESTART_REASON="${PROCESS_IDENTITY_REASON:-rust_after_restart_process_identity_unverified}"; return 1; }
  wait_rust_restart_catch_up || return 1
  RUST_RESTART_SAME_DATADIR=true
  RUST_RESTART_PEER_RECONNECTED=true
  FINAL_PROCESS_IDENTITY_RECHECKED=true
  FINAL_RUST_OUTBOUND_LINK_RECHECKED=true
  FINAL_PEER_SNAPSHOTS_RECHECKED=true
}
start_go_node() {
  local -a argv=("${GO_NODE_BIN}" --network devnet --datadir "${GO_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0)
  START_REASON=""
  GO_CMD="$(argv_cmd "${argv[@]}")"; GO_ARGV_JSON="$(argv_json "${argv[@]}")"
  rubin_process_start "${GO_LOG}" "${argv[@]}" || { START_REASON=go_launch_failed; return 1; }; GO_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${GO_LOG}" "rpc: listening=" 60 "${GO_PID}" || { START_REASON=go_rpc_log_wait_failed; return 1; }
  GO_RPC_ADDR="$(rubin_process_extract_rpc_addr "${GO_LOG}")" || { START_REASON=go_rpc_addr_extract_failed; return 1; }; loopback_endpoint "${GO_RPC_ADDR}" || finish_no_data "go_rpc_addr_malformed"
  GO_P2P_ADDR="$(p2p_addr_for_pid "${GO_PID}" "${GO_RPC_ADDR}" 30)" || { rc=$?; [[ ${rc} -eq 42 ]] && finish_no_data "lsof_failed"; [[ ${rc} -eq 43 ]] && finish_no_data "lsof_timeout"; [[ ${rc} -eq 44 ]] && finish_no_data "go_p2p_addr_ambiguous"; [[ ${rc} -eq 45 ]] && finish_no_data "go_p2p_addr_timeout"; return 1; }; loopback_endpoint "${GO_P2P_ADDR}" || finish_no_data "go_p2p_addr_malformed"
  rubin_process_wait_for_rpc_ready "${GO_RPC_ADDR}" 30 || { START_REASON=go_rpc_ready_timeout; return 1; }; GO_STARTED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
for tool in lsof perl ps sed sort; do command -v "${tool}" >/dev/null 2>&1 || finish_no_data "${tool}_unavailable"; done
build_go_node || finish_no_data "${BUILD_REASON:-go_build_failed}"
build_rust_node || finish_no_data "${BUILD_REASON:-rust_build_failed}"
if (( TX_PATH_MODE >= 1 )); then
  prepare_tx_chainstate || finish_no_data "$(tx_path_prepare_reason "${TX_REASON:-go_submit_chainstate_prepare_failed}" "${TX_PATH_MODE}")"
elif (( RUST_RESTART_MODE == 1 )); then
  prepare_restart_chainstate || finish_no_data "${RUST_RESTART_REASON:-rust_restart_chainstate_prepare_failed}"
elif (( PARTITION_HEAL_REORG_MODE == 1 )); then
  prepare_tx_chainstate || finish_no_data "$(partition_prepare_reason "${TX_REASON:-}")"
fi
start_go_node || finish_no_data "${START_REASON:-go_process_not_ready}"
verify_process_identity node-go go "${GO_PID}" "${GO_RPC_ADDR}" "${GO_P2P_ADDR}" rubin-node-go go_process_identity || finish_no_data "${PROCESS_IDENTITY_REASON:-go_process_identity_unverified}"
if (( PARTITION_HEAL_REORG_MODE == 1 )); then
  start_partition_proxy || finish_no_data "${PARTITION_REASON:-partition_proxy_not_ready}"
fi
start_rust_node || finish_no_data "${START_REASON:-rust_process_not_ready}"
verify_process_identity node-rust rust "${RUST_PID}" "${RUST_RPC_ADDR}" "${RUST_P2P_ADDR}" rubin-node-rust rust_process_identity || finish_no_data "${PROCESS_IDENTITY_REASON:-rust_process_identity_unverified}"
if (( PARTITION_HEAL_REORG_MODE == 1 )); then
  run_partition_heal_reorg_scenario || finish_no_data "${PARTITION_REASON:-partition_heal_reorg_failed}"
else
  wait_peer_snapshot node-rust "${RUST_RPC_ADDR}" "${RUST_PEERS_JSON}" "${MESH_TIMEOUT}" "${GO_P2P_ADDR}" || finish_no_data "${PEER_SNAPSHOT_REASON:-rust_peer_snapshot_missing_go_endpoint}"
  wait_rust_to_go_link rust_to_go_tcp_link_missing rust_to_go_tcp_link_ambiguous
  wait_peer_snapshot node-go "${GO_RPC_ADDR}" "${GO_PEERS_JSON}" "${MESH_TIMEOUT}" "${RUST_TO_GO_LOCAL_ADDR}" || finish_no_data "${PEER_SNAPSHOT_REASON:-go_peer_snapshot_missing_rust_endpoint}"
  verify_process_identity node-go-final go "${GO_PID}" "${GO_RPC_ADDR}" "${GO_P2P_ADDR}" rubin-node-go go_final_process_identity || finish_no_data "${PROCESS_IDENTITY_REASON:-go_final_process_identity_unverified}"
  verify_process_identity node-rust-final rust "${RUST_PID}" "${RUST_RPC_ADDR}" "${RUST_P2P_ADDR}" rubin-node-rust rust_final_process_identity || finish_no_data "${PROCESS_IDENTITY_REASON:-rust_final_process_identity_unverified}"
  FINAL_PROCESS_IDENTITY_RECHECKED=true
  wait_rust_to_go_link rust_final_to_go_tcp_link_missing rust_final_to_go_tcp_link_ambiguous
  FINAL_RUST_OUTBOUND_LINK_RECHECKED=true
  wait_peer_snapshot node-rust-final "${RUST_RPC_ADDR}" "${RUST_PEERS_JSON}" "${MESH_TIMEOUT}" "${GO_P2P_ADDR}" || finish_no_data "${PEER_SNAPSHOT_REASON:-rust_final_peer_snapshot_missing_go_endpoint}"
  wait_peer_snapshot node-go-final "${GO_RPC_ADDR}" "${GO_PEERS_JSON}" "${MESH_TIMEOUT}" "${RUST_TO_GO_LOCAL_ADDR}" || finish_no_data "${PEER_SNAPSHOT_REASON:-go_final_peer_snapshot_missing_rust_endpoint}"
  FINAL_PEER_SNAPSHOTS_RECHECKED=true
fi
if (( RUST_RESTART_MODE == 1 )); then
  run_rust_restart_scenario || finish_no_data "${RUST_RESTART_REASON:-rust_restart_failed}"
fi
if (( TX_PATH_MODE == 1 || TX_PATH_MODE == 2 )); then
  submit_go_tx || finish_no_data "${TX_REASON:-go_submit_failed}"
  wait_rust_accept || finish_no_data "${TX_REASON:-rust_accept_failed}"
  if (( TX_PATH_MODE == 2 )); then
    rust_mine_including_tx || finish_no_data "${TX_REASON:-rust_mine_failed}"
    wait_go_converge_to_rust_mined_block || finish_no_data "${TX_REASON:-go_converge_failed}"
  fi
elif (( TX_PATH_MODE == 3 )); then
  submit_rust_tx || finish_no_data "${TX_REASON:-rust_submit_failed}"
  wait_go_accept || finish_no_data "${TX_REASON:-go_accept_failed}"
  go_mine_including_tx || finish_no_data "${TX_REASON:-go_mine_failed}"
  wait_rust_converge_to_go_mined_block || finish_no_data "${TX_REASON:-rust_converge_failed}"
fi
PASS_REPORT_JSON="$(mktemp "/tmp/mixed-client-mesh-pass.XXXXXX")" || finish_no_data "pass_report_temp_failed"; FINAL_REPORT_JSON="${REPORT_JSON}"; REPORT_JSON="${PASS_REPORT_JSON}"
write_outputs "PASS" || { REPORT_JSON="${FINAL_REPORT_JSON}"; finish_no_data "pass_report_write_failed"; }; REPORT_JSON="${FINAL_REPORT_JSON}"
if ! run_validator "${LEGACY_SCHEMA_MARKER_JSON}" >&2; then
  rm -f -- "${PASS_REPORT_JSON}"; finish_no_data "legacy_schema_marker_validation_failed"
fi
if (( TX_PATH_MODE >= 1 )); then
  if ! check_err="$(check_report "${PASS_REPORT_JSON}" live producer-tx 2>&1)"; then
    rm -f -- "${PASS_REPORT_JSON}"; finish_no_data "pass_report_live_validation_$(combined_report_reason_token <<<"${check_err}")"
  fi
elif (( RUST_RESTART_MODE == 1 )); then
  if ! check_err="$(check_report "${PASS_REPORT_JSON}" live rust-restart 2>&1)"; then
    printf '%s\n' "${check_err}" >"${RUBIN_PROCESS_ARTIFACT_ROOT}/pass-report-live-validation.err" || true
    rm -f -- "${PASS_REPORT_JSON}"; finish_no_data "pass_report_live_validation_$(check_report_reason_token <<<"${check_err}")"
  fi
elif (( PARTITION_HEAL_REORG_MODE == 1 )); then
  if ! check_err="$(check_report "${PASS_REPORT_JSON}" live partition-heal-reorg 2>&1)"; then
    printf '%s\n' "${check_err}" >"${RUBIN_PROCESS_ARTIFACT_ROOT}/pass-report-live-validation.err" || true
    rm -f -- "${PASS_REPORT_JSON}"; finish_no_data "pass_report_live_validation_$(check_report_reason_token <<<"${check_err}")"
  fi
else
  if ! check_err="$(check_report "${PASS_REPORT_JSON}" live 2>&1)"; then
    rm -f -- "${PASS_REPORT_JSON}"; finish_no_data "pass_report_live_validation_$(check_report_reason_token <<<"${check_err}")"
  fi
fi
mv -- "${PASS_REPORT_JSON}" "${REPORT_JSON}" || finish_no_data "pass_report_publish_failed"
PASS_SCENARIO="mixed-client mesh connected"; (( RUST_RESTART_MODE == 1 )) && PASS_SCENARIO="Rust restart/reconnect/catch-up path observed"; (( PARTITION_HEAL_REORG_MODE == 1 )) && PASS_SCENARIO="Partition/heal/reorg source-bound path observed"; (( TX_PATH_MODE == 1 )) && PASS_SCENARIO="Go-submit/Rust-accept path observed"; (( TX_PATH_MODE == 2 )) && PASS_SCENARIO="Go-submit/Rust-mine/Go-converge path observed"; (( TX_PATH_MODE == 3 )) && PASS_SCENARIO="Rust-submit/Go-mine/Rust-converge path observed"
[[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]] && echo "PASS: ${PASS_SCENARIO} go_pid=${GO_PID} rust_pid=${RUST_PID}; report=${REPORT_JSON} legacy_schema_marker=${LEGACY_SCHEMA_MARKER_JSON}" || echo "PASS: ${PASS_SCENARIO} go_pid=${GO_PID} rust_pid=${RUST_PID}; set KEEP_TMP=1 to retain report"

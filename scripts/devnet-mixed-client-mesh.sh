#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"; GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
RUST_WORKSPACE_ROOT="${REPO_ROOT}/clients/rust"; HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"; VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"
CHECK_REPORT="" CHECK_REPORT_MODE="" MESH_TIMEOUT="${MESH_TIMEOUT:-90}" TX_PATH_MODE=0 DETERMINISTIC_TX_FEE="${DETERMINISTIC_TX_FEE:-100000000}"
usage() {
  cat >&2 <<EOF
usage:
  $0 [--go-submit-rust-accept|--go-submit-rust-mine-go-converge]
  $0 --check-report PATH
  $0 --check-report-live PATH

--check-report and --check-report-live validate mixed_client_mesh reports only.
tx-path proofs are same-run producer validation and are not accepted from public
report revalidation paths.
EOF
}
set_tx_path_mode() { local mode="$1" flag="$2"; (( TX_PATH_MODE == 0 )) || { echo "tx-path modes are mutually exclusive: ${flag}" >&2; usage; exit 2; }; TX_PATH_MODE="${mode}"; }
while (($#)); do case "$1" in --go-submit-rust-accept) set_tx_path_mode 1 "$1"; shift ;; --go-submit-rust-mine-go-converge) set_tx_path_mode 2 "$1"; shift ;; --check-report|--check-report-live) [[ $# -ge 2 ]] || { usage; exit 2; }; CHECK_REPORT_MODE=offline; [[ "$1" == "--check-report-live" ]] && CHECK_REPORT_MODE=live; CHECK_REPORT="$2"; shift 2 ;; -h|--help) usage; exit 0 ;; *) usage; exit 2 ;; esac; done
if [[ -n "${CHECK_REPORT_MODE}" && "${TX_PATH_MODE}" != "0" ]]; then echo "tx-path modes cannot be combined with --check-report or --check-report-live" >&2; exit 2; fi
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
import datetime as dt, json, os, re, socket, struct, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path
path = Path(sys.argv[1]); live = sys.argv[3] == "live"; expected_mode = sys.argv[4]; dev_env = sys.argv[5]; go_module_root = sys.argv[6]
SCENARIO_MESH = "mixed_client_mesh"
SCENARIO_TX = "mixed_client_go_submit_rust_accept"
SCENARIO_CONVERGE = "mixed_client_go_submit_rust_mine_go_converge"
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
def verify_block_inclusion_sidecar(label: str, p: Path, txhex: str, txid: str, height: int, block_hash: str, impl: str, endpoint: str, request_path: str) -> None:
    block = load_json_file(label, p)
    req(set(block) == {"block_hex", "canonical", "hash", "height", "implementation", "request_path", "rpc_endpoint"}, f"{label} keys mismatch: {sorted(block)}")
    req(block.get("implementation") == impl and block.get("rpc_endpoint") == endpoint and block.get("request_path") == request_path, f"{label} sidecar identity mismatch")
    actual_hash = block.get("hash") or block.get("block_hash")
    req(block.get("canonical") is True and block.get("height") == height and actual_hash == block_hash, f"{label} sidecar height/hash/canonical mismatch")
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
	BlockHash string `json:"block_hash"`
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
	flag.Parse()
	wantHeight, err := strconv.ParseUint(*heightRaw, 10, 64); if err != nil { die("bad height") }
	raw, err := os.ReadFile(*respPath); if err != nil { die("read block response: " + err.Error()) }
	var resp blockResp; if err := json.Unmarshal(raw, &resp); err != nil { die("decode block response: " + err.Error()) }
	gotHash := resp.Hash; if gotHash == "" { gotHash = resp.BlockHash }
	if resp.Height != wantHeight || strings.ToLower(gotHash) != strings.ToLower(*hashHex) || !resp.Canonical { die("block response height/hash/canonical mismatch") }
	txBytes, err := hex.DecodeString(strings.TrimSpace(*txHex)); if err != nil { die("decode tx_hex: " + err.Error()) }
	_, wantTxid, _, consumed, err := consensus.ParseTx(txBytes); if err != nil || consumed != len(txBytes) { die("parse tx_hex failed") }
	if hex.EncodeToString(wantTxid[:]) != strings.ToLower(*txidHex) { die("tx_hex txid mismatch") }
	blockBytes, err := hex.DecodeString(strings.TrimSpace(resp.BlockHex)); if err != nil { die("decode block_hex: " + err.Error()) }
	pb, err := consensus.ParseBlockBytes(blockBytes); if err != nil { die("parse block_hex failed: " + err.Error()) }
	gotBlockHash, err := consensus.BlockHash(pb.HeaderBytes); if err != nil || hex.EncodeToString(gotBlockHash[:]) != strings.ToLower(*hashHex) { die("parsed block hash mismatch") }
	for _, got := range pb.Txids { if got == wantTxid { return } }
	die("submitted txid missing from parsed block txids")
}
'''
    with tempfile.TemporaryDirectory(prefix="rubin-mesh-block-check-") as td:
        source_path = Path(td) / "block-check.go"
        source_path.write_text(source, encoding="utf-8")
        try:
            proc = subprocess.run([dev_env, "--", "go", "-C", go_module_root, "run", str(source_path), "--block-response", str(p), "--tx-hex", txhex, "--txid", txid, "--height", str(height), "--hash", block_hash], check=False, env={**os.environ, "RUBIN_OPENSSL_SKIP_FIPS_GUARD": "1"}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=max(30, min(LIVE_TIMEOUT, 60)))
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
data = load_json_file("report", path)
req(expected_mode in {"public", "producer-tx"}, f"check_report expected mode is invalid: {expected_mode!r}")
scenario = data.get("scenario")
tx_mode = scenario in {SCENARIO_TX, SCENARIO_CONVERGE}
converge_mode = scenario == SCENARIO_CONVERGE
req(scenario in {SCENARIO_MESH, SCENARIO_TX, SCENARIO_CONVERGE}, f"scenario is not supported: {scenario!r}")
if tx_mode and expected_mode != "producer-tx":
    fail(("public tx-path check-report-live is unsupported" if live else "public tx-path check-report is unsupported") + "; same-run producer evidence is required")
if expected_mode == "producer-tx":
    req(tx_mode, "producer tx validation requires a mixed-client tx-path report")
req(data.get("verdict") == "PASS", f"report verdict is not PASS: {data.get('verdict')!r}")
req("failure_reason" not in data and "schema_marker" not in data, "PASS report must not carry failure/schema-marker verdict fields")
base_keys = {"artifact_root", "final_verification", "legacy_schema_compatibility", "nodes", "peer_connectivity", "scenario", "verdict"}
allowed_keys = base_keys | ({"go_submit", "rust_accept", "tx_path"} if tx_mode else set()) | ({"rust_mine", "go_converge"} if converge_mode else set())
req(set(data) == allowed_keys, f"report top-level keys mismatch: {sorted(data)}")
artifact_root_arg = data.get("artifact_root"); artifact_root = checked_path("artifact_root", artifact_root_arg)
legacy_schema = data.get("legacy_schema_compatibility")
req(isinstance(legacy_schema, dict) and legacy_schema.get("authoritative") is False and "verdict" not in legacy_schema and nonempty_str(legacy_schema.get("marker_path")), "legacy_schema_compatibility missing marker_path")
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
try: validator = subprocess.run([sys.executable, sys.argv[2], str(marker_path)], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
except (OSError, subprocess.TimeoutExpired) as exc: fail(f"legacy marker schema validation failed: {exc}")
req(validator.returncode == 0, "legacy marker schema validation failed: " + ((validator.stderr or validator.stdout).strip().splitlines() or ["validator returned nonzero"])[0])
nodes = data.get("nodes")
req(isinstance(nodes, list) and len(nodes) == 2 and all(isinstance(n, dict) for n in nodes), "PASS report requires exactly two node records")
expected = {"go": ("node-go", "rubin-node-go"), "rust": ("node-rust", "rubin-node-rust")}
for node in nodes:
    impl, name = node.get("implementation"), node.get("name")
    req(isinstance(impl, str) and impl in expected, f"node has invalid implementation: {impl!r}")
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
req(report_node_argv_eq(nodes_by_impl["go"], "node-go", []) and report_node_argv_eq(nodes_by_impl["rust"], "node-rust", ["--peer", nodes_by_impl["go"]["p2p_endpoint"]]), "node command_argv does not match exact launched argv")
req(nodes_by_impl["go"]["pid"] != nodes_by_impl["rust"]["pid"], "go/rust process evidence uses the same pid")
req(nodes_by_impl["go"]["binary"] != nodes_by_impl["rust"]["binary"] and nodes_by_impl["go"]["command"] != nodes_by_impl["rust"]["command"] and nodes_by_impl["go"].get("command_argv") != nodes_by_impl["rust"].get("command_argv"), "go/rust process evidence is not implementation-distinct")
req(len({nodes_by_impl[i][f] for i in ("go", "rust") for f in ("rpc_endpoint", "p2p_endpoint")}) == 4, "node rpc/p2p endpoints are not pairwise distinct")
if tx_mode:
    req(sorted((p.get("name"), p.get("implementation"), p.get("endpoint"), p.get("started_at")) for p in marker.get("participants", []) if isinstance(p, dict)) == sorted((n["name"], n["implementation"], n["rpc_endpoint"], n["started_at"]) for n in nodes), "legacy marker participants are not bound to report nodes")
if tx_mode:
    tx_path = exact_object(data.get("tx_path"), {"submitted_at", "observed_at", "tx_id"}, "tx_path")
    txid = tx_path.get("tx_id")
    req(tx_path == {"submitted_at": "node-go", "observed_at": ["node-rust"], "tx_id": txid}, "tx_path identity mismatch")
    req(isinstance(txid, str) and re.fullmatch(r"[0-9a-f]{64}", txid), "txid is malformed")
    go_submit = exact_object(data.get("go_submit"), {"get_tx_path", "rpc_endpoint", "tx_hex", "tx_status_path", "txid"}, "go_submit")
    rust_accept = exact_object(data.get("rust_accept"), {"get_tx_path", "raw_hex", "rpc_endpoint", "tx_status_path", "txid"}, "rust_accept")
    txhex = go_submit.get("tx_hex")
    req(isinstance(txhex, str) and 2 <= len(txhex) <= MAX_TX_HEX_CHARS and len(txhex) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", txhex), "tx_hex is malformed or unbounded")
    req(parse_txid_from_hex(txhex) == txid, "tx_hex txid mismatch")
    req(go_submit.get("txid") == txid and rust_accept.get("txid") == txid, "tx report txid mismatch")
    req(rust_accept.get("raw_hex") == txhex, "tx report raw transaction mismatch")
    req(go_submit.get("rpc_endpoint") == nodes_by_impl["go"]["rpc_endpoint"] and rust_accept.get("rpc_endpoint") == nodes_by_impl["rust"]["rpc_endpoint"], "tx report rpc endpoint mismatch")
    go_status = artifact_file("go_submit.tx_status_path", go_submit.get("tx_status_path"), artifact_root)
    go_get = artifact_file("go_submit.get_tx_path", go_submit.get("get_tx_path"), artifact_root)
    rust_status = artifact_file("rust_accept.tx_status_path", rust_accept.get("tx_status_path"), artifact_root)
    rust_get = artifact_file("rust_accept.get_tx_path", rust_accept.get("get_tx_path"), artifact_root)
    req(len({go_status, go_get, rust_status, rust_get}) == 4, "tx sidecar paths are not pairwise distinct")
    tx_sidecars(load_json_file("go_submit.tx_status", go_status), load_json_file("go_submit.get_tx", go_get), txid, txhex, "go_submit", "go", nodes_by_impl["go"]["rpc_endpoint"], f"/tx_status?txid={txid}", f"/get_tx?txid={txid}")
    tx_sidecars(load_json_file("rust_accept.tx_status", rust_status), load_json_file("rust_accept.get_tx", rust_get), txid, txhex, "rust_accept", "rust", nodes_by_impl["rust"]["rpc_endpoint"], f"/tx_status?txid={txid}", f"/get_tx?txid={txid}")
    if live and not converge_mode:
        tx_sidecars(tx_rpc(nodes_by_impl["go"]["rpc_endpoint"], f"/tx_status?txid={txid}", "go_submit.tx_status", "go"), tx_rpc(nodes_by_impl["go"]["rpc_endpoint"], f"/get_tx?txid={txid}", "go_submit.get_tx", "go"), txid, txhex, "go_submit.live", "go", nodes_by_impl["go"]["rpc_endpoint"], f"/tx_status?txid={txid}", f"/get_tx?txid={txid}")
        tx_sidecars(tx_rpc(nodes_by_impl["rust"]["rpc_endpoint"], f"/tx_status?txid={txid}", "rust_accept.tx_status", "rust"), tx_rpc(nodes_by_impl["rust"]["rpc_endpoint"], f"/get_tx?txid={txid}", "rust_accept.get_tx", "rust"), txid, txhex, "rust_accept.live", "rust", nodes_by_impl["rust"]["rpc_endpoint"], f"/tx_status?txid={txid}", f"/get_tx?txid={txid}")
    if converge_mode:
        rust_mine = exact_object(data.get("rust_mine"), {"block_hash", "block_path", "class", "height", "mine_next_path", "mined_by", "raw_hex", "rpc_endpoint", "tx_count", "txid"}, "rust_mine")
        go_converge = exact_object(data.get("go_converge"), {"block_hash", "block_path", "class", "converged_at", "height", "raw_hex", "rpc_endpoint", "tip_path", "txid"}, "go_converge")
        req(rust_mine.get("class") == "mined_included" and rust_mine.get("mined_by") == "node-rust", "rust_mine is not node-rust mined_included")
        req(go_converge.get("class") == "canonical_block_found" and go_converge.get("converged_at") == "node-go", "go_converge is not node-go canonical_block_found")
        req(rust_mine.get("txid") == txid and go_converge.get("txid") == txid and rust_mine.get("raw_hex") == txhex and go_converge.get("raw_hex") == txhex, "mined/converged tx identity differs from submitted tx")
        req(rust_mine.get("rpc_endpoint") == nodes_by_impl["rust"]["rpc_endpoint"] and go_converge.get("rpc_endpoint") == nodes_by_impl["go"]["rpc_endpoint"], "mined/converged RPC endpoints are not bound to expected nodes")
        height, block_hash = rust_mine.get("height"), rust_mine.get("block_hash")
        req(isinstance(height, int) and not isinstance(height, bool) and height >= 1, "rust_mine.height is malformed")
        req(isinstance(block_hash, str) and re.fullmatch(r"[0-9a-f]{64}", block_hash), "rust_mine.block_hash is malformed")
        req(isinstance(rust_mine.get("tx_count"), int) and not isinstance(rust_mine.get("tx_count"), bool) and rust_mine["tx_count"] >= 2, "rust_mine.tx_count does not prove coinbase plus submitted tx")
        req(go_converge.get("height") == height and go_converge.get("block_hash") == block_hash, "go_converge does not match rust_mine height/hash")
        rust_mine_next_path = artifact_file("rust_mine.mine_next_path", rust_mine.get("mine_next_path"), artifact_root)
        rust_block_path = artifact_file("rust_mine.block_path", rust_mine.get("block_path"), artifact_root)
        go_tip_path = artifact_file("go_converge.tip_path", go_converge.get("tip_path"), artifact_root)
        go_block_path = artifact_file("go_converge.block_path", go_converge.get("block_path"), artifact_root)
        req(len({rust_mine_next_path, rust_block_path, go_tip_path, go_block_path}) == 4, "converge sidecar paths are not pairwise distinct")
        mine_next = load_json_file("rust_mine.mine_next", rust_mine_next_path)
        req(set(mine_next) == {"block_hash", "height", "implementation", "mined", "nonce", "request_path", "rpc_endpoint", "timestamp", "tx_count"}, f"rust_mine.mine_next keys mismatch: {sorted(mine_next)}")
        req(mine_next.get("implementation") == "rust" and mine_next.get("rpc_endpoint") == nodes_by_impl["rust"]["rpc_endpoint"] and mine_next.get("request_path") == "/mine_next", "rust_mine mine_next sidecar identity mismatch")
        req(mine_next.get("mined") is True and mine_next.get("height") == height and mine_next.get("block_hash") == block_hash and mine_next.get("tx_count") == rust_mine["tx_count"], "rust_mine mine_next sidecar does not match report")
        verify_block_inclusion_sidecar("rust_mine.block_path", rust_block_path, txhex, txid, height, block_hash, "rust", nodes_by_impl["rust"]["rpc_endpoint"], f"/get_block?height={height}")
        verify_block_inclusion_sidecar("go_converge.block_path", go_block_path, txhex, txid, height, block_hash, "go", nodes_by_impl["go"]["rpc_endpoint"], f"/get_block?height={height}")
        tip = load_json_file("go_converge.tip", go_tip_path)
        req(set(tip) == {"best_known_height", "has_tip", "height", "implementation", "in_ibd", "request_path", "rpc_endpoint", "tip_hash"}, f"go_converge.tip keys mismatch: {sorted(tip)}")
        req(tip.get("implementation") == "go" and tip.get("rpc_endpoint") == nodes_by_impl["go"]["rpc_endpoint"] and tip.get("request_path") == "/get_tip", "go_converge tip sidecar identity mismatch")
        req(tip.get("has_tip") is True and tip.get("height") == height and tip.get("tip_hash") == block_hash, "go_converge tip sidecar does not match rust mined block")
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
if [[ -n "${CHECK_REPORT_MODE}" ]]; then need_tool python3; [[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }; [[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }; check_report "${CHECK_REPORT}" "${CHECK_REPORT_MODE}"; exit 0; fi
if (( TX_PATH_MODE >= 1 )); then validate_deterministic_tx_fee; fi
need_tool python3; [[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }; [[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init mixed-client-mesh
GO_NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"; RUST_NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-rust"
GO_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-go"; RUST_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-rust"
GO_LOG="node-go.log"; RUST_LOG="node-rust.log"; REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mixed-client-mesh-report.json"; LEGACY_SCHEMA_MARKER_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mixed-client-mesh-legacy-schema-marker.json"
GO_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-peers.json"; RUST_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-peers.json"
GO_SUBMIT_STATUS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-tx-status.json"; GO_SUBMIT_GET_TX_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-get-tx.json"; RUST_STATUS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-tx-status.json"; RUST_GET_TX_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-get-tx.json"
RUST_MINE_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-mine-next.json"; RUST_MINE_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-mined-block.json"; GO_CONVERGE_TIP_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-converge-tip.json"; GO_CONVERGE_BLOCK_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-converge-block.json"
TXGEN_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-txgen"; KEYGEN_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.go"; KEYGEN_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.json"; BLOCK_CHECK_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/block-check.go"; MINE_LOG="mine-go.log"
GO_PID="" RUST_PID="" GO_RPC_ADDR="" RUST_RPC_ADDR="" GO_P2P_ADDR="" RUST_P2P_ADDR="" GO_STARTED_AT_UTC="" RUST_STARTED_AT_UTC="" GO_COMM="" RUST_COMM="" RUST_TO_GO_LOCAL_ADDR="" GO_CMD="" RUST_CMD="" GO_ARGV_JSON="" RUST_ARGV_JSON="" FINAL_PROCESS_IDENTITY_RECHECKED="" FINAL_RUST_OUTBOUND_LINK_RECHECKED="" FINAL_PEER_SNAPSHOTS_RECHECKED="" PROCESS_IDENTITY_REASON="" START_REASON="" BUILD_REASON="" TX_REASON="" TX_ID="" TX_HEX="" TX_FROM_KEY_FILE="" TX_FROM_KEY_DIR="" TX_TO_KEY="" RUST_MINE_HEIGHT="" RUST_MINE_HASH="" RUST_MINE_TX_COUNT=""
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
check_report_reason_token() { python3 -c 'import sys; msg=" ".join(x[5:].strip() for x in sys.stdin.read().splitlines() if x.startswith("FAIL:")); rules=[("public tx-path check-report-live is unsupported","public_tx_path_check_report_live_unsupported"),("public tx-path check-report is unsupported","public_tx_path_check_report_unsupported"),("same-run producer evidence is required","tx_path_requires_same_run_producer_evidence"),("report path is required","report_path_required"),("report is not a regular file","report_not_regular_file"),("report is empty","report_empty"),("report is too large","report_too_large"),("report read failed","report_read_failed"),("report malformed JSON","report_malformed_json"),("live peer snapshot malformed JSON","live_peer_snapshot_malformed_json"),("differs from live exact peer set","live_peer_snapshot_mismatch"),("live listeners are not pid-owned","live_listener_not_pid_owned"),("rust outbound TCP link is not live and rust-owned","rust_outbound_link_not_live"),("argv_unavailable","argv_unavailable"),("live process argv/executable does not match report","argv_mismatch"),("lsof_timeout","lsof_timeout"),("lsof_unavailable","lsof_unavailable"),("lsof_failed","lsof_failed"),("pid_exe_failed","pid_exe_failed"),("pid_exe_unavailable","pid_exe_unavailable"),("argv","argv_mismatch"),("same pid","same_pid"),("process_comm","process_identity_invalid"),("process_alive","process_identity_invalid"),("process-backed","process_identity_invalid"),("peer snapshot","peer_snapshot_invalid"),("legacy marker","legacy_marker_invalid"),("failure/schema-marker","pass_report_has_failure_fields"),("failure_reason","pass_report_has_failure_fields"),("root is not an object","report_root_invalid")]; print(next((t for p,t in rules if p in msg), "unknown"))'; }
tx_report_reason_token() {
  local msg
  msg="$(cat)"
  python3 - "${msg}" <<'PY'
import re, sys
msg = "\n".join(line[5:].strip() if line.startswith("FAIL:") else line for line in sys.argv[1].splitlines())
rules = [("rust_mine is not node-rust mined_included", "rust_mine_class_invalid"), ("go_converge is not node-go canonical_block_found", "go_converge_class_invalid"), ("mined/converged RPC endpoints are not bound", "converge_rpc_endpoint_mismatch"), ("rust_mine.height is malformed", "rust_mine_height_invalid"), ("rust_mine.block_hash is malformed", "rust_mine_hash_invalid"), ("sidecar identity mismatch", "converge_sidecar_identity_mismatch"), ("converge sidecar paths are not pairwise distinct", "converge_sidecar_paths_not_distinct"), ("submitted txid missing from parsed block txids", "block_missing_submitted_txid"), ("parse block_hex failed", "block_hex_parse_failed"), ("parsed block hash mismatch", "block_hash_mismatch"), ("inclusion check timeout", "block_inclusion_timeout"), ("inclusion check failed", "block_inclusion_failed"), ("mined/converged tx identity differs", "converged_tx_identity_mismatch"), ("go_converge does not match rust_mine", "go_converge_height_hash_mismatch"), ("rust_mine.tx_count", "rust_mine_tx_count_invalid"), ("mine_next sidecar does not match", "rust_mine_sidecar_invalid"), ("sidecar height/hash/canonical mismatch", "block_sidecar_invalid"), ("block_hex is missing", "block_sidecar_invalid"), ("tip sidecar does not match", "go_converge_tip_invalid"), ("tx parser consumed mismatch", "tx_parser_consumed_mismatch"), ("tx parser timeout", "tx_parser_timeout"), ("tx parser unavailable", "tx_parser_unavailable"), ("tx parser output too large", "tx_parser_output_too_large"), ("tx parser malformed output", "tx_parser_malformed_output"), ("tx parser root is not an object", "tx_parser_root_invalid"), ("tx parser did not produce txid", "tx_parser_missing_txid"), ("tx parser failed", "tx_parser_failed"), ("tx_hex is malformed or unbounded", "tx_hex_malformed_or_unbounded"), ("txid is malformed", "txid_malformed"), ("tx report rpc endpoint mismatch", "tx_report_rpc_endpoint_mismatch"), ("capture identity mismatch", "tx_capture_identity_mismatch"), ("tx sidecar paths are not pairwise distinct", "tx_sidecar_paths_not_distinct"), ("scenario mismatch", "scenario_mismatch"), ("verdict mismatch", "verdict_mismatch"), ("artifact_root mismatch", "artifact_root_mismatch"), ("tx_path identity mismatch", "tx_path_identity_mismatch"), ("tx report txid mismatch", "tx_identity_mismatch"), ("tx report raw transaction mismatch", "raw_tx_mismatch")]
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
  local impl="$1" method="$2" addr="$3" path="$4" out="$5" status=0; local tmp="${out}.raw"
  rpc_json "${method}" "${addr}" "${path}" >"${tmp}" || status=$?
  (( status == 0 )) || { rm -f -- "${tmp}"; case "${status}" in 22) return 21 ;; 23) return 23 ;; *) return 22 ;; esac; }
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
  echo "Mining mature chainstate for Go-submit -> Rust-accept path" >&2
  bounded_mesh "${GO_NODE_BIN}" --network devnet --datadir "${GO_DIR}" --mine-address "${mine_address}" --mine-blocks 101 --mine-exit >"$(_rubin_process_resolve_log "${MINE_LOG}")" 2>&1 || { status=$?; cleanup_tx_from_key_file || true; [[ ${status} -eq 142 ]] && TX_REASON=go_submit_mine_timeout || TX_REASON=go_submit_mine_failed; return 1; }
  cp -R -- "${GO_DIR}/." "${RUST_DIR}/" || { cleanup_tx_from_key_file || true; TX_REASON=go_submit_chainstate_copy_failed; return 1; }
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
txid_parse_reason() { case "$1" in 2) printf '%s\n' go_submit_txid_parse_timeout ;; 3) printf '%s\n' go_submit_txid_parser_unavailable ;; 4) printf '%s\n' go_submit_txid_parser_failed ;; 5) printf '%s\n' go_submit_txid_parser_malformed_output ;; 6) printf '%s\n' go_submit_txid_parser_root_invalid ;; 7) printf '%s\n' go_submit_txid_missing_or_malformed ;; 8) printf '%s\n' go_submit_txid_parser_output_too_large ;; 9) printf '%s\n' go_submit_txid_parser_consumed_mismatch ;; *) printf '%s\n' go_submit_txid_parse_failed ;; esac; }
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
  cleanup_tx_from_key_file || cleanup_status=$?
  (( cleanup_status == 0 )) || { TX_REASON=go_submit_keygen_cleanup_failed; return 1; }
  (( status == 0 )) || { [[ ${status} -eq 142 ]] && TX_REASON=go_submit_txgen_timeout || TX_REASON=go_submit_txgen_failed; return 1; }
  [[ "${TX_HEX}" =~ ^[0-9a-f]+$ && ${#TX_HEX} -le 20000 && $(( ${#TX_HEX} % 2 )) -eq 0 ]] || { TX_REASON=go_submit_tx_hex_malformed_or_unbounded; return 1; }
  TX_ID="$(parse_txid)" || { rc=$?; TX_REASON="$(txid_parse_reason "${rc}")"; return 1; }
  capture_tx_rpc_sidecar go "${GO_RPC_ADDR}" "/tx_status?txid=${TX_ID}" "${GO_SUBMIT_STATUS_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason go_submit_tx_status "${rc}")"; return 1; }
  capture_tx_rpc_sidecar go "${GO_RPC_ADDR}" "/get_tx?txid=${TX_ID}" "${GO_SUBMIT_GET_TX_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason go_submit_get_tx "${rc}")"; return 1; }
  verify_tx_sidecars go_submit go "${GO_RPC_ADDR}" "${TX_ID}" "${TX_HEX}" "/tx_status?txid=${TX_ID}" "/get_tx?txid=${TX_ID}" "${GO_SUBMIT_STATUS_JSON}" "${GO_SUBMIT_GET_TX_JSON}" || { rc=$?; TX_REASON="$(tx_sidecar_reason go_submit "${rc}")"; return 1; }
}
wait_rust_accept() {
  local deadline rc=0 last_retry_reason=""
  TX_REASON=""
  deadline=$((SECONDS + MESH_TIMEOUT))
  while (( SECONDS < deadline )); do
    if capture_tx_rpc_sidecar rust "${RUST_RPC_ADDR}" "/tx_status?txid=${TX_ID}" "${RUST_STATUS_JSON}"; then
      if capture_tx_rpc_sidecar rust "${RUST_RPC_ADDR}" "/get_tx?txid=${TX_ID}" "${RUST_GET_TX_JSON}"; then
        if verify_tx_sidecars rust_accept rust "${RUST_RPC_ADDR}" "${TX_ID}" "${TX_HEX}" "/tx_status?txid=${TX_ID}" "/get_tx?txid=${TX_ID}" "${RUST_STATUS_JSON}" "${RUST_GET_TX_JSON}" >/dev/null 2>&1; then
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
	flag.Parse()
	wantHeight, err := strconv.ParseUint(*heightRaw, 10, 64); if err != nil { die("bad height") }
	raw, err := os.ReadFile(*respPath); if err != nil { die("read block response: " + err.Error()) }
	var resp blockResp; if err := json.Unmarshal(raw, &resp); err != nil { die("decode block response: " + err.Error()) }
	if resp.Height != wantHeight || strings.ToLower(resp.Hash) != strings.ToLower(*hashHex) || !resp.Canonical { die("block response height/hash/canonical mismatch") }
	txBytes, err := hex.DecodeString(strings.TrimSpace(*txHex)); if err != nil { die("decode tx_hex: " + err.Error()) }
	_, wantTxid, _, consumed, err := consensus.ParseTx(txBytes); if err != nil || consumed != len(txBytes) { die("parse tx_hex failed") }
	if hex.EncodeToString(wantTxid[:]) != strings.ToLower(*txidHex) { die("tx_hex txid mismatch") }
	blockBytes, err := hex.DecodeString(strings.TrimSpace(resp.BlockHex)); if err != nil { die("decode block_hex: " + err.Error()) }
	pb, err := consensus.ParseBlockBytes(blockBytes); if err != nil { die("parse block_hex failed: " + err.Error()) }
	gotHash, err := consensus.BlockHash(pb.HeaderBytes); if err != nil || hex.EncodeToString(gotHash[:]) != strings.ToLower(*hashHex) { die("parsed block hash mismatch") }
	for _, got := range pb.Txids { if got == wantTxid { return } }
	die("submitted txid missing from parsed block txids")
}
EOF
}
verify_block_inclusion() {
  local label="$1" block_path="$2" height="$3" block_hash="$4" output
  [[ -s "${BLOCK_CHECK_GO}" ]] || write_block_check_go || { TX_REASON="${label}_block_check_write_failed"; return 1; }
  output="$(bounded_mesh /usr/bin/env RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${BLOCK_CHECK_GO}" --block-response "${block_path}" --tx-hex "${TX_HEX}" --txid "${TX_ID}" --height "${height}" --hash "${block_hash}" 2>&1)" || {
    local status=$?
    printf '%s\n' "${label} inclusion check failed: ${output}" >&2
    if [[ "${status}" -eq 142 ]]; then
      TX_REASON="${label}_inclusion_timeout"
    else
      TX_REASON="${label}_inclusion_failed"
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
rust_mine_including_tx() {
  local parsed rc=0
  TX_REASON=""
  capture_rpc_sidecar rust POST "${RUST_RPC_ADDR}" /mine_next "${RUST_MINE_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason rust_mine "${rc}")"; return 1; }
  parsed="$(parse_mine_next_response "${RUST_MINE_JSON}")" || { rc=$?; case "${rc}" in 13) TX_REASON=rust_mine_malformed_rpc_body ;; 14) TX_REASON=rust_mine_unavailable ;; 16) TX_REASON=rust_mine_tx_count_invalid ;; *) TX_REASON=rust_mine_unknown_failure ;; esac; return 1; }
  IFS=$'\t' read -r RUST_MINE_HEIGHT RUST_MINE_HASH RUST_MINE_TX_COUNT <<<"${parsed}" || { TX_REASON=rust_mine_malformed_rpc_body; return 1; }
  capture_rpc_sidecar rust GET "${RUST_RPC_ADDR}" "/get_block?height=${RUST_MINE_HEIGHT}" "${RUST_MINE_BLOCK_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason rust_mine_get_block "${rc}")"; return 1; }
  verify_block_inclusion rust_mine "${RUST_MINE_BLOCK_JSON}" "${RUST_MINE_HEIGHT}" "${RUST_MINE_HASH}"
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
  local deadline tmp rc=0 saw_valid_tip=false
  TX_REASON=""
  deadline=$((SECONDS + MESH_TIMEOUT)); tmp="${GO_CONVERGE_TIP_JSON}.tmp"
  while (( SECONDS < deadline )); do
    if capture_rpc_sidecar go GET "${GO_RPC_ADDR}" /get_tip "${tmp}"; then
      if tip_matches "${tmp}" "${RUST_MINE_HEIGHT}" "${RUST_MINE_HASH}"; then
        mv -- "${tmp}" "${GO_CONVERGE_TIP_JSON}" || { TX_REASON=go_converge_artifact_write_failed; return 1; }
        capture_rpc_sidecar go GET "${GO_RPC_ADDR}" "/get_block?height=${RUST_MINE_HEIGHT}" "${GO_CONVERGE_BLOCK_JSON}" || { rc=$?; TX_REASON="$(tx_capture_reason go_converge_get_block "${rc}")"; return 1; }
        verify_block_inclusion go_converge "${GO_CONVERGE_BLOCK_JSON}" "${RUST_MINE_HEIGHT}" "${RUST_MINE_HASH}"
        return $?
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
write_outputs() {
  local verdict="$1" reason="${2:-}"
  export REPORT_JSON LEGACY_SCHEMA_MARKER_JSON verdict reason GO_PID RUST_PID GO_RPC_ADDR RUST_RPC_ADDR \
    GO_P2P_ADDR RUST_P2P_ADDR GO_STARTED_AT_UTC RUST_STARTED_AT_UTC GO_COMM RUST_COMM \
    GO_NODE_BIN RUST_NODE_BIN GO_CMD RUST_CMD GO_ARGV_JSON RUST_ARGV_JSON GO_PEERS_JSON RUST_PEERS_JSON \
    GO_PROCESS_ALIVE RUST_PROCESS_ALIVE GO_RPC_PROCESS_BACKED RUST_RPC_PROCESS_BACKED GO_P2P_PROCESS_BACKED RUST_P2P_PROCESS_BACKED \
    RUST_TO_GO_LOCAL_ADDR FINAL_PROCESS_IDENTITY_RECHECKED FINAL_RUST_OUTBOUND_LINK_RECHECKED FINAL_PEER_SNAPSHOTS_RECHECKED \
    RUBIN_PROCESS_ARTIFACT_ROOT TX_PATH_MODE TX_ID TX_HEX GO_SUBMIT_STATUS_JSON GO_SUBMIT_GET_TX_JSON RUST_STATUS_JSON RUST_GET_TX_JSON \
    RUST_MINE_JSON RUST_MINE_BLOCK_JSON GO_CONVERGE_TIP_JSON GO_CONVERGE_BLOCK_JSON RUST_MINE_HEIGHT RUST_MINE_HASH RUST_MINE_TX_COUNT
  python3 - <<'PY'
import json, os
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
tx_mode = tx_path_mode in {"1", "2"}
converge_mode = tx_path_mode == "2"
report = {
    "scenario": "mixed_client_go_submit_rust_mine_go_converge" if converge_mode else "mixed_client_go_submit_rust_accept" if tx_mode else "mixed_client_mesh",
    "verdict": verdict,
    "artifact_root": e["RUBIN_PROCESS_ARTIFACT_ROOT"],
    "nodes": nodes,
    "peer_connectivity": {
        "go_to_rust": verdict == "PASS",
        "rust_to_go": verdict == "PASS",
        "bidirectional_observed": verdict == "PASS",
        "counterpart_links": {"go_peer_snapshot_expected_addr": e.get("RUST_TO_GO_LOCAL_ADDR") or None, "rust_peer_snapshot_expected_addr": e.get("GO_P2P_ADDR") or None, "rust_outbound_local_addr": e.get("RUST_TO_GO_LOCAL_ADDR") or None, "rust_outbound_remote_addr": e.get("GO_P2P_ADDR") or None, "rust_outbound_pid": int(e["RUST_PID"]) if e.get("RUST_PID", "").isdigit() else None},
        "go_peer_snapshot": go_snapshot,
        "rust_peer_snapshot": rust_snapshot,
    },
    "final_verification": {"producer_side": verdict == "PASS", "process_identity_rechecked": e.get("FINAL_PROCESS_IDENTITY_RECHECKED") == "true", "rust_outbound_link_rechecked": e.get("FINAL_RUST_OUTBOUND_LINK_RECHECKED") == "true", "peer_snapshots_rechecked": e.get("FINAL_PEER_SNAPSHOTS_RECHECKED") == "true", "rust_outbound_pid": int(e["RUST_PID"]) if e.get("RUST_PID", "").isdigit() else None, "rust_outbound_local_addr": e.get("RUST_TO_GO_LOCAL_ADDR") or None, "rust_outbound_remote_addr": e.get("GO_P2P_ADDR") or None},
    "legacy_schema_compatibility": {
        "authoritative": False,
        "marker_path": e["LEGACY_SCHEMA_MARKER_JSON"],
        "purpose": "schema-valid legacy artifact only; not the mesh report verdict",
        "reason": "existing mixed_client_evidence_v1 PASS requires tx_path; RUB-21 mesh-only PASS lives in this report",
    },
}
if tx_mode and verdict == "PASS":
    tx_path = {"submitted_at": "node-go", "observed_at": ["node-rust"], "tx_id": e["TX_ID"]}
    report["tx_path"] = tx_path
    report["go_submit"] = {"txid": e["TX_ID"], "tx_hex": e["TX_HEX"], "rpc_endpoint": e["GO_RPC_ADDR"], "tx_status_path": e["GO_SUBMIT_STATUS_JSON"], "get_tx_path": e["GO_SUBMIT_GET_TX_JSON"]}
    report["rust_accept"] = {"txid": e["TX_ID"], "raw_hex": e["TX_HEX"], "rpc_endpoint": e["RUST_RPC_ADDR"], "tx_status_path": e["RUST_STATUS_JSON"], "get_tx_path": e["RUST_GET_TX_JSON"]}
    if converge_mode:
        report["rust_mine"] = {"block_hash": e["RUST_MINE_HASH"], "block_path": e["RUST_MINE_BLOCK_JSON"], "class": "mined_included", "height": int(e["RUST_MINE_HEIGHT"]), "mine_next_path": e["RUST_MINE_JSON"], "mined_by": "node-rust", "raw_hex": e["TX_HEX"], "rpc_endpoint": e["RUST_RPC_ADDR"], "tx_count": int(e["RUST_MINE_TX_COUNT"]), "txid": e["TX_ID"]}
        report["go_converge"] = {"block_hash": e["RUST_MINE_HASH"], "block_path": e["GO_CONVERGE_BLOCK_JSON"], "class": "canonical_block_found", "converged_at": "node-go", "height": int(e["RUST_MINE_HEIGHT"]), "raw_hex": e["TX_HEX"], "rpc_endpoint": e["GO_RPC_ADDR"], "tip_path": e["GO_CONVERGE_TIP_JSON"], "txid": e["TX_ID"]}
if verdict != "PASS":
    report["failure_reason"] = reason or "mixed-client mesh did not produce PASS evidence"
with open(e["REPORT_JSON"], "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)
    f.write("\n")
legacy_marker_reason = reason if verdict != "PASS" and reason else "mixed-client mesh process/connectivity PASS is recorded in sibling report; existing schema v1 PASS requires tx_path proof owned by RUB-22/RUB-23"
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
start_rust_node() {
  local -a argv=("${RUST_NODE_BIN}" --network devnet --datadir "${RUST_DIR}" --bind 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --peer "${GO_P2P_ADDR}")
  START_REASON=""
  RUST_CMD="$(argv_cmd "${argv[@]}")"; RUST_ARGV_JSON="$(argv_json "${argv[@]}")"
  rubin_process_start "${RUST_LOG}" "${argv[@]}" || { START_REASON=rust_launch_failed; return 1; }; RUST_PID="${RUBIN_PROCESS_LAST_PID}"
  rubin_process_wait_for_log "${RUST_LOG}" "p2p: listening=" 60 "${RUST_PID}" || { START_REASON=rust_p2p_log_wait_failed; return 1; }
  rubin_process_wait_for_log "${RUST_LOG}" "rpc: listening=" 60 "${RUST_PID}" || { START_REASON=rust_rpc_log_wait_failed; return 1; }
  RUST_P2P_ADDR="$(extract_log_addr "${RUST_LOG}" "p2p: listening=")" || { START_REASON=rust_p2p_addr_extract_failed; return 1; }; loopback_endpoint "${RUST_P2P_ADDR}" || finish_no_data "rust_p2p_addr_malformed"
  RUST_RPC_ADDR="$(rubin_process_extract_rpc_addr "${RUST_LOG}")" || { START_REASON=rust_rpc_addr_extract_failed; return 1; }; loopback_endpoint "${RUST_RPC_ADDR}" || finish_no_data "rust_rpc_addr_malformed"
  rubin_process_wait_for_rpc_ready "${RUST_RPC_ADDR}" 30 || { START_REASON=rust_rpc_ready_timeout; return 1; }; RUST_STARTED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
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
if (( TX_PATH_MODE >= 1 )); then prepare_tx_chainstate || finish_no_data "${TX_REASON:-go_submit_chainstate_prepare_failed}"; fi
start_go_node || finish_no_data "${START_REASON:-go_process_not_ready}"
verify_process_identity node-go go "${GO_PID}" "${GO_RPC_ADDR}" "${GO_P2P_ADDR}" rubin-node-go go_process_identity || finish_no_data "${PROCESS_IDENTITY_REASON:-go_process_identity_unverified}"
start_rust_node || finish_no_data "${START_REASON:-rust_process_not_ready}"
verify_process_identity node-rust rust "${RUST_PID}" "${RUST_RPC_ADDR}" "${RUST_P2P_ADDR}" rubin-node-rust rust_process_identity || finish_no_data "${PROCESS_IDENTITY_REASON:-rust_process_identity_unverified}"
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
if (( TX_PATH_MODE >= 1 )); then
  submit_go_tx || finish_no_data "${TX_REASON:-go_submit_failed}"
  wait_rust_accept || finish_no_data "${TX_REASON:-rust_accept_failed}"
  if (( TX_PATH_MODE == 2 )); then
    rust_mine_including_tx || finish_no_data "${TX_REASON:-rust_mine_failed}"
    wait_go_converge_to_rust_mined_block || finish_no_data "${TX_REASON:-go_converge_failed}"
  fi
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
else
  if ! check_err="$(check_report "${PASS_REPORT_JSON}" live 2>&1)"; then
    rm -f -- "${PASS_REPORT_JSON}"; finish_no_data "pass_report_live_validation_$(check_report_reason_token <<<"${check_err}")"
  fi
fi
mv -- "${PASS_REPORT_JSON}" "${REPORT_JSON}" || finish_no_data "pass_report_publish_failed"
PASS_SCENARIO="mixed-client mesh connected"; (( TX_PATH_MODE == 1 )) && PASS_SCENARIO="Go-submit/Rust-accept path observed"; (( TX_PATH_MODE == 2 )) && PASS_SCENARIO="Go-submit/Rust-mine/Go-converge path observed"
[[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]] && echo "PASS: ${PASS_SCENARIO} go_pid=${GO_PID} rust_pid=${RUST_PID}; report=${REPORT_JSON} legacy_schema_marker=${LEGACY_SCHEMA_MARKER_JSON}" || echo "PASS: ${PASS_SCENARIO} go_pid=${GO_PID} rust_pid=${RUST_PID}; set KEEP_TMP=1 to retain report"

#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV_ENV="${REPO_ROOT}/scripts/dev-env.sh"; GO_MODULE_ROOT="${REPO_ROOT}/clients/go"
RUST_WORKSPACE_ROOT="${REPO_ROOT}/clients/rust"; HELPER="${REPO_ROOT}/scripts/devnet-process-common.sh"; VALIDATOR="${REPO_ROOT}/scripts/devnet/validate_mixed_client_evidence.py"
CHECK_REPORT="" CHECK_REPORT_MODE="" MESH_TIMEOUT="${MESH_TIMEOUT:-90}" TX_PATH_MODE=0 DETERMINISTIC_TX_FEE="${DETERMINISTIC_TX_FEE:-10000}"
usage() { echo "usage: $0 [--go-submit-rust-accept] [--check-report PATH|--check-report-live PATH]" >&2; }
while (($#)); do case "$1" in --go-submit-rust-accept) TX_PATH_MODE=1; shift ;; --check-report|--check-report-live) [[ $# -ge 2 ]] || { usage; exit 2; }; CHECK_REPORT_MODE=offline; [[ "$1" == "--check-report-live" ]] && CHECK_REPORT_MODE=live; CHECK_REPORT="$2"; shift 2 ;; -h|--help) usage; exit 0 ;; *) usage; exit 2 ;; esac; done
need_tool() { command -v -- "$1" >/dev/null 2>&1 || { echo "$1 is required for mixed-client mesh evidence" >&2; exit 1; }; }
validate_deterministic_tx_fee() {
  [[ "${DETERMINISTIC_TX_FEE}" =~ ^[0-9]{1,10}$ ]] || { echo "DETERMINISTIC_TX_FEE must be a positive integer <= 9999999999" >&2; exit 2; }
  DETERMINISTIC_TX_FEE="$((10#${DETERMINISTIC_TX_FEE}))"
  (( DETERMINISTIC_TX_FEE > 0 )) || { echo "DETERMINISTIC_TX_FEE must be a positive integer <= 9999999999" >&2; exit 2; }
  export DETERMINISTIC_TX_FEE
}
run_validator() { RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- python3 "${VALIDATOR}" "$@"; }
check_report() { local report="${1:-}" mode="${2:-offline}" expected_mode="${3:-auto}"
  [[ "${expected_mode}" != auto || "${TX_PATH_MODE:-0}" != "1" ]] || expected_mode=tx
  [[ -n "${report}" ]] || { echo "FAIL: report path is required" >&2; return 1; }
  RUBIN_OPENSSL_SKIP_FIPS_GUARD=1 "${DEV_ENV}" -- python3 - "${report}" "${VALIDATOR}" "${mode}" "${GO_MODULE_ROOT}" "${expected_mode}" <<'PY'
import datetime as dt, json, os, shutil, socket, struct, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path
path = Path(sys.argv[1]); live = sys.argv[3] == "live"
expected_mode = sys.argv[5]
MAX_REPORT_JSON_BYTES = 2 << 20
MAX_REPORT_TX_HEX_CHARS = 2 << 20
def fail(message: str) -> None: print(f"FAIL: {message}", file=sys.stderr); sys.exit(1)
try: LIVE_TIMEOUT = int(os.environ["MESH_TIMEOUT"])
except (KeyError, ValueError): fail("MESH_TIMEOUT must be an integer in [1, 600]")
def req(ok: bool, message: str) -> None:
    if not ok: fail(message)
def decode_json_bytes(label: str, raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        fail(f"malformed JSON {label}: {exc}")
def load_json_file(label: str, json_path: Path) -> object:
    try:
        req(json_path.is_file(), f"{label} is not a regular file")
        with json_path.open("rb") as f:
            raw = f.read(MAX_REPORT_JSON_BYTES + 1)
    except OSError as exc:
        fail(f"cannot read {label}: {exc}")
    req(raw != b"", f"{label} missing or empty")
    req(len(raw) <= MAX_REPORT_JSON_BYTES, f"{label} exceeds devnet report maximum")
    return decode_json_bytes(label, raw)
def http_json(url: str, oversized_message: str, malformed_message: str) -> object:
    with urllib.request.urlopen(url, timeout=5) as resp:
        raw = resp.read(MAX_REPORT_JSON_BYTES + 1)
    req(len(raw) <= MAX_REPORT_JSON_BYTES, oversized_message)
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        fail(f"{malformed_message}: {exc}")
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
SECRET_KEY_FRAGMENTS = ("secret", "private", "from_der", "from_key", "token", "password", "credential")
def req_no_secret_keys(label: str, value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            req(not any(fragment in lowered for fragment in SECRET_KEY_FRAGMENTS), f"{label} carries secret-looking key: {key}")
            req_no_secret_keys(f"{label}.{key}", child)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            req_no_secret_keys(f"{label}[{index}]", child)
def req_exact_keys(label: str, value: dict, allowed: set[str]) -> None:
    req_no_secret_keys(label, value)
    keys = set(value)
    req(keys == allowed, f"{label} has unexpected or missing keys: {sorted(keys ^ allowed)}")
def parse_txid(txhex: str) -> str:
    go_bin = shutil.which("go")
    req(go_bin is not None, "go toolchain unavailable for tx_identity parser")
    try:
        proc = subprocess.run(
            [go_bin, "-C", sys.argv[4], "run", "./cmd/rubin-consensus-cli"],
            input=json.dumps({"op": "parse_tx", "tx_hex": txhex}) + "\n",
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        fail("tx_identity parser timeout")
    except OSError as exc:
        fail(f"tx_identity parser tool failure: {exc.__class__.__name__}")
    if proc.returncode != 0:
        fail(f"tx_identity parser nonzero exit: {proc.returncode}")
    req(len(proc.stdout.encode("utf-8", "surrogateescape")) <= 65536, "tx_identity parser stdout malformed: oversized")
    try:
        parsed = json.loads(proc.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as exc:
        fail(f"tx_identity parser stdout malformed: {exc.__class__.__name__}")
    req(isinstance(parsed, dict) and parsed.get("ok") is True, "tx_identity parser stdout malformed: rejected tx")
    try:
        tx_len = len(bytes.fromhex(txhex))
    except ValueError:
        fail("tx_identity parser input is not canonical hex")
    req(isinstance(parsed.get("consumed"), int) and not isinstance(parsed.get("consumed"), bool) and parsed["consumed"] == tx_len, "tx_identity parser stdout malformed: consumed length mismatch")
    parsed_txid = parsed.get("txid")
    req(isinstance(parsed_txid, str) and len(parsed_txid) == 64 and all(c in "0123456789abcdef" for c in parsed_txid), "tx_identity parser stdout malformed: txid")
    return parsed_txid
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
def argv_eq(actual: list[str], expected: list[str]) -> bool: return len(actual) == len(expected) and bool(actual) and checked_path("live argv[0]", actual[0]) == checked_path("report command_argv[0]", expected[0]) and actual[1:] == expected[1:]
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
        data = http_json(f"http://{addr}/peers", "live peer snapshot exceeds devnet report maximum", f"live peer snapshot malformed JSON for {addr}")
    except (urllib.error.URLError, TimeoutError, socket.timeout):
        return None
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        fail(f"live peer snapshot malformed JSON for {addr}: {exc}")
    req(isinstance(data, dict), f"live peer snapshot malformed JSON for {addr}")
    return data
def live_tx_pending_found(label: str, addr: str, txid: str, txhex: str) -> None:
    deadline = time.monotonic() + LIVE_TIMEOUT
    saw_success = False
    while True:
        try:
            status = http_json(f"http://{addr}/tx_status?txid={txid}", f"{label}_rpc_body_oversized", f"{label}_malformed_rpc_body")
            req(isinstance(status, dict), f"{label}_malformed_rpc_body")
            saw_success = True
            status_txid = status.get("txid")
            status_value = status.get("status")
            if isinstance(status_txid, str) and status_txid != txid:
                fail(f"{label}_wrong_tx_identity")
            req(status_txid == txid and status_value in {"missing", "pending"}, f"{label}_malformed_rpc_body")
            if status_value == "pending":
                try:
                    got = http_json(f"http://{addr}/get_tx?txid={txid}", f"{label}_rpc_body_oversized", f"{label}_malformed_rpc_body")
                except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError):
                    fail(f"{label}_malformed_rpc_body")
                except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, socket.timeout):
                    fail(f"{label}_rpc_failed")
                req(isinstance(got, dict), f"{label}_malformed_rpc_body")
                saw_success = True
                req(isinstance(got.get("found"), bool), f"{label}_malformed_rpc_body")
                req(got.get("found") is True, f"{label}_get_tx_missing")
                req(got.get("txid") == txid and got.get("raw_hex") == txhex, f"{label}_wrong_tx_identity")
                return
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError):
            fail(f"{label}_malformed_rpc_body")
        except urllib.error.HTTPError:
            pass
        except (urllib.error.URLError, TimeoutError, socket.timeout):
            pass
        if time.monotonic() >= deadline:
            fail(f"{label}_pending_timeout" if saw_success else f"{label}_rpc_failed")
        time.sleep(1)
def snapshot_norm(label: str, snapshot: object, expected_addr: str, exact: bool = True) -> list[tuple[str, bool]]:
    req(isinstance(snapshot, dict), f"{label} is not an object")
    req_exact_keys(label, snapshot, {"count", "peers"})
    count = snapshot.get("count")
    peers = snapshot.get("peers")
    req(isinstance(count, int) and not isinstance(count, bool) and isinstance(peers, list) and count == len(peers), "peer snapshot count/peers are invalid")
    peer_proof_keys = {"addr", "handshake_complete"}
    live_metadata_keys = {"ban_score", "best_height", "da_mempool_size", "last_error", "protocol_version", "pruned_below_height", "tx_relay"}
    allowed_peer_keys = peer_proof_keys | live_metadata_keys if label.startswith("live ") else peer_proof_keys
    for index, peer in enumerate(peers):
        req(isinstance(peer, dict), "peer snapshot entries are malformed or duplicated")
        req_exact_keys(f"{label}.peers[{index}]", peer, allowed_peer_keys)
    norm = sorted((p.get("addr"), p.get("handshake_complete")) for p in peers if isinstance(p, dict) and ep(p.get("addr")) and isinstance(p.get("handshake_complete"), bool))
    req(len(norm) == len(peers) and len({addr for addr, _ in norm}) == len(norm), "peer snapshot entries are malformed or duplicated")
    if exact: req(norm == [(expected_addr, True)], "peer snapshot has unexpected peer set")
    return norm
def ts(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 20 or value[-1] != "Z": return False
    try: return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%dT%H:%M:%SZ") == value
    except ValueError: return False
data = load_json_file("report", path)
req(isinstance(data, dict), "report root is not an object")
scenario = data.get("scenario")
req(scenario in {"mixed_client_mesh", "mixed_client_go_submit_rust_accept"}, f"scenario is not recognized: {scenario!r}")
tx_mode = scenario == "mixed_client_go_submit_rust_accept"
req(expected_mode in {"auto", "tx", "producer-tx"}, f"check_report expected mode is invalid: {expected_mode!r}")
if expected_mode in {"tx", "producer-tx"}:
    req(tx_mode, "report scenario does not match requested tx-path mode")
if tx_mode:
    req_exact_keys("tx report", data, {"artifact_root", "final_verification", "go_submit", "legacy_schema_compatibility", "nodes", "peer_connectivity", "rust_accept", "scenario", "tx_path", "verdict"})
else:
    req_exact_keys("mesh report", data, {"artifact_root", "final_verification", "legacy_schema_compatibility", "nodes", "peer_connectivity", "scenario", "verdict"})
req(data.get("verdict") == "PASS", f"report verdict is not PASS: {data.get('verdict')!r}")
req("failure_reason" not in data and "schema_marker" not in data, "PASS report must not carry failure/schema-marker verdict fields")
if tx_mode and expected_mode != "producer-tx":
    fail("tx-path check-report is structural-only and cannot prove Go-submit evidence")
artifact_root_arg = data.get("artifact_root"); artifact_root = checked_path("artifact_root", artifact_root_arg)
legacy_schema = data.get("legacy_schema_compatibility")
req(isinstance(legacy_schema, dict), "legacy_schema_compatibility missing marker_path")
req_exact_keys("legacy_schema_compatibility", legacy_schema, {"authoritative", "marker_path", "purpose", "reason"})
req(isinstance(legacy_schema, dict) and legacy_schema.get("authoritative") is False and "verdict" not in legacy_schema and nonempty_str(legacy_schema.get("marker_path")), "legacy_schema_compatibility missing marker_path")
marker_path = checked_path("legacy_schema_compatibility.marker_path", legacy_schema.get("marker_path"))
try: marker_path.relative_to(artifact_root)
except ValueError: fail("legacy marker is outside artifact_root")
marker = load_json_file("legacy marker", marker_path)
req(isinstance(marker, dict), "legacy marker root is not an object")
req_exact_keys("schema marker", marker, {"evidence_type", "participants", "scenario", "schema_version", "tx_path", "verdict"} if tx_mode else {"evidence_type", "failure_reason", "participants", "scenario", "schema_version", "verdict"})
req(isinstance(marker, dict) and marker.get("scenario") == "mixed_client_mesh_schema_marker" and marker.get("evidence_type") == "mixed_client_process_soak", "legacy marker has wrong scenario/evidence_type")
marker_participants = marker.get("participants")
req(isinstance(marker_participants, list), "schema marker participants differ from report roles")
req(len(marker_participants) == 2 and all(isinstance(p, dict) for p in marker_participants), "schema marker participants differ from report roles")
for participant in marker_participants:
    req_exact_keys("schema marker participant", participant, {"endpoint", "implementation", "name", "started_at"})
if tx_mode:
    req(marker.get("verdict") == "PASS" and isinstance(marker.get("tx_path"), dict), "tx-path report requires schema-valid PASS marker with tx_path")
else:
    req(marker.get("verdict") == "FAIL", "mesh report requires non-authoritative FAIL marker")
try: validator = subprocess.run([sys.executable, sys.argv[2], str(marker_path)], check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
except (OSError, subprocess.TimeoutExpired) as exc: fail(f"legacy marker schema validation failed: {exc}")
req(validator.returncode == 0, "legacy marker schema validation failed: " + ((validator.stderr or validator.stdout).strip().splitlines() or ["validator returned nonzero"])[0])
nodes = data.get("nodes")
req(isinstance(nodes, list) and len(nodes) == 2 and all(isinstance(n, dict) for n in nodes), "PASS report requires exactly two node records")
expected = {"go": ("node-go", "rubin-node-go"), "rust": ("node-rust", "rubin-node-rust")}
for node in nodes:
    req_exact_keys("node record", node, {"binary", "command", "command_argv", "implementation", "name", "p2p_endpoint", "p2p_endpoint_process_backed", "pid", "process_alive", "process_comm", "rpc_endpoint", "rpc_endpoint_process_backed", "started_at"})
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
req(nodes_by_impl["go"]["command_argv"] == [nodes_by_impl["go"]["binary"], "--network", "devnet", "--datadir", str(Path(artifact_root_arg) / "node-go"), "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0"] and nodes_by_impl["rust"]["command_argv"] == [nodes_by_impl["rust"]["binary"], "--network", "devnet", "--datadir", str(Path(artifact_root_arg) / "node-rust"), "--bind", "127.0.0.1:0", "--rpc-bind", "127.0.0.1:0", "--peer", nodes_by_impl["go"]["p2p_endpoint"]], "node command_argv does not match exact launched argv")
req(nodes_by_impl["go"]["pid"] != nodes_by_impl["rust"]["pid"], "go/rust process evidence uses the same pid")
req(nodes_by_impl["go"]["binary"] != nodes_by_impl["rust"]["binary"] and nodes_by_impl["go"]["command"] != nodes_by_impl["rust"]["command"] and nodes_by_impl["go"].get("command_argv") != nodes_by_impl["rust"].get("command_argv"), "go/rust process evidence is not implementation-distinct")
req(len({nodes_by_impl[i][f] for i in ("go", "rust") for f in ("rpc_endpoint", "p2p_endpoint")}) == 4, "node rpc/p2p endpoints are not pairwise distinct")
connectivity = data.get("peer_connectivity")
req(isinstance(connectivity, dict), "PASS report missing peer_connectivity object")
req_exact_keys("peer_connectivity", connectivity, {"bidirectional_observed", "counterpart_links", "go_peer_snapshot", "go_to_rust", "rust_peer_snapshot", "rust_to_go"})
req(all(connectivity.get(f) is True for f in ("go_to_rust", "rust_to_go", "bidirectional_observed")), "peer_connectivity booleans are not all true")
req(isinstance(links := connectivity.get("counterpart_links"), dict), "PASS report missing counterpart_links")
req_exact_keys("counterpart_links", links, {"go_peer_snapshot_expected_addr", "rust_outbound_local_addr", "rust_outbound_pid", "rust_outbound_remote_addr", "rust_peer_snapshot_expected_addr"})
go_expected, rust_expected = links.get("go_peer_snapshot_expected_addr"), links.get("rust_peer_snapshot_expected_addr")
req(all(ep(links.get(f)) for f in ("go_peer_snapshot_expected_addr", "rust_peer_snapshot_expected_addr", "rust_outbound_local_addr", "rust_outbound_remote_addr")), "counterpart link endpoint is malformed")
req(rust_expected == nodes_by_impl["go"]["p2p_endpoint"] and links.get("rust_outbound_remote_addr") == rust_expected and links.get("rust_outbound_local_addr") == go_expected and links.get("rust_outbound_pid") == nodes_by_impl["rust"]["pid"], "peer evidence is not bound to expected counterpart endpoints")
req(isinstance(go_expected, str) and go_expected not in {rust_expected, nodes_by_impl["rust"]["p2p_endpoint"], nodes_by_impl["go"]["rpc_endpoint"], nodes_by_impl["rust"]["rpc_endpoint"]}, "go peer evidence is not a rust outbound peer address")
if live:
    eventually(lambda: f"{go_expected}->{rust_expected}" in lsof_lines(nodes_by_impl["rust"]["pid"], "ESTABLISHED"), "rust outbound TCP link is not live and rust-owned")
final = data.get("final_verification")
req(isinstance(final, dict) and all(final.get(f) is True for f in ("producer_side", "process_identity_rechecked", "rust_outbound_link_rechecked", "peer_snapshots_rechecked")), "PASS report missing producer-side final verification")
req_exact_keys("final_verification", final, {"peer_snapshots_rechecked", "process_identity_rechecked", "producer_side", "rust_outbound_link_rechecked", "rust_outbound_local_addr", "rust_outbound_pid", "rust_outbound_remote_addr"})
req(final.get("rust_outbound_pid") == nodes_by_impl["rust"]["pid"] and final.get("rust_outbound_local_addr") == go_expected and final.get("rust_outbound_remote_addr") == rust_expected, "final verification is not bound to peer evidence")
for field, expected_addr in (("go_peer_snapshot", go_expected), ("rust_peer_snapshot", rust_expected)):
    stored = snapshot_norm(field, connectivity.get(field), expected_addr)
    if live:
        endpoint = nodes_by_impl["go" if field.startswith("go_") else "rust"]["rpc_endpoint"]
        eventually(lambda endpoint=endpoint, stored=stored, field=field, expected_addr=expected_addr: (fresh := peers(endpoint)) is not None and stored == snapshot_norm(f"live {field}", fresh, expected_addr, False), f"{field} differs from live exact peer set")
if tx_mode:
    tx_path = data.get("tx_path")
    go_submit = data.get("go_submit")
    rust_accept = data.get("rust_accept")
    req(isinstance(tx_path, dict) and isinstance(go_submit, dict) and isinstance(rust_accept, dict), "tx-path report missing tx_path/go_submit/rust_accept")
    req_exact_keys("tx_path", tx_path, {"observed_at", "submitted_at", "tx_id"})
    req_exact_keys("go_submit", go_submit, {"accepted", "get_tx_path", "rpc_endpoint", "submit_response_path", "tx_hex", "tx_status_path", "txid"})
    req_exact_keys("rust_accept", rust_accept, {"class", "get_tx_path", "raw_hex", "rpc_endpoint", "tx_status_path", "txid"})
    txid = tx_path.get("tx_id")
    txhex = go_submit.get("tx_hex")
    req(isinstance(txid, str) and len(txid) == 64 and all(c in "0123456789abcdef" for c in txid), "tx_path.tx_id is not canonical hex")
    req(tx_path.get("submitted_at") == "node-go" and tx_path.get("observed_at") == ["node-rust"], "tx_path is not Go-submit -> Rust-observe")
    req(isinstance(txhex, str) and len(txhex) > 0 and len(txhex) % 2 == 0, "go_submit.tx_hex is not lowercase even hex")
    req(len(txhex) <= MAX_REPORT_TX_HEX_CHARS, "go_submit.tx_hex exceeds devnet report maximum")
    req(all(c in "0123456789abcdef" for c in txhex), "go_submit.tx_hex is not lowercase even hex")
    req(marker.get("tx_path") == tx_path, "schema marker tx_path differs from report tx_path")
    nodes_by_name = {node["name"]: node for node in nodes}
    marker_roles = {p.get("name"): p.get("implementation") for p in marker_participants}
    req(marker_roles == {"node-go": "go", "node-rust": "rust"}, "schema marker participants differ from report roles")
    participant_bindings = {
        "implementation": "implementation",
        "endpoint": "rpc_endpoint",
        "rpc_endpoint": "rpc_endpoint",
        "p2p_endpoint": "p2p_endpoint",
        "started_at": "started_at",
        "pid": "pid",
        "process_comm": "process_comm",
        "binary": "binary",
        "command": "command",
        "command_argv": "command_argv",
    }
    for participant in marker_participants:
        node = nodes_by_name.get(participant.get("name"))
        req(node is not None, "schema marker participant identity differs from report node identity")
        req(participant.get("endpoint") == node["rpc_endpoint"], "schema marker participant identity differs from report node identity")
        req(participant.get("started_at") == node["started_at"], "schema marker participant identity differs from report node identity")
        for marker_field, report_field in participant_bindings.items():
            if marker_field in participant and report_field in node:
                req(participant[marker_field] == node[report_field], "schema marker participant identity differs from report node identity")
    req(go_submit.get("accepted") is True and go_submit.get("txid") == txid and go_submit.get("rpc_endpoint") == nodes_by_impl["go"]["rpc_endpoint"], "go_submit is not bound to node-go txid")
    req(rust_accept.get("class") == "pending_found" and rust_accept.get("txid") == txid and rust_accept.get("rpc_endpoint") == nodes_by_impl["rust"]["rpc_endpoint"], "rust_accept is not pending_found for the submitted txid")
    req(rust_accept.get("raw_hex") == txhex, "rust_accept raw_hex does not match submitted tx")
    def sidecar(label: str, value: object, expected_name: str) -> dict:
        sidecar_path = checked_path(label, value)
        try:
            sidecar_path.relative_to(artifact_root)
        except ValueError:
            fail(f"{label} is outside artifact_root")
        req(sidecar_path == artifact_root / expected_name, f"{label} is not the expected artifact path")
        sidecar_data = load_json_file("sidecar artifact", sidecar_path)
        req(isinstance(sidecar_data, dict), f"{label} root is not an object")
        return sidecar_data
    submit_sidecar = sidecar("go_submit.submit_response_path", go_submit.get("submit_response_path"), "go-submit.json")
    status_sidecar = sidecar("rust_accept.tx_status_path", rust_accept.get("tx_status_path"), "rust-tx-status.json")
    get_tx_sidecar = sidecar("rust_accept.get_tx_path", rust_accept.get("get_tx_path"), "rust-get-tx.json")
    submit_status_sidecar = sidecar("go_submit.tx_status_path", go_submit.get("tx_status_path"), "go-tx-status.json")
    submit_get_tx_sidecar = sidecar("go_submit.get_tx_path", go_submit.get("get_tx_path"), "go-get-tx.json")
    req_exact_keys("go submit sidecar", submit_sidecar, {"accepted", "txid"})
    req_exact_keys("go submit tx_status sidecar", submit_status_sidecar, {"status", "txid"})
    req_exact_keys("go submit get_tx sidecar", submit_get_tx_sidecar, {"found", "raw_hex", "txid"})
    req_exact_keys("rust tx_status sidecar", status_sidecar, {"status", "txid"})
    req_exact_keys("rust get_tx sidecar", get_tx_sidecar, {"found", "raw_hex", "txid"})
    role_paths = [checked_path(label, value) for label, value in (
        ("go_submit.submit_response_path", go_submit.get("submit_response_path")),
        ("go_submit.tx_status_path", go_submit.get("tx_status_path")),
        ("go_submit.get_tx_path", go_submit.get("get_tx_path")),
        ("rust_accept.tx_status_path", rust_accept.get("tx_status_path")),
        ("rust_accept.get_tx_path", rust_accept.get("get_tx_path")),
    )]
    req(len(set(role_paths)) == len(role_paths), "tx sidecar artifact paths are not distinct")
    req(submit_sidecar.get("accepted") is True and submit_sidecar.get("txid") == txid, "go submit sidecar does not prove accepted txid")
    req(submit_status_sidecar.get("status") == "pending" and submit_status_sidecar.get("txid") == txid, "go submit tx_status sidecar does not prove pending stored txid")
    req(isinstance(submit_get_tx_sidecar.get("found"), bool), "go submit get_tx sidecar found flag is malformed")
    req(submit_get_tx_sidecar.get("found") is True, "go submit get_tx sidecar reports missing tx")
    req(submit_get_tx_sidecar.get("txid") == txid and submit_get_tx_sidecar.get("raw_hex") == txhex, "go submit get_tx sidecar does not prove raw tx identity")
    req(status_sidecar.get("status") == "pending" and status_sidecar.get("txid") == txid, "rust tx_status sidecar does not prove pending txid")
    req(isinstance(get_tx_sidecar.get("found"), bool), "rust get_tx sidecar found flag is malformed")
    req(get_tx_sidecar.get("found") is True, "rust get_tx sidecar reports missing tx")
    req(get_tx_sidecar.get("txid") == txid and get_tx_sidecar.get("raw_hex") == txhex, "rust get_tx sidecar does not prove raw tx identity")
    if not live:
        fail("tx-path offline check-report requires --check-report-live for admission proof")
    req(parse_txid(txhex) == txid, "tx_path.tx_id does not match parsed go_submit.tx_hex")
    if live:
        live_tx_pending_found("go_submit_live", nodes_by_impl["go"]["rpc_endpoint"], txid, txhex)
        live_tx_pending_found("rust_accept_live", nodes_by_impl["rust"]["rpc_endpoint"], txid, txhex)
else:
    req(all(field not in data for field in ("tx_path", "go_submit", "rust_accept")), "mesh report must not carry tx_path/go_submit/rust_accept")
print(f"PASS: mixed-client mesh report {'accepted' if live else 'structurally accepted'} {path}" + ("" if live else "; live proof not checked"))
PY
}
[[ "${MESH_TIMEOUT}" =~ ^[0-9]{1,3}$ ]] || { echo "MESH_TIMEOUT must be an integer in [1, 600]" >&2; exit 2; }; MESH_TIMEOUT="$((10#${MESH_TIMEOUT}))"; (( MESH_TIMEOUT >= 1 && MESH_TIMEOUT <= 600 )) || { echo "MESH_TIMEOUT must be an integer in [1, 600]" >&2; exit 2; }; export MESH_TIMEOUT
if [[ -n "${CHECK_REPORT_MODE}" ]]; then need_tool python3; check_report "${CHECK_REPORT}" "${CHECK_REPORT_MODE}"; exit 0; fi
if (( TX_PATH_MODE == 1 )); then validate_deterministic_tx_fee; fi
need_tool python3; [[ -x "${DEV_ENV}" ]] || { echo "dev-env wrapper missing or non-executable: ${DEV_ENV}" >&2; exit 1; }; [[ -r "${VALIDATOR}" ]] || { echo "validator unreadable: ${VALIDATOR}" >&2; exit 1; }
# shellcheck source=scripts/devnet-process-common.sh disable=SC1091
source "${HELPER}"
rubin_process_init mixed-client-mesh
GO_NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-go"; RUST_NODE_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-node-rust"
GO_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-go"; RUST_DIR="${RUBIN_PROCESS_ARTIFACT_ROOT}/node-rust"
GO_LOG="node-go.log"; RUST_LOG="node-rust.log"; REPORT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mixed-client-mesh-report.json"; LEGACY_SCHEMA_MARKER_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/mixed-client-mesh-legacy-schema-marker.json"
GO_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-peers.json"; RUST_PEERS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-peers.json"
GO_SUBMIT_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-submit.json"; GO_SUBMIT_STATUS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-tx-status.json"; GO_SUBMIT_GET_TX_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-get-tx.json"; RUST_STATUS_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-tx-status.json"; RUST_GET_TX_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/rust-get-tx.json"
TXGEN_BIN="${RUBIN_PROCESS_ARTIFACT_ROOT}/rubin-txgen"; KEYGEN_GO="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.go"; KEYGEN_JSON="${RUBIN_PROCESS_ARTIFACT_ROOT}/keygen.json"; MINE_LOG="mine-go.log"
GO_PID="" RUST_PID="" GO_RPC_ADDR="" RUST_RPC_ADDR="" GO_P2P_ADDR="" RUST_P2P_ADDR="" GO_STARTED_AT_UTC="" RUST_STARTED_AT_UTC="" GO_COMM="" RUST_COMM="" RUST_TO_GO_LOCAL_ADDR="" GO_CMD="" RUST_CMD="" GO_ARGV_JSON="" RUST_ARGV_JSON="" FINAL_PROCESS_IDENTITY_RECHECKED="" FINAL_RUST_OUTBOUND_LINK_RECHECKED="" FINAL_PEER_SNAPSHOTS_RECHECKED="" PROCESS_IDENTITY_REASON="" START_REASON="" BUILD_REASON="" TX_REASON="" TX_ID="" TX_HEX="" RUST_ACCEPT_CLASS="" TX_FROM_KEY_FILE="" TX_TO_KEY=""
mkdir -p -- "${GO_DIR}" "${RUST_DIR}"
run_fips_preflight_before_captured_dev_env() { [[ "${RUBIN_OPENSSL_FIPS_MODE:-off}" != "only" || "${RUBIN_OPENSSL_SKIP_FIPS_GUARD:-0}" == "1" ]] && return 0; echo "Running FIPS-only preflight before captured dev-env command streams" >&2; "${DEV_ENV}" -- "${REPO_ROOT}/scripts/crypto/openssl/fips-preflight.sh" >&2; }
bounded() { perl -e 'alarm shift @ARGV; exec @ARGV; die "exec failed: $!\n"' 5 "$@"; }
argv_cmd() { local out="" arg q; for arg; do printf -v q "%q" "$arg"; out+="${out:+ }${q}"; done; printf '%s\n' "${out}"; }; argv_json() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@"; }
loopback_endpoint() { local endpoint="${1:-}" port; [[ "${endpoint}" =~ ^127[.]0[.]0[.]1:([0-9]{1,5})$ ]] || return 1; port="${BASH_REMATCH[1]}"; (( 10#${port} >= 1 && 10#${port} <= 65535 )); }
disable_xtrace_for_secret() { case "$-" in *x*) set +x; return 0 ;; *) return 1 ;; esac; }
restore_xtrace_after_secret() { [[ "${1:-0}" == "1" ]] && set -x; return 0; }
cleanup_tx_from_key_file() {
  local xtrace_was_enabled=0
  if disable_xtrace_for_secret; then xtrace_was_enabled=1; fi
  local secret_file="${TX_FROM_KEY_FILE:-}" cleanup_status=0
  if [[ -n "${secret_file}" ]]; then
    rm -f -- "${secret_file}" || cleanup_status=$?
    TX_FROM_KEY_FILE=""
  fi
  restore_xtrace_after_secret "${xtrace_was_enabled}"
  return "${cleanup_status}"
}
cleanup_tx_from_key_file_for_failure() {
  local reason="$1" cleanup_status=0
  cleanup_tx_from_key_file || cleanup_status=$?
  if (( cleanup_status != 0 )); then
    TX_REASON=go_submit_keygen_cleanup_failed
    return "${cleanup_status}"
  fi
  TX_REASON="${reason}"
}
rubin_process_exit_trap_with_tx_secret_cleanup() {
  local status=$? cleanup_status=0
  cleanup_tx_from_key_file || cleanup_status=$?
  rubin_process_cleanup "${status}" || cleanup_status=$?
  [[ "${status}" != "0" ]] && exit "${status}"
  exit "${cleanup_status}"
}
trap rubin_process_exit_trap_with_tx_secret_cleanup EXIT
check_report_reason_token() { python3 -c 'import sys; msg=" ".join(x[5:].strip() for x in sys.stdin.read().splitlines() if x.startswith("FAIL:")); rules=[("tx-path check-report is structural-only and cannot prove Go-submit evidence","tx_path_check_report_structural_only"),("report scenario does not match requested tx-path mode","report_scenario_mismatch"),("mesh report must not carry tx_path/go_submit/rust_accept","mesh_tx_path_fields_forbidden"),("tx-path offline check-report requires --check-report-live","tx_path_offline_requires_live"),("tx report has unexpected or missing keys","tx_report_keys_invalid"),("mesh report has unexpected or missing keys","mesh_report_keys_invalid"),("tx_path has unexpected or missing keys","tx_path_keys_invalid"),("go_submit has unexpected or missing keys","go_submit_keys_invalid"),("rust_accept has unexpected or missing keys","rust_accept_keys_invalid"),("secret-looking key","pass_report_secret_field"),("legacy_schema_compatibility has unexpected or missing keys","legacy_schema_compatibility_keys_invalid"),("schema marker has unexpected or missing keys","legacy_marker_invalid"),("schema marker participant has unexpected or missing keys","legacy_marker_invalid"),("node record has unexpected or missing keys","node_record_keys_invalid"),("peer_connectivity has unexpected or missing keys","peer_connectivity_keys_invalid"),("counterpart_links has unexpected or missing keys","counterpart_links_keys_invalid"),("final_verification has unexpected or missing keys","final_verification_keys_invalid"),("go_peer_snapshot has unexpected or missing keys","peer_snapshot_invalid"),("rust_peer_snapshot has unexpected or missing keys","peer_snapshot_invalid"),(".peers[","peer_snapshot_invalid"),("go submit sidecar has unexpected or missing keys","go_submit_sidecar_invalid"),("go submit tx_status sidecar has unexpected or missing keys","go_submit_sidecar_invalid"),("go submit get_tx sidecar has unexpected or missing keys","go_submit_sidecar_invalid"),("rust tx_status sidecar has unexpected or missing keys","rust_accept_sidecar_invalid"),("rust get_tx sidecar has unexpected or missing keys","rust_accept_sidecar_invalid"),("report is not a regular file","report_not_regular"),("cannot read report","report_unreadable"),("malformed JSON report","report_malformed_json"),("report exceeds devnet report maximum","report_oversized"),("legacy marker is not a regular file","legacy_marker_invalid"),("legacy marker exceeds devnet report maximum","legacy_marker_oversized"),("_rpc_body_oversized","live_rpc_body_oversized"),("live peer snapshot exceeds devnet report maximum","live_peer_snapshot_oversized"),("go_submit_live_malformed_rpc_body","go_submit_live_malformed_rpc_body"),("go_submit_live_wrong_tx_identity","go_submit_live_wrong_tx_identity"),("go_submit_live_rpc_failed","go_submit_live_rpc_failed"),("go_submit_live_pending_timeout","go_submit_live_pending_timeout"),("go_submit_live_get_tx_missing","go_submit_live_get_tx_missing"),("rust_accept_live_malformed_rpc_body","rust_accept_live_malformed_rpc_body"),("rust_accept_live_wrong_tx_identity","rust_accept_live_wrong_tx_identity"),("rust_accept_live_rpc_failed","rust_accept_live_rpc_failed"),("rust_accept_live_pending_timeout","rust_accept_live_pending_timeout"),("rust_accept_live_get_tx_missing","rust_accept_live_get_tx_missing"),("tx-path report missing tx_path/go_submit/rust_accept","tx_path_fields_missing"),("tx_path.tx_id is not canonical hex","tx_identity_invalid"),("tx_path is not Go-submit -> Rust-observe","tx_path_direction_invalid"),("go_submit.tx_hex is not lowercase even hex","tx_identity_tx_hex_invalid"),("go_submit.tx_hex exceeds devnet report maximum","tx_identity_tx_hex_oversized"),("tx_path.tx_id does not match parsed go_submit.tx_hex","tx_identity_mismatch"),("go_submit is not bound to node-go txid","go_submit_identity_invalid"),("rust_accept is not pending_found for the submitted txid","rust_accept_class_invalid"),("rust_accept raw_hex does not match submitted tx","rust_accept_raw_mismatch"),("schema marker tx_path differs from report tx_path","schema_marker_tx_path_mismatch"),("schema marker participant identity differs from report node identity","schema_marker_participant_identity_mismatch"),("schema marker participants differ from report roles","schema_marker_roles_mismatch"),("go submit sidecar does not prove accepted txid","go_submit_response_invalid"),("go submit tx_status sidecar does not prove pending stored txid","go_submit_sidecar_invalid"),("go submit get_tx sidecar found flag is malformed","go_submit_sidecar_invalid"),("go submit get_tx sidecar reports missing tx","go_submit_get_tx_missing"),("go submit get_tx sidecar does not prove raw tx identity","go_submit_sidecar_invalid"),("rust tx_status sidecar does not prove pending txid","rust_accept_sidecar_invalid"),("rust get_tx sidecar found flag is malformed","rust_accept_sidecar_invalid"),("rust get_tx sidecar reports missing tx","rust_accept_get_tx_missing"),("rust get_tx sidecar does not prove raw tx identity","rust_accept_sidecar_invalid"),("go_submit keygen material is malformed","go_submit_keygen_invalid"),("go_submit.fee is malformed","go_submit_fee_invalid"),("go_submit.fee is below parsed tx weight","go_submit_fee_below_mempool_floor"),("go toolchain unavailable for tx_fee_floor parser","go_submit_fee_floor_parser_tool_failure"),("tx_fee_floor parser timeout","go_submit_fee_floor_parser_timeout"),("tx_fee_floor parser tool failure","go_submit_fee_floor_parser_tool_failure"),("tx_fee_floor parser nonzero exit","go_submit_fee_floor_parser_nonzero"),("tx_fee_floor parser stdout malformed","go_submit_fee_floor_parser_stdout_malformed"),("sidecar artifact is not a regular file","sidecar_artifact_invalid"),("sidecar artifact missing or empty","sidecar_artifact_invalid"),("malformed JSON sidecar artifact","sidecar_artifact_invalid"),("sidecar artifact exceeds devnet report maximum","sidecar_artifact_oversized"),("tx sidecar artifact paths are not distinct","sidecar_artifact_alias"),("txgen_command_argv_redacted is too large","txgen_argv_oversized"),("txgen_command_argv_redacted is malformed","txgen_argv_invalid"),("rust_accept.get_tx_path","rust_accept_sidecar_invalid"),("rust_accept.tx_status_path","rust_accept_sidecar_invalid"),("go_submit.submit_response_path","go_submit_sidecar_invalid"),("go_submit.tx_status_path","go_submit_sidecar_invalid"),("go_submit.get_tx_path","go_submit_sidecar_invalid"),("go toolchain unavailable for tx_identity parser","tx_identity_go_unavailable"),("tx_identity parser timeout","tx_identity_parser_timeout"),("tx_identity parser tool failure","tx_identity_parser_tool_failure"),("tx_identity parser nonzero exit","tx_identity_parser_nonzero"),("tx_identity parser stdout malformed","tx_identity_parser_stdout_malformed"),("tx_identity parser","tx_identity_parser_failed"),("txgen_command_argv_redacted","txgen_argv_invalid"),("txgen_command_argv","txgen_argv_invalid"),("txgen argv is not bound to executable artifact","txgen_executable_invalid"),("go_submit.keygen_path","go_submit_keygen_invalid"),("live peer snapshot malformed JSON","live_peer_snapshot_malformed_json"),("differs from live exact peer set","live_peer_snapshot_mismatch"),("live listeners are not pid-owned","live_listener_not_pid_owned"),("rust outbound TCP link is not live and rust-owned","rust_outbound_link_not_live"),("argv_unavailable","argv_unavailable"),("live process argv/executable does not match report","argv_mismatch"),("lsof_timeout","lsof_timeout"),("lsof_unavailable","lsof_unavailable"),("lsof_failed","lsof_failed"),("pid_exe_failed","pid_exe_failed"),("pid_exe_unavailable","pid_exe_unavailable"),("argv","argv_mismatch"),("same pid","same_pid"),("process_comm","process_identity_invalid"),("process_alive","process_identity_invalid"),("process-backed","process_identity_invalid"),("peer snapshot","peer_snapshot_invalid"),("legacy marker","legacy_marker_invalid"),("failure/schema-marker","pass_report_has_failure_fields"),("failure_reason","pass_report_has_failure_fields"),("root is not an object","report_root_invalid")]; print(next((t for p,t in rules if p in msg), "unknown"))'; }
rpc_json() {
  local method="$1" addr="$2" path="$3"
  python3 - "${method}" "${addr}" "${path}" <<'PY'
import socket, sys, urllib.error, urllib.request
method, addr, path = sys.argv[1:4]
req = urllib.request.Request(f"http://{addr}{path}", method=method)
try:
    with urllib.request.urlopen(req, timeout=5) as resp:
        raw = resp.read((2 << 20) + 1)
    if len(raw) > (2 << 20):
        sys.exit(24)
    print(raw.decode("utf-8"), end="")
except urllib.error.HTTPError as exc:
    try:
        raw = exc.read((2 << 20) + 1)
        if len(raw) > (2 << 20):
            sys.exit(24)
        print(raw.decode("utf-8"), end="")
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
        except (json.JSONDecodeError, RecursionError, ValueError): sys.exit(2)
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
	"fmt"
	"os"

	"github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"
)

func writePrivateKey(path string, derHex string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(derHex + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "private key output path required")
		os.Exit(2)
	}
	from, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		panic(err)
	}
	defer from.Close()
	to, err := consensus.NewMLDSA87Keypair()
	if err != nil {
		panic(err)
	}
	defer to.Close()
	der, err := from.PrivateKeyDER()
	if err != nil {
		panic(err)
	}
	derHex := hex.EncodeToString(der)
	if err := writePrivateKey(os.Args[1], derHex); err != nil {
		fmt.Fprintln(os.Stderr, "write private key failed")
		os.Exit(1)
	}
	out := map[string]string{
		"mine_address_hex": hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(from.PubkeyBytes())),
		"to_address_hex":   hex.EncodeToString(consensus.P2PKCovenantDataForPubkey(to.PubkeyBytes())),
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		panic(err)
	}
}
EOF
}
prepare_tx_chainstate() {
  local keygen_public_json mine_address rc tmp_parent xtrace_was_enabled=0
  TX_REASON=""
  build_go_txgen || { TX_REASON="${BUILD_REASON:-go_txgen_build_failed}"; return 1; }
  write_keygen || { TX_REASON=go_submit_keygen_write_failed; return 1; }
  tmp_parent="${TMPDIR:-/tmp}"
  if disable_xtrace_for_secret; then xtrace_was_enabled=1; fi
  TX_FROM_KEY_FILE="$(mktemp "${tmp_parent%/}/rubin-txgen-from-key.XXXXXXXXXX")" || { rc=$?; restore_xtrace_after_secret "${xtrace_was_enabled}"; TX_REASON=go_submit_keygen_temp_failed; return "${rc}"; }
  if [[ "${TX_FROM_KEY_FILE}" == "${RUBIN_PROCESS_ARTIFACT_ROOT}" || "${TX_FROM_KEY_FILE}" == "${RUBIN_PROCESS_ARTIFACT_ROOT}/"* ]]; then
    cleanup_tx_from_key_file || true
    restore_xtrace_after_secret "${xtrace_was_enabled}"
    TX_REASON=go_submit_keygen_temp_under_artifact_root
    return 1
  fi
  keygen_public_json="$("${DEV_ENV}" -- go -C "${GO_MODULE_ROOT}" run "${KEYGEN_GO}" "${TX_FROM_KEY_FILE}")" || { rc=$?; cleanup_tx_from_key_file_for_failure go_submit_keygen_failed || { restore_xtrace_after_secret "${xtrace_was_enabled}"; return 1; }; restore_xtrace_after_secret "${xtrace_was_enabled}"; return "${rc}"; }
  restore_xtrace_after_secret "${xtrace_was_enabled}"
  TX_TO_KEY="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["to_address_hex"])' <<<"${keygen_public_json}")" || { cleanup_tx_from_key_file_for_failure go_submit_keygen_material_malformed || return 1; return 1; }
  mine_address="$(python3 -c 'import json, sys; print(json.load(sys.stdin)["mine_address_hex"])' <<<"${keygen_public_json}")" || { cleanup_tx_from_key_file_for_failure go_submit_keygen_material_malformed || return 1; return 1; }
  python3 -c '
import json
import sys

data = json.load(sys.stdin)
required = {"mine_address_hex", "to_address_hex"}
if set(data) != required:
    raise SystemExit(2)
public = {
    "mine_address_hex": data["mine_address_hex"],
    "to_address_hex": data["to_address_hex"],
}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(public, f, indent=2, sort_keys=True)
    f.write("\n")
	' "${KEYGEN_JSON}" <<<"${keygen_public_json}" || { cleanup_tx_from_key_file_for_failure go_submit_keygen_write_failed || return 1; return 1; }
  rm -f -- "${KEYGEN_GO}" || { cleanup_tx_from_key_file_for_failure go_submit_keygen_cleanup_failed || return 1; return 1; }
  echo "Mining mature chainstate for Go-submit -> Rust-accept path" >&2
  "${GO_NODE_BIN}" --network devnet --datadir "${GO_DIR}" --mine-address "${mine_address}" --mine-blocks 101 --mine-exit >"$(_rubin_process_resolve_log "${MINE_LOG}")" 2>&1 || { cleanup_tx_from_key_file_for_failure go_submit_mine_failed || return 1; return 1; }
  cp -R -- "${GO_DIR}/." "${RUST_DIR}/" || { cleanup_tx_from_key_file_for_failure go_submit_chainstate_copy_failed || return 1; return 1; }
}
submit_go_tx() {
  local rc status=0 cleanup_status=0 err_file="${RUBIN_PROCESS_ARTIFACT_ROOT}/go-submit.err" xtrace_was_enabled=0
  TX_REASON=""
  if disable_xtrace_for_secret; then xtrace_was_enabled=1; fi
  local from_key_file="${TX_FROM_KEY_FILE:-}" to_key="${TX_TO_KEY}"
  if [[ -z "${from_key_file}" || -z "${to_key}" ]]; then
    cleanup_tx_from_key_file || true
    restore_xtrace_after_secret "${xtrace_was_enabled}"
    TX_REASON=go_submit_keygen_material_malformed
    return 1
  fi
  if [[ ! -f "${from_key_file}" ]]; then
    cleanup_tx_from_key_file || true
    restore_xtrace_after_secret "${xtrace_was_enabled}"
    TX_REASON=go_submit_keygen_material_malformed
    return 1
  fi
  local -a argv=("${TXGEN_BIN}" --datadir "${GO_DIR}" --from-key-file "${from_key_file}" --to-key "${to_key}" --amount 1 --fee "${DETERMINISTIC_TX_FEE}")
  TX_HEX="$("${argv[@]}" 2>"${err_file}")" || status=$?
  cleanup_tx_from_key_file || cleanup_status=$?
  restore_xtrace_after_secret "${xtrace_was_enabled}"
  (( cleanup_status == 0 )) || { TX_REASON=go_submit_keygen_cleanup_failed; return 1; }
  (( status == 0 )) || { TX_REASON=go_submit_txgen_failed; return 1; }
  python3 - "${TX_HEX}" >"${GO_SUBMIT_JSON}.parse-request" <<'PY' || { TX_REASON=tx_identity_malformed; return 1; }
import json
import sys

print(json.dumps({"op": "parse_tx", "tx_hex": sys.argv[1].strip()}))
PY
  TX_ID="$(python3 - "${DEV_ENV}" "${GO_MODULE_ROOT}" "${GO_SUBMIT_JSON}.parse-request" <<'PY'
import json
import os
import subprocess
import sys

dev_env, module_root, request_path = sys.argv[1:4]
try:
    request = open(request_path, encoding="utf-8")
except OSError:
    raise SystemExit(13)
with request:
    env = os.environ.copy()
    env["RUBIN_OPENSSL_SKIP_FIPS_GUARD"] = "1"
    try:
        proc = subprocess.run(
            [dev_env, "--", "go", "-C", module_root, "run", "./cmd/rubin-consensus-cli"],
            stdin=request,
            check=False,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit(12)
    except OSError:
        raise SystemExit(13)
if proc.returncode != 0:
    raise SystemExit(14)
if len(proc.stdout.encode("utf-8", "surrogateescape")) > 65536:
    raise SystemExit(15)
try:
    data = json.loads(proc.stdout)
except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
    raise SystemExit(15)
if data.get("ok") is not True:
    raise SystemExit(15)
txid = data.get("txid")
if not isinstance(txid, str) or len(txid) != 64 or any(c not in "0123456789abcdef" for c in txid):
    raise SystemExit(15)
print(txid)
PY
	)" || { rc=$?; case "${rc}" in 12) TX_REASON=tx_identity_parser_timeout ;; 13) TX_REASON=tx_identity_parser_tool_failure ;; 14) TX_REASON=tx_identity_parser_nonzero ;; 15) TX_REASON=tx_identity_parser_stdout_malformed ;; *) TX_REASON=tx_identity_parser_unknown_failure ;; esac; return 1; }
  python3 - "${TX_HEX}" >"${GO_SUBMIT_JSON}.fee-floor-request" <<'PY' || { TX_REASON=go_submit_fee_floor_request_failed; return 1; }
import json
import sys

print(json.dumps({"op": "tx_weight_and_stats", "tx_hex": sys.argv[1].strip()}))
PY
  TX_REQUIRED_FEE="$(python3 - "${DEV_ENV}" "${GO_MODULE_ROOT}" "${GO_SUBMIT_JSON}.fee-floor-request" <<'PY'
import json
import os
import subprocess
import sys

dev_env, module_root, request_path = sys.argv[1:4]
try:
    request = open(request_path, encoding="utf-8")
except OSError:
    raise SystemExit(13)
with request:
    env = os.environ.copy()
    env["RUBIN_OPENSSL_SKIP_FIPS_GUARD"] = "1"
    try:
        proc = subprocess.run(
            [dev_env, "--", "go", "-C", module_root, "run", "./cmd/rubin-consensus-cli"],
            stdin=request,
            check=False,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        raise SystemExit(12)
    except OSError:
        raise SystemExit(13)
if proc.returncode != 0:
    raise SystemExit(14)
if len(proc.stdout.encode("utf-8", "surrogateescape")) > 65536:
    raise SystemExit(15)
try:
    data = json.loads(proc.stdout)
except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
    raise SystemExit(15)
if data.get("ok") is not True:
    raise SystemExit(15)
weight = data.get("weight")
if not isinstance(weight, int) or isinstance(weight, bool) or weight <= 0:
    raise SystemExit(15)
print(weight)
PY
	)" || { rc=$?; case "${rc}" in 12) TX_REASON=go_submit_fee_floor_parser_timeout ;; 13) TX_REASON=go_submit_fee_floor_parser_tool_failure ;; 14) TX_REASON=go_submit_fee_floor_parser_nonzero ;; 15) TX_REASON=go_submit_fee_floor_parser_stdout_malformed ;; *) TX_REASON=go_submit_fee_floor_parser_unknown_failure ;; esac; return 1; }
  (( DETERMINISTIC_TX_FEE >= TX_REQUIRED_FEE )) || { TX_REASON=go_submit_fee_below_mempool_floor; return 1; }
  python3 - "${GO_RPC_ADDR}" "${TX_HEX}" "${GO_SUBMIT_JSON}" 2>"${err_file}" <<'PY' || status=$?
import json
import socket
import sys
import urllib.error
import urllib.request

addr, tx_hex, out_path = sys.argv[1:4]
body = json.dumps({"tx_hex": tx_hex.strip()}).encode("utf-8")
request = urllib.request.Request(
    f"http://{addr}/submit_tx",
    data=body,
    headers={"Content-Type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=5) as response:
        raw_bytes = response.read((2 << 20) + 1)
        if len(raw_bytes) > (2 << 20):
            raise SystemExit(19)
        raw = raw_bytes.decode("utf-8")
except urllib.error.HTTPError as exc:
    try:
        raw_bytes = exc.read((2 << 20) + 1)
        if len(raw_bytes) > (2 << 20):
            raise SystemExit(19)
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit(13)
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(raw)
    except OSError:
        raise SystemExit(17)
    raise SystemExit(16)
except UnicodeDecodeError:
    raise SystemExit(13)
except (urllib.error.URLError, TimeoutError, socket.timeout):
    raise SystemExit(12)
try:
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(raw)
except OSError:
    raise SystemExit(17)
PY
  case "${status}" in 0) ;; 12) TX_REASON=go_submit_rpc_failed; return 1 ;; 13) TX_REASON=go_submit_malformed_rpc_body; return 1 ;; 16) TX_REASON=go_submit_submit_response_rejected; return 1 ;; 17) TX_REASON=go_submit_artifact_write_failed; return 1 ;; 19) TX_REASON=go_submit_rpc_body_oversized; return 1 ;; *) TX_REASON=go_submit_unknown_failure; return 1 ;; esac
  status=0
  rpc_json GET "${GO_RPC_ADDR}" "/tx_status?txid=${TX_ID}" >"${GO_SUBMIT_STATUS_JSON}" 2>"${err_file}" || { rc=$?; case "${rc}" in 23) TX_REASON=go_submit_malformed_rpc_body ;; 24) TX_REASON=go_submit_rpc_body_oversized ;; *) TX_REASON=go_submit_rpc_failed ;; esac; return 1; }
  rpc_json GET "${GO_RPC_ADDR}" "/get_tx?txid=${TX_ID}" >"${GO_SUBMIT_GET_TX_JSON}" 2>"${err_file}" || { rc=$?; case "${rc}" in 23) TX_REASON=go_submit_malformed_rpc_body ;; 24) TX_REASON=go_submit_rpc_body_oversized ;; *) TX_REASON=go_submit_rpc_failed ;; esac; return 1; }
  python3 - "${TX_ID}" "${TX_HEX}" "${GO_SUBMIT_JSON}" "${GO_SUBMIT_STATUS_JSON}" "${GO_SUBMIT_GET_TX_JSON}" 2>"${err_file}" <<'PY' || status=$?
import json
import sys

txid, tx_hex, submit_path, status_path, get_path = sys.argv[1:6]
try:
    with open(submit_path, encoding="utf-8") as f:
        submit = json.load(f)
    with open(status_path, encoding="utf-8") as f:
        status = json.load(f)
    with open(get_path, encoding="utf-8") as f:
        got = json.load(f)
except (json.JSONDecodeError, RecursionError, ValueError):
    raise SystemExit(13)
except UnicodeDecodeError:
    raise SystemExit(13)
except OSError:
    raise SystemExit(12)
if not isinstance(submit, dict) or not isinstance(status, dict) or not isinstance(got, dict):
    raise SystemExit(13)
if submit.get("accepted") is not True or submit.get("txid") != txid:
    raise SystemExit(15)
status_txid = status.get("txid")
status_value = status.get("status")
if isinstance(status_txid, str) and status_txid != txid:
    raise SystemExit(15)
if status_txid != txid or status_value not in {"missing", "pending"}:
    raise SystemExit(13)
if status_value != "pending":
    raise SystemExit(14)
if not isinstance(got.get("found"), bool):
    raise SystemExit(13)
if got.get("found") is not True:
    raise SystemExit(18)
if got.get("txid") != txid or got.get("raw_hex") != tx_hex.strip():
    raise SystemExit(15)
PY
  case "${status}" in 0) return 0 ;; 12) TX_REASON=go_submit_artifact_write_failed ;; 13) TX_REASON=go_submit_malformed_rpc_body ;; 14) TX_REASON=go_submit_pending_timeout ;; 15) TX_REASON=go_submit_wrong_tx_identity ;; 18) TX_REASON=go_submit_get_tx_missing ;; *) TX_REASON=go_submit_unknown_failure ;; esac
  return 1
}
wait_rust_accept() {
  local accept_class status
  TX_REASON=""
  accept_class="$(python3 - "${RUST_RPC_ADDR}" "${TX_ID}" "${TX_HEX}" "${RUST_STATUS_JSON}" "${RUST_GET_TX_JSON}" "${MESH_TIMEOUT}" <<'PY'
import json
import socket
import sys
import time
import urllib.error
import urllib.request

addr, txid, tx_hex, status_path, get_tx_path, timeout_s = sys.argv[1:7]
deadline = time.monotonic() + int(timeout_s)
saw_success = False

class BodyOversizedError(ValueError):
    pass

def fetch_json(path: str) -> dict:
    with urllib.request.urlopen(f"http://{addr}{path}", timeout=5) as response:
        raw_bytes = response.read((2 << 20) + 1)
    if len(raw_bytes) > (2 << 20):
        raise BodyOversizedError("response body exceeds devnet report maximum")
    raw = raw_bytes.decode("utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("response root is not an object")
    return data

while time.monotonic() < deadline:
    try:
        status = fetch_json(f"/tx_status?txid={txid}")
        saw_success = True
        with open(status_path, "w", encoding="utf-8") as f:
            json.dump(status, f, indent=2, sort_keys=True)
            f.write("\n")
        status_txid = status.get("txid")
        status_value = status.get("status")
        if isinstance(status_txid, str) and status_txid != txid:
            raise SystemExit(15)
        if status_txid != txid or status_value not in {"missing", "pending"}:
            raise SystemExit(13)
        if status_value == "pending":
            try:
                got = fetch_json(f"/get_tx?txid={txid}")
            except BodyOversizedError:
                raise SystemExit(19)
            except json.JSONDecodeError:
                raise SystemExit(13)
            except UnicodeDecodeError:
                raise SystemExit(13)
            except RecursionError:
                raise SystemExit(13)
            except ValueError:
                raise SystemExit(13)
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, socket.timeout):
                raise SystemExit(12)
            saw_success = True
            try:
                with open(get_tx_path, "w", encoding="utf-8") as f:
                    json.dump(got, f, indent=2, sort_keys=True)
                    f.write("\n")
            except OSError:
                raise SystemExit(16)
            if not isinstance(got.get("found"), bool):
                raise SystemExit(13)
            if got.get("found") is True:
                if got.get("txid") == txid and got.get("raw_hex") == tx_hex.strip():
                    print("pending_found")
                    raise SystemExit(0)
                raise SystemExit(15)
            raise SystemExit(18)
    except json.JSONDecodeError:
        raise SystemExit(13)
    except BodyOversizedError:
        raise SystemExit(19)
    except UnicodeDecodeError:
        raise SystemExit(13)
    except RecursionError:
        raise SystemExit(13)
    except ValueError:
        raise SystemExit(13)
    except urllib.error.HTTPError:
        time.sleep(1)
        continue
    except (urllib.error.URLError, TimeoutError, socket.timeout):
        time.sleep(1)
        continue
    except OSError:
        raise SystemExit(16)
    time.sleep(1)
if not saw_success:
    raise SystemExit(12)
raise SystemExit(14)
PY
)" || status=$?
  status="${status:-0}"
  case "${status}" in 0) RUST_ACCEPT_CLASS="${accept_class}"; return 0 ;; 12) TX_REASON=rust_accept_rpc_failed ;; 13) TX_REASON=rust_accept_malformed_rpc_body ;; 14) TX_REASON=rust_accept_pending_timeout ;; 15) TX_REASON=rust_accept_wrong_tx_identity ;; 16) TX_REASON=rust_accept_artifact_write_failed ;; 18) TX_REASON=rust_accept_get_tx_missing ;; 19) TX_REASON=rust_accept_rpc_body_oversized ;; *) TX_REASON=rust_accept_unknown_failure ;; esac
  return 1
}
write_outputs() {
  local verdict="$1" reason="${2:-}"
  export REPORT_JSON LEGACY_SCHEMA_MARKER_JSON verdict reason GO_PID RUST_PID GO_RPC_ADDR RUST_RPC_ADDR \
    GO_P2P_ADDR RUST_P2P_ADDR GO_STARTED_AT_UTC RUST_STARTED_AT_UTC GO_COMM RUST_COMM \
    GO_NODE_BIN RUST_NODE_BIN GO_CMD RUST_CMD GO_ARGV_JSON RUST_ARGV_JSON GO_PEERS_JSON RUST_PEERS_JSON \
    GO_PROCESS_ALIVE RUST_PROCESS_ALIVE GO_RPC_PROCESS_BACKED RUST_RPC_PROCESS_BACKED GO_P2P_PROCESS_BACKED RUST_P2P_PROCESS_BACKED \
    RUST_TO_GO_LOCAL_ADDR FINAL_PROCESS_IDENTITY_RECHECKED FINAL_RUST_OUTBOUND_LINK_RECHECKED FINAL_PEER_SNAPSHOTS_RECHECKED \
    RUBIN_PROCESS_ARTIFACT_ROOT TX_PATH_MODE TX_ID TX_HEX GO_SUBMIT_JSON GO_SUBMIT_STATUS_JSON GO_SUBMIT_GET_TX_JSON RUST_STATUS_JSON RUST_GET_TX_JSON RUST_ACCEPT_CLASS
  python3 - <<'PY'
import json, os
e = os.environ
verdict = e["verdict"]
reason = (e.get("reason") or "").strip()
def read_peer_snapshot(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return {"count": 0, "peers": []}
    peers = data.get("peers") if isinstance(data, dict) else None
    count = data.get("count") if isinstance(data, dict) else None
    if not isinstance(count, int) or isinstance(count, bool) or not isinstance(peers, list) or count != len(peers):
        return {"count": 0, "peers": []}
    normalized = []
    for peer in peers:
        if not isinstance(peer, dict) or not isinstance(peer.get("addr"), str) or not isinstance(peer.get("handshake_complete"), bool):
            return {"count": 0, "peers": []}
        normalized.append({"addr": peer["addr"], "handshake_complete": peer["handshake_complete"]})
    return {"count": len(normalized), "peers": normalized}
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
go_snapshot, rust_snapshot = read_peer_snapshot(e["GO_PEERS_JSON"]), read_peer_snapshot(e["RUST_PEERS_JSON"])
tx_mode = e.get("TX_PATH_MODE") == "1"
report = {
    "scenario": "mixed_client_go_submit_rust_accept" if tx_mode else "mixed_client_mesh",
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
    report["go_submit"] = {
        "accepted": True,
        "txid": e["TX_ID"],
        "tx_hex": e["TX_HEX"],
        "rpc_endpoint": e["GO_RPC_ADDR"],
        "submit_response_path": e["GO_SUBMIT_JSON"],
        "tx_status_path": e["GO_SUBMIT_STATUS_JSON"],
        "get_tx_path": e["GO_SUBMIT_GET_TX_JSON"],
    }
    report["rust_accept"] = {
        "class": e["RUST_ACCEPT_CLASS"],
        "txid": e["TX_ID"],
        "raw_hex": e["TX_HEX"],
        "rpc_endpoint": e["RUST_RPC_ADDR"],
        "tx_status_path": e["RUST_STATUS_JSON"],
        "get_tx_path": e["RUST_GET_TX_JSON"],
    }
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
  local reason="$1" cleanup_status=0
  cleanup_tx_from_key_file || cleanup_status=$?
  if (( cleanup_status != 0 )); then
    reason=go_submit_keygen_cleanup_failed
  fi
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
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
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
    else
      rc=$?
      case "${rc}" in
        23) PEER_SNAPSHOT_REASON=peer_snapshot_malformed_json ;;
        24) PEER_SNAPSHOT_REASON=peer_snapshot_rpc_body_oversized ;;
        *) PEER_SNAPSHOT_REASON=peer_snapshot_rpc_failed ;;
      esac
    fi
    sleep 1
  done
  if [[ "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_rpc_failed || -s "${tmp}.err" ]]; then PEER_SNAPSHOT_REASON=peer_snapshot_rpc_failed; elif [[ "${PEER_SNAPSHOT_REASON:-}" == unexpected_peer_snapshot_peer || "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_malformed_json || "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_rpc_body_oversized || "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_invalid_shape || "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_handshake_incomplete || "${PEER_SNAPSHOT_REASON:-}" == peer_snapshot_expected_peer_absent ]]; then :; elif [[ -s "${tmp}" ]] && ! python3 -m json.tool "${tmp}" >/dev/null 2>&1; then PEER_SNAPSHOT_REASON=peer_snapshot_malformed_json; else PEER_SNAPSHOT_REASON="${label}_peer_snapshot_missing_endpoint"; fi
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
if (( TX_PATH_MODE == 1 )); then
  prepare_tx_chainstate || finish_no_data "${TX_REASON:-go_submit_chainstate_prepare_failed}"
fi
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
if (( TX_PATH_MODE == 1 )); then
  submit_go_tx || finish_no_data "${TX_REASON:-go_submit_failed}"
  wait_rust_accept || finish_no_data "${TX_REASON:-rust_accept_failed}"
fi
PASS_REPORT_JSON="$(mktemp "/tmp/mixed-client-mesh-pass.XXXXXX")" || finish_no_data "pass_report_temp_failed"; FINAL_REPORT_JSON="${REPORT_JSON}"; REPORT_JSON="${PASS_REPORT_JSON}"
write_outputs "PASS" || { REPORT_JSON="${FINAL_REPORT_JSON}"; finish_no_data "pass_report_write_failed"; }; REPORT_JSON="${FINAL_REPORT_JSON}"
if ! run_validator "${LEGACY_SCHEMA_MARKER_JSON}" >&2; then
  rm -f -- "${PASS_REPORT_JSON}"; finish_no_data "legacy_schema_marker_validation_failed"
fi
PRODUCER_CHECK_MODE=auto; (( TX_PATH_MODE == 1 )) && PRODUCER_CHECK_MODE=producer-tx
if ! check_err="$(check_report "${PASS_REPORT_JSON}" live "${PRODUCER_CHECK_MODE}" 2>&1)"; then
  rm -f -- "${PASS_REPORT_JSON}"; finish_no_data "pass_report_live_validation_$(check_report_reason_token <<<"${check_err}")"
fi
mv -- "${PASS_REPORT_JSON}" "${REPORT_JSON}" || finish_no_data "pass_report_publish_failed"
[[ "${RUBIN_PROCESS_KEEP_ARTIFACTS}" == "1" ]] && echo "PASS: mixed-client mesh connected go_pid=${GO_PID} rust_pid=${RUST_PID}; report=${REPORT_JSON} legacy_schema_marker=${LEGACY_SCHEMA_MARKER_JSON}" || echo "PASS: mixed-client mesh connected go_pid=${GO_PID} rust_pid=${RUST_PID}; set KEEP_TMP=1 to retain report"

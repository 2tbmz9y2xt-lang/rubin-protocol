#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import subprocess
import sys
from typing import Any, Dict, List, Tuple


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "conformance" / "fixtures"
BIN_DIR = REPO_ROOT / "conformance" / "bin"


def run(cmd: List[str], cwd: pathlib.Path) -> None:
    p = subprocess.run(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        out = p.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{out}")


def build_tools() -> Tuple[pathlib.Path, pathlib.Path]:
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    go_cli = BIN_DIR / "go-consensus-cli"
    run(
        ["go", "build", "-o", str(go_cli), "./cmd/rubin-consensus-cli"],
        cwd=REPO_ROOT / "clients" / "go",
    )

    run(
        ["cargo", "build", "-p", "rubin-consensus-cli"],
        cwd=REPO_ROOT / "clients" / "rust",
    )
    rust_cli = REPO_ROOT / "clients" / "rust" / "target" / "debug" / "rubin-consensus-cli"
    if sys.platform.startswith("win"):
        rust_cli = rust_cli.with_suffix(".exe")

    if not rust_cli.exists():
        raise RuntimeError(f"missing rust cli binary: {rust_cli}")

    return go_cli, rust_cli


def call_tool(tool_path: pathlib.Path, req: Dict[str, Any]) -> Dict[str, Any]:
    p = subprocess.run(
        [str(tool_path)],
        input=(json.dumps(req) + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(os.environ),
    )
    if p.returncode != 0:
        stderr = p.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"tool failed: {tool_path} rc={p.returncode} stderr={stderr}")
    out = p.stdout.decode("utf-8", errors="replace")
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"tool returned non-json: {tool_path}\n{out}\n{e}")


def load_fixtures() -> List[Dict[str, Any]]:
    fixtures = []
    for p in sorted(FIXTURES_DIR.glob("CV-*.json")):
        fixtures.append(json.loads(p.read_text(encoding="utf-8")))
    return fixtures


def validate_vector(
    gate: str,
    v: Dict[str, Any],
    go_cli: pathlib.Path,
    rust_cli: pathlib.Path,
) -> List[str]:
    op = v.get("op")
    if not op:
        return [f"{gate}/{v.get('id','?')}: missing op"]

    req: Dict[str, Any] = {"op": op}
    if op == "parse_tx":
        req["tx_hex"] = v["tx_hex"]
    elif op == "merkle_root":
        req["txids"] = v["txids"]
    elif op == "sighash_v1":
        req["tx_hex"] = v["tx_hex"]
        req["chain_id"] = v["chain_id"]
        req["input_index"] = v["input_index"]
        req["input_value"] = v["input_value"]
    else:
        return [f"{gate}/{v.get('id','?')}: unknown op {op}"]

    go_resp = call_tool(go_cli, req)
    rust_resp = call_tool(rust_cli, req)

    problems: List[str] = []
    vid = v.get("id", "?")

    if bool(go_resp.get("ok")) != bool(rust_resp.get("ok")):
        problems.append(f"{gate}/{vid}: go ok={go_resp.get('ok')} rust ok={rust_resp.get('ok')}")
        return problems

    if bool(v.get("expect_ok")) != bool(go_resp.get("ok")):
        problems.append(f"{gate}/{vid}: expect_ok={v.get('expect_ok')} got_ok={go_resp.get('ok')}")
        return problems

    if not go_resp.get("ok"):
        ge = go_resp.get("err")
        re = rust_resp.get("err")
        if ge != re:
            problems.append(f"{gate}/{vid}: err mismatch go={ge} rust={re}")
        if "expect_err" in v and ge != v["expect_err"]:
            problems.append(f"{gate}/{vid}: expect_err={v['expect_err']} got_err={ge}")
        return problems

    # ok=true
    if op == "parse_tx":
        for k in ["txid", "wtxid"]:
            if go_resp.get(k) != rust_resp.get(k):
                problems.append(
                    f"{gate}/{vid}: {k} mismatch go={go_resp.get(k)} rust={rust_resp.get(k)}"
                )
        if "expect_txid" in v and go_resp.get("txid") != v["expect_txid"]:
            problems.append(f"{gate}/{vid}: expect_txid mismatch")
        if "expect_wtxid" in v and go_resp.get("wtxid") != v["expect_wtxid"]:
            problems.append(f"{gate}/{vid}: expect_wtxid mismatch")
    elif op == "merkle_root":
        if go_resp.get("merkle_root") != rust_resp.get("merkle_root"):
            problems.append(
                f"{gate}/{vid}: merkle_root mismatch go={go_resp.get('merkle_root')} rust={rust_resp.get('merkle_root')}"
            )
        if "expect_merkle_root" in v and go_resp.get("merkle_root") != v["expect_merkle_root"]:
            problems.append(f"{gate}/{vid}: expect_merkle_root mismatch")
    elif op == "sighash_v1":
        if go_resp.get("digest") != rust_resp.get("digest"):
            problems.append(
                f"{gate}/{vid}: digest mismatch go={go_resp.get('digest')} rust={rust_resp.get('digest')}"
            )
        if "expect_digest" in v and go_resp.get("digest") != v["expect_digest"]:
            problems.append(f"{gate}/{vid}: expect_digest mismatch")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only-gates", nargs="*", default=None)
    ap.add_argument("--list-gates", action="store_true")
    args = ap.parse_args()

    fixtures = load_fixtures()
    gates = [f["gate"] for f in fixtures]
    if args.list_gates:
        for g in gates:
            print(g)
        return 0

    only = set(args.only_gates or [])
    if only:
        fixtures = [f for f in fixtures if f["gate"] in only]

    go_cli, rust_cli = build_tools()

    total = 0
    problems: List[str] = []
    for f in fixtures:
        gate = f["gate"]
        vectors = f.get("vectors", [])
        for v in vectors:
            total += 1
            problems.extend(validate_vector(gate, v, go_cli, rust_cli))

    if problems:
        for p in problems:
            print("FAIL", p)
        print(f"FAILED: {len(problems)} problems across {total} vectors")
        return 1

    print(f"PASS: {total} vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

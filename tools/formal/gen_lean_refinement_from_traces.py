#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Header:
    repo_commit: str
    fixtures_digest_sha3_256: str


def _fail(msg: str) -> None:
    raise SystemExit(f"ERROR: {msg}")


def _load_jsonl(path: Path) -> tuple[Header, list[dict[str, Any]]]:
    if not path.exists():
        _fail(f"trace file not found: {path}")
    header: Header | None = None
    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            rec_type = obj.get("type")
            if line_no == 1:
                if rec_type != "header":
                    _fail("first JSONL record must be type=header")
                if obj.get("schema_version") != 1:
                    _fail(f"unsupported schema_version: {obj.get('schema_version')}")
                header = Header(
                    repo_commit=str(obj.get("repo_commit", "")),
                    fixtures_digest_sha3_256=str(obj.get("fixtures_digest_sha3_256", "")),
                )
                continue
            if rec_type != "entry":
                _fail(f"unexpected record type at line {line_no}: {rec_type}")
            entries.append(obj)
    if header is None:
        _fail("missing header record")
    if not entries:
        _fail("no entry records in trace file")
    return header, entries


def _lean_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def _hex0x(s: str) -> str:
    t = s.strip().lower()
    if not t:
        return "0x"
    if t.startswith("0x"):
        return t
    return "0x" + t


def _lean_opt_nat(x: Any) -> str:
    if x is None:
        return "none"
    if isinstance(x, bool):
        _fail("expected nat, got bool")
    if isinstance(x, int):
        if x < 0:
            _fail(f"expected nat, got negative: {x}")
        return f"some {x}"
    _fail(f"expected nat, got: {type(x)}")


def _lean_opt_hex(x: Any) -> str:
    if x is None:
        return "none"
    if not isinstance(x, str):
        _fail(f"expected hex string, got: {type(x)}")
    return f"some ({_lean_str(_hex0x(x))})"


def _require_keys(obj: dict[str, Any], keys: list[str], ctx: str) -> None:
    for k in keys:
        if k not in obj:
            _fail(f"missing key {k} in {ctx}")


def _emit_go_trace_v1(header: Header, entries: list[dict[str, Any]]) -> str:
    parse_rows: list[tuple[str, str]] = []
    sighash_rows: list[tuple[str, str]] = []
    pow_rows: list[tuple[str, str]] = []
    utxo_rows: list[tuple[str, str]] = []
    block_rows: list[tuple[str, str]] = []

    for e in entries:
        gate = str(e.get("gate", ""))
        vector_id = str(e.get("vector_id", ""))
        op = str(e.get("op", ""))
        ok = bool(e.get("ok", False))
        err = str(e.get("err", ""))
        outputs = e.get("outputs")
        if not isinstance(outputs, dict):
            _fail(f"outputs must be object: {gate}/{vector_id}")

        if gate == "CV-PARSE":
            _require_keys(outputs, ["consumed", "txid", "wtxid"], f"{gate}/{vector_id}")
            parse_rows.append((
                vector_id,
                "{ id := "
                + _lean_str(vector_id)
                + ", ok := "
                + ("true" if ok else "false")
                + ", err := "
                + _lean_str(err)
                + ", consumed := "
                + str(int(outputs["consumed"]))
                + ", txidHex := "
                + _lean_str(_hex0x(str(outputs["txid"])))
                + ", wtxidHex := "
                + _lean_str(_hex0x(str(outputs["wtxid"])))
                + " }"
            ))
        elif gate == "CV-SIGHASH":
            _require_keys(outputs, ["digest"], f"{gate}/{vector_id}")
            sighash_rows.append((
                vector_id,
                "{ id := "
                + _lean_str(vector_id)
                + ", ok := "
                + ("true" if ok else "false")
                + ", err := "
                + _lean_str(err)
                + ", digestHex := "
                + _lean_str(_hex0x(str(outputs["digest"])))
                + " }"
            ))
        elif gate == "CV-POW":
            # op-specific outputs
            out_target_new = outputs.get("target_new")
            out_block_hash = outputs.get("block_hash")
            pow_rows.append((
                vector_id,
                "{ id := "
                + _lean_str(vector_id)
                + ", op := "
                + _lean_str(op)
                + ", ok := "
                + ("true" if ok else "false")
                + ", err := "
                + _lean_str(err)
                + ", targetNewHex := "
                + _lean_opt_hex(out_target_new)
                + ", blockHashHex := "
                + _lean_opt_hex(out_block_hash)
                + " }"
            ))
        elif gate == "CV-UTXO-BASIC":
            utxo_rows.append((
                vector_id,
                "{ id := "
                + _lean_str(vector_id)
                + ", ok := "
                + ("true" if ok else "false")
                + ", err := "
                + _lean_str(err)
                + ", fee := "
                + _lean_opt_nat(outputs.get("fee"))
                + ", utxoCount := "
                + _lean_opt_nat(outputs.get("utxo_count"))
                + " }"
            ))
        elif gate == "CV-BLOCK-BASIC":
            block_rows.append((
                vector_id,
                "{ id := "
                + _lean_str(vector_id)
                + ", ok := "
                + ("true" if ok else "false")
                + ", err := "
                + _lean_str(err)
                + ", blockHashHex := "
                + _lean_opt_hex(outputs.get("block_hash"))
                + ", sumWeight := "
                + _lean_opt_nat(outputs.get("sum_weight"))
                + ", sumDa := "
                + _lean_opt_nat(outputs.get("sum_da"))
                + " }"
            ))
        else:
            # non-critical gate for refinement: ignore
            continue

    def _sorted_rows(rows: list[tuple[str, str]]) -> list[str]:
        # Deterministic output (CI-friendly): sort by vector id.
        return [row for _, row in sorted(rows, key=lambda t: t[0])]

    def list_block(name: str, type_name: str, rows: list[tuple[str, str]]) -> str:
        rr = _sorted_rows(rows)
        return f"def {name} : List {type_name} := [\n  " + ",\n  ".join(rr) + "\n]\n"

    out = []
    out.append("-- AUTOGENERATED: do not edit by hand.")
    out.append("-- Generated from rubin-formal/traces/go_trace_v1.jsonl via tools/formal/gen_lean_refinement_from_traces.py")
    out.append("")
    out.append("namespace RubinFormal.Refinement")
    out.append("")
    out.append("structure ParseOut where")
    out.append("  id : String")
    out.append("  ok : Bool")
    out.append("  err : String")
    out.append("  consumed : Nat")
    out.append("  txidHex : String")
    out.append("  wtxidHex : String")
    out.append("")
    out.append("structure SighashOut where")
    out.append("  id : String")
    out.append("  ok : Bool")
    out.append("  err : String")
    out.append("  digestHex : String")
    out.append("")
    out.append("structure PowOut where")
    out.append("  id : String")
    out.append("  op : String")
    out.append("  ok : Bool")
    out.append("  err : String")
    out.append("  targetNewHex : Option String")
    out.append("  blockHashHex : Option String")
    out.append("")
    out.append("structure UtxoBasicOut where")
    out.append("  id : String")
    out.append("  ok : Bool")
    out.append("  err : String")
    out.append("  fee : Option Nat")
    out.append("  utxoCount : Option Nat")
    out.append("")
    out.append("structure BlockBasicOut where")
    out.append("  id : String")
    out.append("  ok : Bool")
    out.append("  err : String")
    out.append("  blockHashHex : Option String")
    out.append("  sumWeight : Option Nat")
    out.append("  sumDa : Option Nat")
    out.append("")
    out.append(f"def goTraceRepoCommit : String := {_lean_str(header.repo_commit)}")
    out.append(f"def goTraceFixturesDigestSHA3_256 : String := {_lean_str(header.fixtures_digest_sha3_256)}")
    out.append("")
    out.append(list_block("parseOuts", "ParseOut", parse_rows))
    out.append(list_block("sighashOuts", "SighashOut", sighash_rows))
    out.append(list_block("powOuts", "PowOut", pow_rows))
    out.append(list_block("utxoBasicOuts", "UtxoBasicOut", utxo_rows))
    out.append(list_block("blockBasicOuts", "BlockBasicOut", block_rows))
    out.append("end RubinFormal.Refinement")
    out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--traces",
        default="rubin-formal/traces/go_trace_v1.jsonl",
        help="path to Go trace JSONL (schema_v1)",
    )
    ap.add_argument(
        "--out",
        default="rubin-formal/RubinFormal/Refinement/GoTraceV1.lean",
        help="output Lean module path",
    )
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    trace_path = (repo_root / args.traces).resolve()
    out_path = (repo_root / args.out).resolve()

    header, entries = _load_jsonl(trace_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_emit_go_trace_v1(header, entries), encoding="utf-8")
    print(f"OK: wrote {out_path.relative_to(repo_root)} ({len(entries)} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

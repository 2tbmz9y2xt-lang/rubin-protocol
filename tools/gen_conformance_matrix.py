#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "conformance" / "fixtures"
PROTOCOL_FIXTURES_DIR = FIXTURES_DIR / "protocol"
RUNNER_PATH = REPO_ROOT / "conformance" / "runner" / "run_cv_bundle.py"
OUT_PATH = REPO_ROOT / "conformance" / "MATRIX.md"
EXPECTED_PROTOCOL_ARTIFACTS = frozenset(
    {
        "legacy_exposure_hook_vectors.json",
        "legacy_exposure_report_v1_example.json",
        "live_binding_policy_v1.json",
        "production_rotation_schedule_v1.json",
    }
)
EXPECTED_GATES = frozenset(
    {
        "CV-BLOCK-BASIC",
        "CV-COMPACT",
        "CV-CANONICAL-INVARIANT",
        "CV-COVENANT-GENESIS",
        "CV-DA-INTEGRITY",
        "CV-DA-STRESS",
        "CV-DETERMINISM",
        "CV-DEVNET-CHAIN",
        "CV-DEVNET-GENESIS",
        "CV-DEVNET-MATURITY",
        "CV-DEVNET-SIGHASH-CHAINID",
        "CV-DEVNET-SUBSIDY",
        "CV-EXT",
        "CV-NATIVE-ROTATION-CUTOFF",
        "CV-NATIVE-ROTATION-SUNSET",
        "CV-FEATUREBITS",
        "CV-FLAGDAY",
        "CV-FORK-CHOICE",
        "CV-HTLC",
        "CV-HTLC-ORDERING",
        "CV-MERKLE",
        "CV-MULTISIG",
        "CV-NATIVE-ROTATION-CREATE",
        "CV-NATIVE-ROTATION-SPEND",
        "CV-NATIVE-ROTATION-DESCRIPTOR",
        "CV-NATIVE-ROTATION-WEIGHT",
        "CV-OUTPUT-DESCRIPTOR",
        "CV-PARSE",
        "CV-POW",
        "CV-PV-CACHE",
        "CV-PV-CURSOR",
        "CV-PV-DA",
        "CV-PV-DAG",
        "CV-PV-ERR",
        "CV-PV-MIXED",
        "CV-PV-STRESS",
        "CV-REPLAY",
        "CV-SIG",
        "CV-SIGHASH",
        "CV-STEALTH",
        "CV-SUBSIDY",
        "CV-TIMESTAMP",
        "CV-TXCTX",
        "CV-UTXO-BASIC",
        "CV-VALIDATION-ORDER",
        "CV-VAULT",
        "CV-VAULT-POLICY",
        "CV-WEIGHT",
    }
)


@dataclass(frozen=True)
class GateRow:
    gate: str
    vectors: int
    ops: tuple[str, ...]
    local_ops: tuple[str, ...]
    executable_ops: tuple[str, ...]


@dataclass(frozen=True)
class ProtocolArtifactRow:
    path: str
    purpose: str
    coverage: str


PROTOCOL_ARTIFACT_META: dict[str, tuple[str, str]] = {
    "legacy_exposure_hook_vectors.json": (
        "Operational protocol artifact",
        "legacy exposure scanner / hook-driven verification receipts",
    ),
    "legacy_exposure_report_v1_example.json": (
        "Operational protocol artifact",
        "example report shape for legacy exposure scanner consumers",
    ),
    "live_binding_policy_v1.json": (
        "Canonical live binding policy artifact",
        "Go/Rust consensus embedded copies, loader drift checks, and live binding/runtime parity tests",
    ),
    "production_rotation_schedule_v1.json": (
        "Canonical production rotation schedule artifact",
        "Go node / Rust node embedded schedule loaders and production activation checks",
    ),
}


class DuplicateJSONKeyError(ValueError):
    pass


def reject_nonstandard_json_constant(token: str) -> Any:
    raise ValueError(f"invalid JSON constant {token!r}")


def load_local_ops() -> set[str]:
    spec = importlib.util.spec_from_file_location("rubin_run_cv_bundle", str(RUNNER_PATH))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load runner module: {RUNNER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    local_ops = getattr(mod, "LOCAL_OPS", None)
    if not isinstance(local_ops, set) or not all(isinstance(x, str) for x in local_ops):
        raise RuntimeError("runner LOCAL_OPS missing/invalid")
    return set(local_ops)


def iter_fixtures() -> Iterable[Path]:
    if not FIXTURES_DIR.exists():
        raise RuntimeError(f"missing fixtures dir: {FIXTURES_DIR}")
    return sorted(FIXTURES_DIR.glob("CV-*.json"))


def iter_protocol_artifacts() -> Iterable[Path]:
    if not PROTOCOL_FIXTURES_DIR.exists():
        raise RuntimeError(f"missing protocol fixtures dir: {PROTOCOL_FIXTURES_DIR}")
    return sorted(PROTOCOL_FIXTURES_DIR.glob("*.json"))


def reject_duplicate_json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key, value in pairs:
        if key in data:
            raise DuplicateJSONKeyError(f'duplicate JSON key "{key}"')
        data[key] = value
    return data


def load_json_fail_closed(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8", errors="strict")
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicate_json_object_pairs,
            parse_constant=reject_nonstandard_json_constant,
        )
    except UnicodeDecodeError as err:
        raise RuntimeError(f"invalid JSON artifact {path}: {err}") from err
    except DuplicateJSONKeyError as err:
        raise RuntimeError(f"invalid JSON artifact {path}: {err}") from err
    except json.JSONDecodeError as err:
        raise RuntimeError(
            f"invalid JSON artifact {path}: {err.msg} (line {err.lineno}, column {err.colno})"
        ) from err
    except OSError as err:
        reason = err.strerror or err.__class__.__name__
        raise RuntimeError(f"cannot read JSON artifact {path.name}: {reason}") from err
    except ValueError as err:
        raise RuntimeError(f"invalid JSON artifact {path}: {err}") from err


def validate_fixture_schema(data: Any, path: Path) -> tuple[str, list[dict[str, Any]]]:
    if not isinstance(data, dict):
        raise RuntimeError(f"fixture root must be object: {path}")

    missing = [field for field in ("gate", "vectors") if field not in data]
    if missing:
        missing_str = ", ".join(missing)
        raise RuntimeError(f"fixture missing required field(s): {missing_str}: {path}")

    gate = data["gate"]
    vectors = data["vectors"]
    if not isinstance(gate, str) or not gate.strip():
        raise RuntimeError(f"fixture field gate must be non-empty string: {path}")
    if not isinstance(vectors, list):
        raise RuntimeError(f"fixture field vectors must be an array: {path}")

    for idx, vector in enumerate(vectors):
        if not isinstance(vector, dict):
            raise RuntimeError(f"fixture vector[{idx}] must be object: {path}")
        op = vector.get("op")
        if gate == "CV-TXCTX" and (op is None or (isinstance(op, str) and not op.strip())):
            continue
        if not isinstance(op, str) or not op.strip():
            vid = vector.get("id", f"#{idx}")
            raise RuntimeError(f"fixture vector missing required op: {path} ({vid})")

    return gate.strip(), vectors


def normalized_vector_op(gate: str, vector: dict[str, Any]) -> str:
    op = vector.get("op")
    if isinstance(op, str) and op.strip():
        return op.strip()
    if gate == "CV-TXCTX":
        return "txctx_spend_vector"
    raise RuntimeError(f"fixture vector missing required op: {gate} ({vector.get('id', '?')})")


def load_gate_rows(local_ops: set[str]) -> list[GateRow]:
    rows: list[GateRow] = []
    seen_gates: set[str] = set()
    for p in iter_fixtures():
        data = json.loads(p.read_text(encoding="utf-8", errors="strict"))
        gate, vectors = validate_fixture_schema(data, p)
        if gate in seen_gates:
            raise RuntimeError(f"duplicate fixture gate: {gate}: {p}")
        seen_gates.add(gate)
        ops = tuple(sorted({normalized_vector_op(gate, v) for v in vectors}))

        local = tuple(sorted([o for o in ops if o in local_ops]))
        executable = tuple(sorted([o for o in ops if o not in local_ops]))
        rows.append(
            GateRow(
                gate=gate,
                vectors=len(vectors),
                ops=ops,
                local_ops=local,
                executable_ops=executable,
            )
        )
    rows.sort(key=lambda r: r.gate)
    return rows


def load_protocol_artifact_rows() -> list[ProtocolArtifactRow]:
    if set(PROTOCOL_ARTIFACT_META) != EXPECTED_PROTOCOL_ARTIFACTS:
        missing_meta = sorted(EXPECTED_PROTOCOL_ARTIFACTS - set(PROTOCOL_ARTIFACT_META))
        unexpected_meta = sorted(set(PROTOCOL_ARTIFACT_META) - EXPECTED_PROTOCOL_ARTIFACTS)
        problems: list[str] = []
        if missing_meta:
            problems.append(f"missing protocol artifact metadata: {', '.join(missing_meta)}")
        if unexpected_meta:
            problems.append(
                f"unexpected protocol artifact metadata: {', '.join(unexpected_meta)}"
            )
        raise RuntimeError(
            f"protocol artifact metadata completeness check failed: {'; '.join(problems)}"
        )

    protocol_paths = list(iter_protocol_artifacts())
    actual_names = {path.name for path in protocol_paths}
    missing = sorted(EXPECTED_PROTOCOL_ARTIFACTS - actual_names)
    unexpected = sorted(actual_names - EXPECTED_PROTOCOL_ARTIFACTS)
    if missing or unexpected:
        problems: list[str] = []
        if missing:
            problems.append(f"missing protocol artifacts: {', '.join(missing)}")
        if unexpected:
            problems.append(f"unexpected protocol artifacts: {', '.join(unexpected)}")
        raise RuntimeError(
            f"protocol artifact completeness check failed: {'; '.join(problems)}"
        )

    rows: list[ProtocolArtifactRow] = []
    for path in protocol_paths:
        load_json_fail_closed(path)
        purpose, coverage = PROTOCOL_ARTIFACT_META[path.name]
        rows.append(
            ProtocolArtifactRow(
                path=path.relative_to(FIXTURES_DIR).as_posix(),
                purpose=purpose,
                coverage=coverage,
            )
        )
    return rows


def validate_expected_gates(rows: list[GateRow]) -> None:
    actual_gates = {row.gate for row in rows}
    missing = sorted(EXPECTED_GATES - actual_gates)
    unexpected = sorted(actual_gates - EXPECTED_GATES)

    if not missing and not unexpected:
        return

    problems: list[str] = []
    if missing:
        problems.append(f"missing fixtures for gates: {', '.join(missing)}")
    if unexpected:
        problems.append(f"unexpected gates in fixtures: {', '.join(unexpected)}")
    raise RuntimeError(f"fixture completeness check failed: {'; '.join(problems)}")


def render(rows: list[GateRow], local_ops: set[str], protocol_rows: list[ProtocolArtifactRow]) -> str:
    total_vectors = sum(r.vectors for r in rows)
    total_gates = len(rows)
    all_ops = sorted({o for r in rows for o in r.ops})
    all_exec_ops = sorted({o for r in rows for o in r.executable_ops})
    all_local_ops = sorted({o for r in rows for o in r.local_ops})

    def fmt_ops(items: Iterable[str]) -> str:
        return ", ".join(items) if items else "-"

    lines: list[str] = []
    lines.append("# Conformance Matrix (generated)")
    lines.append("")
    lines.append("Generated by `tools/gen_conformance_matrix.py`.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Gates: **{total_gates}**")
    lines.append(f"- Vectors: **{total_vectors}**")
    lines.append(f"- Unique ops: **{len(all_ops)}**")
    lines.append(f"- Executable ops (Go↔Rust parity): **{len(all_exec_ops)}**")
    lines.append(f"- Local-only ops (runner-defined): **{len(all_local_ops)}**")
    lines.append(f"- Shared protocol artifacts: **{len(protocol_rows)}**")
    lines.append("")
    lines.append("## Gates")
    lines.append("")
    lines.append("| Gate | Vectors | Ops | Executable ops | Local-only ops |")
    lines.append("| --- | ---: | --- | --- | --- |")
    for r in rows:
        lines.append(
            f"| `{r.gate}` | {r.vectors} | {fmt_ops(r.ops)} | {fmt_ops(r.executable_ops)} | {fmt_ops(r.local_ops)} |"
        )
    lines.append("")
    lines.append("## Local-only ops (runner)")
    lines.append("")
    for op in sorted(local_ops):
        lines.append(f"- `{op}`")
    lines.append("")
    lines.append("## Shared Protocol Artifacts")
    lines.append("")
    lines.append("| Artifact | Purpose | Coverage |")
    lines.append("| --- | --- | --- |")
    for row in protocol_rows:
        lines.append(f"| `{row.path}` | {row.purpose} | {row.coverage} |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if conformance/MATRIX.md is out of date")
    args = ap.parse_args()

    local_ops = load_local_ops()
    rows = load_gate_rows(local_ops)
    protocol_rows = load_protocol_artifact_rows()
    validate_expected_gates(rows)
    content = render(rows, local_ops, protocol_rows)

    if args.check:
        if not OUT_PATH.exists():
            print(f"ERROR: missing {OUT_PATH}")
            return 1
        cur = OUT_PATH.read_text(encoding="utf-8", errors="strict")
        if cur != content:
            print("ERROR: conformance/MATRIX.md is out of date (run tools/gen_conformance_matrix.py)")
            return 1
        print("OK: conformance/MATRIX.md is up to date")
        return 0

    OUT_PATH.write_text(content, encoding="utf-8")
    print(f"WROTE: {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

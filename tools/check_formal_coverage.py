#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ALLOWED_STATUS = {"proved", "stated", "deferred"}
ALLOWED_PROOF_LEVEL = {"toy-model", "spec-model", "byte-model", "refinement"}
ALLOWED_CLAIM_LEVEL = {"toy", "byte", "refined"}
EXPECTED_CLAIM_BY_PROOF = {
    "toy-model": "toy",
    "spec-model": "toy",
    "byte-model": "byte",
    "refinement": "refined",
}
REQUIRED_SECTION_KEYS = {
    "consensus_constants",
    "transaction_wire",
    "transaction_identifiers",
    "weight_accounting",
    "witness_commitment",
    "sighash_v1",
    "consensus_error_codes",
    "covenant_registry",
    "difficulty_update",
    "transaction_structural_rules",
    "replay_domain_checks",
    "utxo_state_model",
    "coinbase_and_subsidy",
    "value_conservation",
    "da_set_integrity",
    "block_timestamp_rules",
    "block_validation_order",
    "parallel_validation_equivalence",
}
THEOREM_DECL_RE = re.compile(r"^\s*theorem\s+([A-Za-z_][A-Za-z0-9_']*)\b", re.MULTILINE)
NAMESPACE_RE = re.compile(r"^\s*namespace\s+([A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*)\b")
END_RE = re.compile(r"^\s*end(?:\s+([A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*))?\s*$")


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def declared_lean_theorems(lean_root: Path) -> set[str]:
    names: set[str] = set()
    for path in lean_root.rglob("*.lean"):
        namespace_stack: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if match := NAMESPACE_RE.match(line):
                namespace_stack.append(match.group(1))
                continue
            if END_RE.match(line):
                if namespace_stack:
                    namespace_stack.pop()
                continue
            if match := THEOREM_DECL_RE.match(line):
                theorem_name = match.group(1)
                namespace = ".".join(namespace_stack)
                names.add(f"{namespace}.{theorem_name}" if namespace else theorem_name)
    return names


def validate_coverage_summary(coverage: dict, rows: list[dict]) -> list[str]:
    summary = coverage.get("coverage_summary")
    if not isinstance(summary, dict):
        return ["missing coverage_summary{} in rubin-formal/proof_coverage.json"]

    status_counts = {status: 0 for status in ALLOWED_STATUS}
    theorem_refs: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            return [f"coverage_summary cannot inspect non-object coverage[{index}]"]
        status = row.get("status")
        if status in status_counts:
            status_counts[status] += 1
        theorems = row.get("theorems", [])
        if isinstance(theorems, list):
            theorem_refs.extend(t for t in theorems if isinstance(t, str))

    unique_theorems = sorted(set(theorem_refs))
    reused_theorems = sorted(t for t in unique_theorems if theorem_refs.count(t) > 1)
    expected = {
        "section_rows": len(rows),
        "proved_rows": status_counts["proved"],
        "stated_rows": status_counts["stated"],
        "deferred_rows": status_counts["deferred"],
        "theorem_references": len(theorem_refs),
        "unique_theorem_names": len(unique_theorems),
        "reused_theorem_names": reused_theorems,
    }

    errors: list[str] = []
    for key, value in expected.items():
        if summary.get(key) != value:
            errors.append(f"coverage_summary.{key} drift: expected {value!r}, got {summary.get(key)!r}")
    rule = summary.get("counting_rule")
    if not isinstance(rule, str) or "unique_theorem_names" not in rule:
        errors.append("coverage_summary.counting_rule must explain theorem reference vs unique theorem-name counting")
    return errors


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    coverage_path = repo_root / "rubin-formal" / "proof_coverage.json"
    fixtures_dir = repo_root / "conformance" / "fixtures"
    conformance_dir = repo_root / "rubin-formal" / "RubinFormal" / "Conformance"
    conformance_index = conformance_dir / "Index.lean"

    if not coverage_path.exists():
        return fail("rubin-formal/proof_coverage.json not found")
    if not fixtures_dir.exists():
        return fail("conformance/fixtures not found")
    if not conformance_dir.exists():
        return fail("rubin-formal/RubinFormal/Conformance not found")
    if not conformance_index.exists():
        return fail("rubin-formal/RubinFormal/Conformance/Index.lean not found")

    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))

    proof_level = coverage.get("proof_level")
    if proof_level not in ALLOWED_PROOF_LEVEL:
        return fail(
            f"invalid or missing proof_level in rubin-formal/proof_coverage.json: {proof_level}; "
            f"expected one of {sorted(ALLOWED_PROOF_LEVEL)}"
        )
    claim_level = coverage.get("claim_level")
    if claim_level not in ALLOWED_CLAIM_LEVEL:
        return fail(
            f"invalid or missing claim_level in rubin-formal/proof_coverage.json: {claim_level}; "
            f"expected one of {sorted(ALLOWED_CLAIM_LEVEL)}"
        )
    expected_claim = EXPECTED_CLAIM_BY_PROOF.get(proof_level)
    if expected_claim != claim_level:
        return fail(
            f"proof_level/claim_level mismatch: proof_level={proof_level} requires claim_level={expected_claim}, got {claim_level}"
        )

    claims = coverage.get("claims")
    if not isinstance(claims, dict):
        return fail("missing claims{} in rubin-formal/proof_coverage.json (required to prevent overclaim)")
    allowed_claims = claims.get("allowed")
    forbidden_claims = claims.get("forbidden")
    if not isinstance(allowed_claims, list) or len(allowed_claims) == 0:
        return fail("claims.allowed[] must be a non-empty list in rubin-formal/proof_coverage.json")
    if not isinstance(forbidden_claims, list) or len(forbidden_claims) == 0:
        return fail("claims.forbidden[] must be a non-empty list in rubin-formal/proof_coverage.json")

    refinement_bridge = coverage.get("refinement_bridge_file")
    if not isinstance(refinement_bridge, str) or not refinement_bridge:
        return fail("missing refinement_bridge_file in rubin-formal/proof_coverage.json")
    if not (repo_root / refinement_bridge).exists():
        return fail(f"refinement_bridge_file does not exist: {refinement_bridge}")

    expected_keys = set(REQUIRED_SECTION_KEYS)
    rows = coverage.get("coverage")
    if not isinstance(rows, list):
        return fail("coverage[]. list is missing in proof_coverage.json")
    declared_theorems = declared_lean_theorems(repo_root / "rubin-formal" / "RubinFormal")

    summary_errors = validate_coverage_summary(coverage, rows)
    if summary_errors:
        for err in summary_errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    seen_keys: set[str] = set()
    bad = False
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            print(f"ERROR: coverage[{index}] is not an object", file=sys.stderr)
            bad = True
            continue

        key = row.get("section_key")
        status = row.get("status")
        theorems = row.get("theorems", [])
        file_path = row.get("file")

        if key not in expected_keys:
            print(f"ERROR: unknown section_key in coverage[{index}]: {key}", file=sys.stderr)
            bad = True
            continue
        if key in seen_keys:
            print(f"ERROR: duplicate section_key in coverage: {key}", file=sys.stderr)
            bad = True
        seen_keys.add(key)

        if status not in ALLOWED_STATUS:
            print(
                f"ERROR: invalid status for {key}: {status}; expected one of {sorted(ALLOWED_STATUS)}",
                file=sys.stderr,
            )
            bad = True

        if status in {"proved", "stated"}:
            if not isinstance(theorems, list) or len(theorems) == 0:
                print(f"ERROR: {key} has status={status} but empty theorems[]", file=sys.stderr)
                bad = True
        if isinstance(theorems, list):
            for theorem_ref in theorems:
                if not isinstance(theorem_ref, str) or not theorem_ref:
                    print(f"ERROR: {key} has invalid theorem reference: {theorem_ref}", file=sys.stderr)
                    bad = True
                    continue
                if theorem_ref not in declared_theorems:
                    print(f"ERROR: {key} references missing Lean theorem declaration: {theorem_ref}", file=sys.stderr)
                    bad = True

        if not isinstance(file_path, str) or not file_path:
            print(f"ERROR: {key} has missing file path", file=sys.stderr)
            bad = True
        else:
            abs_file = repo_root / file_path
            if not abs_file.exists():
                print(f"ERROR: coverage file does not exist for {key}: {file_path}", file=sys.stderr)
                bad = True

    missing = sorted(expected_keys - seen_keys)
    if missing:
        print("ERROR: missing section keys in proof coverage:", file=sys.stderr)
        for key in missing:
            print(f"  - {key}", file=sys.stderr)
        bad = True

    if bad:
        return 1

    # Conformance fixture → Lean replay coverage check.
    # Policy: every replay-covered CV-*.json fixture MUST have a matching Lean
    # vectors+replay module imported by Conformance/Index.lean, and a gate theorem named:
    #   cv_<gate_snake>_vectors_pass
    #
    # This prevents silently adding fixtures without formal replay coverage.
    index_txt = conformance_index.read_text(encoding="utf-8")

    def gate_to_camel(gate: str) -> str:
        if not gate.startswith("CV-"):
            raise ValueError(f"invalid gate name: {gate}")
        parts = gate[3:].split("-")
        return "".join(p.lower().capitalize() for p in parts if p)

    def gate_to_snake(gate: str) -> str:
        if not gate.startswith("CV-"):
            raise ValueError(f"invalid gate name: {gate}")
        return gate[3:].lower().replace("-", "_")

    # Gates that are runtime/parallel-only (e.g. connect_block_parallel) and do not
    # yet have Lean vectors/replay; skip formal coverage requirement for them.
    FORMAL_SKIP_GATE_PREFIXES = ("CV-PV-",)

    fixture_files = sorted(p for p in fixtures_dir.glob("CV-*.json") if p.is_file())
    if not fixture_files:
        return fail("no CV-*.json fixtures found in conformance/fixtures")

    conf_bad = False
    replay_fixture_files: list[Path] = []
    skipped_fixture_files: list[Path] = []
    for p in fixture_files:
        fixture = json.loads(p.read_text(encoding="utf-8"))
        gate = fixture.get("gate")
        if not isinstance(gate, str) or not gate.startswith("CV-"):
            print(f"ERROR: invalid or missing gate in fixture {p.relative_to(repo_root)}: {gate}", file=sys.stderr)
            conf_bad = True
            continue
        if any(gate.startswith(prefix) for prefix in FORMAL_SKIP_GATE_PREFIXES):
            skipped_fixture_files.append(p)
            continue
        replay_fixture_files.append(p)

        camel = gate_to_camel(gate)
        snake = gate_to_snake(gate)
        vectors_file = conformance_dir / f"CV{camel}Vectors.lean"
        replay_file = conformance_dir / f"CV{camel}Replay.lean"

        if not vectors_file.exists():
            print(f"ERROR: missing Lean vectors for {gate}: {vectors_file.relative_to(repo_root)}", file=sys.stderr)
            conf_bad = True
        if not replay_file.exists():
            print(f"ERROR: missing Lean replay for {gate}: {replay_file.relative_to(repo_root)}", file=sys.stderr)
            conf_bad = True
        else:
            theorem = f"cv_{snake}_vectors_pass"
            replay_txt = replay_file.read_text(encoding="utf-8")
            if theorem not in replay_txt:
                print(
                    f"ERROR: missing theorem {theorem} in {replay_file.relative_to(repo_root)} (required for gate replay)",
                    file=sys.stderr,
                )
                conf_bad = True

        imp_vectors = f"import RubinFormal.Conformance.CV{camel}Vectors"
        imp_replay = f"import RubinFormal.Conformance.CV{camel}Replay"
        if imp_vectors not in index_txt:
            print(
                f"ERROR: Conformance/Index.lean does not import vectors for {gate}: expected line '{imp_vectors}'",
                file=sys.stderr,
            )
            conf_bad = True
        if imp_replay not in index_txt:
            print(
                f"ERROR: Conformance/Index.lean does not import replay for {gate}: expected line '{imp_replay}'",
                file=sys.stderr,
            )
            conf_bad = True

    if conf_bad:
        return 1

    print(
        f"OK: formal coverage baseline is consistent "
        f"({len(seen_keys)} section rows), "
        f"{len(replay_fixture_files)} replay-covered conformance fixtures "
        f"({len(skipped_fixture_files)} runtime/parallel-only fixtures skipped), "
        f"proof_level={proof_level}, claim_level={claim_level}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import json
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
    "value_conservation",
    "da_set_integrity",
}


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


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
    # Policy: every CV-*.json fixture MUST have a matching Lean vectors+replay module
    # imported by Conformance/Index.lean, and a gate theorem named:
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

    fixture_files = sorted(p for p in fixtures_dir.glob("CV-*.json") if p.is_file())
    if not fixture_files:
        return fail("no CV-*.json fixtures found in conformance/fixtures")

    conf_bad = False
    for p in fixture_files:
        fixture = json.loads(p.read_text(encoding="utf-8"))
        gate = fixture.get("gate")
        if not isinstance(gate, str) or not gate.startswith("CV-"):
            print(f"ERROR: invalid or missing gate in fixture {p.relative_to(repo_root)}: {gate}", file=sys.stderr)
            conf_bad = True
            continue

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
        f"({len(seen_keys)} pinned section keys), "
        f"{len(fixture_files)} conformance fixtures covered by Lean replay, "
        f"proof_level={proof_level}, claim_level={claim_level}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

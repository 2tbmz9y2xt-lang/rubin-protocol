#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ALLOWED_STATUS = {"proved", "proved_with_axiom", "stated", "deferred"}
ALLOWED_EVIDENCE_LEVEL = {
    "machine_checked_universal",
    "machine_checked_assumption_backed",
    "machine_checked_behavioral",
    "machine_checked_contract",
    "machine_checked_model",
}
ALLOWED_PROOF_TRUST = {"kernel_checked", "compiler_trusted"}
PENDING_PACKAGE_MATURITY = "experimental_pending_reverification"
ALLOWED_PROOF_LEVEL = {"toy-model", "spec-model", "byte-model", "refinement"}
ALLOWED_CLAIM_LEVEL = {"toy", "byte", "refined"}
EXPECTED_CLAIM_BY_PROOF = {
    "toy-model": "toy",
    "spec-model": "toy",
    "byte-model": "byte",
    "refinement": "refined",
}
REQUIRED_SECTION_EVIDENCE_LEVELS = {
    "consensus_constants": "machine_checked_universal",
    "consensus_constants_witness_lengths_pre_rotation": "machine_checked_universal",
    "consensus_constants_native_binding_manifest_pre_rotation": "machine_checked_universal",
    "transaction_wire": "machine_checked_universal",
    "transaction_identifiers": "machine_checked_universal",
    "transaction_identifiers_crypto_residual": "machine_checked_assumption_backed",
    "weight_accounting": "machine_checked_universal",
    "witness_commitment": "machine_checked_universal",
    "witness_commitment_crypto_residual": "machine_checked_assumption_backed",
    "sighash_v1": "machine_checked_universal",
    "sighash_v1_digest_collision_residual": "machine_checked_assumption_backed",
    "consensus_error_codes": "machine_checked_universal",
    "covenant_registry": "machine_checked_model",
    "difficulty_update": "machine_checked_universal",
    "transaction_structural_rules": "machine_checked_universal",
    "replay_domain_checks": "machine_checked_universal",
    "utxo_state_model": "machine_checked_universal",
    "coinbase_and_subsidy": "machine_checked_universal",
    "value_conservation": "machine_checked_universal",
    "da_set_integrity": "machine_checked_universal",
    "block_timestamp_rules": "machine_checked_universal",
    "fork_choice": "machine_checked_universal",
    "block_validation_order": "machine_checked_universal",
    "parallel_validation_equivalence": "machine_checked_universal",
    "txcontext_formal": "machine_checked_universal",
    "native_rotation": "machine_checked_universal",
    "spend_gate_bridge": "machine_checked_universal",
    "threshold_stealth_spend_suite_gate": "machine_checked_universal",
    "htlc_spend_side_structural": "machine_checked_universal",
    "create_side_live_gate": "machine_checked_universal",
    "htlc_spend_side_crypto_assumption": "machine_checked_assumption_backed",
    "feature_activation_fsm": "machine_checked_universal",
}
REQUIRED_SECTION_KEYS = set(REQUIRED_SECTION_EVIDENCE_LEVELS)
EXPECTED_SOURCE_REBIND_SCALARS = {
    "source_oid": "2d9f1024f1d0b1bfb3fe6a8b727762e7a979b3a0",
    "inventory_sha256": "77c9bac4f36c0bbce260388baad93216cd2b231e12c2a7edfc170ec3070596d6",
    "original_imported_source_paths": 109,
    "active_imported_source_paths": 102,
    "disposition": "DROP_STALE_SOURCE",
    "byte_exact_path_count": 79,
    "reconcile_current_protocol_path_count": 14,
    "import_adapt_single_owner_path_count": 1,
    "transplant_check_logic_path_count": 1,
    "import_package_check_or_test_path_count": 7,
    "active_partition_equation": "79 + 14 + 1 + 1 + 7 = 102",
    "original_inventory_equation": "102 + 7 = 109",
}
SOURCE_REBIND_COUNT_KEYS = {
    "original_imported_source_paths",
    "active_imported_source_paths",
    "byte_exact_path_count",
    "reconcile_current_protocol_path_count",
    "import_adapt_single_owner_path_count",
    "transplant_check_logic_path_count",
    "import_package_check_or_test_path_count",
}
EXPECTED_SOURCE_REBIND_PATHS = {
    "reconcile_current_protocol_paths": {
        "RubinFormal/Conformance/CVVaultLifecycleReplay.lean",
        "RubinFormal/ConnectBlockStrong.lean",
        "RubinFormal/CovenantRegistryExhaustive.lean",
        "RubinFormal/ErrorPriority.lean",
        "RubinFormal/HtlcSpendStructuralLiveBridge.lean",
        "RubinFormal/PerTxStateMachine.lean",
        "RubinFormal/RefinementBridgeV1.lean",
        "RubinFormal/RotationPrelude.lean",
        "RubinFormal/SighashAssumptionBridge.lean",
        "RubinFormal/SpendGateLiveBridge.lean",
        "RubinFormal/StructuralRulesBehavioral.lean",
        "RubinFormal/TxWireTxAfterDaCoreStep.lean",
        "RubinFormal/TxWireTxFinalizeContract.lean",
        "RubinFormal/VaultStateMachine.lean",
    },
    "import_adapt_single_owner_paths": {"REGISTRY_COMPLETENESS_POLICY.md"},
    "transplant_check_logic_paths": {"scripts/check.sh"},
    "import_package_check_or_test_paths": {
        "tests/test_check_formal_registry_truth.py",
        "tests/test_integration.py",
        "tests/test_path_resolution.py",
        "tests/test_registry_extraction.py",
        "tests/test_scope_and_names.py",
        "tests/test_strip_lean_comments.py",
        "tests/test_validation.py",
    },
    "excluded_stale_source_paths": {
        "RubinFormal/ConsensusConstantsBehavioral.lean",
        "RubinFormal/FormalGap03.lean",
        "RubinFormal/TxWireTxPayloadContract.lean",
        "RubinFormal/TxWireTxWithWitnessContract.lean",
        "RubinFormal/TxWireTxAfterDaCoreContract.lean",
        "RubinFormal/TxWireTxBodyContract.lean",
        "RubinFormal/TxWireTxContract.lean",
    },
}
SOURCE_REBIND_LIST_COUNTS = {
    "reconcile_current_protocol_paths": "reconcile_current_protocol_path_count",
    "import_adapt_single_owner_paths": "import_adapt_single_owner_path_count",
    "transplant_check_logic_paths": "transplant_check_logic_path_count",
    "import_package_check_or_test_paths": "import_package_check_or_test_path_count",
}
THEOREM_DECL_RE = re.compile(
    r"^\s*theorem\s+([A-Za-z_][A-Za-z0-9_'?!]*(?:\.[A-Za-z_][A-Za-z0-9_'?!]*)*)(?=\s|$|[:({\[])",
    re.MULTILINE,
)
NAMESPACE_RE = re.compile(r"^\s*namespace\s+([A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*)\s*$")
SECTION_RE = re.compile(r"^\s*section(?:\s+([A-Za-z_][A-Za-z0-9_']*))?\s*$")
END_RE = re.compile(r"^\s*end(?:\s+([A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*))?\s*$")


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def strip_lean_comments(source: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(source):
        if source[i] == '"':
            out.append(source[i])
            i += 1
            while i < len(source):
                ch = source[i]
                out.append(ch)
                if ch == "\\" and i + 1 < len(source):
                    out.append(source[i + 1])
                    i += 2
                    continue
                i += 1
                if ch == '"':
                    break
            continue
        if source.startswith("--", i):
            while i < len(source) and source[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if source.startswith("/-", i):
            depth = 1
            out.extend((" ", " "))
            i += 2
            while i < len(source) and depth:
                if source.startswith("/-", i):
                    depth += 1
                    out.extend((" ", " "))
                    i += 2
                elif source.startswith("-/", i):
                    depth -= 1
                    out.extend((" ", " "))
                    i += 2
                else:
                    out.append("\n" if source[i] == "\n" else " ")
                    i += 1
            continue
        out.append(source[i])
        i += 1
    return "".join(out)


def has_canonical_import(source: str, expected_line: str) -> bool:
    return any(line.strip() == expected_line for line in strip_lean_comments(source).splitlines())


def declared_lean_theorems_in_text(source: str) -> set[str]:
    names: set[str] = set()
    scope_stack: list[tuple[str, str | None]] = []
    for line in strip_lean_comments(source).splitlines():
        if match := NAMESPACE_RE.match(line):
            scope_stack.append(("namespace", match.group(1)))
            continue
        if match := SECTION_RE.match(line):
            scope_stack.append(("section", match.group(1)))
            continue
        if match := END_RE.match(line):
            label = match.group(1)
            if label is None:
                if scope_stack:
                    scope_stack.pop()
            else:
                for index in range(len(scope_stack) - 1, -1, -1):
                    if scope_stack[index][1] == label:
                        del scope_stack[index:]
                        break
            continue
        if match := THEOREM_DECL_RE.match(line):
            namespace = ".".join(label for kind, label in scope_stack if kind == "namespace" and label is not None)
            names.add(f"{namespace}.{match.group(1)}" if namespace else match.group(1))
    return names


def declared_lean_theorems(lean_root: Path) -> set[str]:
    names: set[str] = set()
    for path in lean_root.rglob("*.lean"):
        names.update(declared_lean_theorems_in_text(path.read_text(encoding="utf-8")))
    return names


def validate_source_rebind(doc: dict) -> list[str]:
    source_rebind = doc.get("source_rebind")
    if not isinstance(source_rebind, dict):
        return ["missing source_rebind{} provenance manifest"]

    errors: list[str] = []
    for key, expected in EXPECTED_SOURCE_REBIND_SCALARS.items():
        value = source_rebind.get(key)
        if key in SOURCE_REBIND_COUNT_KEYS and type(value) is not int:
            errors.append(
                f"source_rebind.{key} must be an exact integer, got {value!r}"
            )
            continue
        if value != expected:
            errors.append(f"source_rebind.{key} drift: expected {expected!r}, got {value!r}")

    for key, expected_paths in EXPECTED_SOURCE_REBIND_PATHS.items():
        value = source_rebind.get(key)
        if not isinstance(value, list) or not all(isinstance(path, str) and path for path in value):
            errors.append(f"source_rebind.{key} must be a string list")
            continue
        if len(value) != len(set(value)):
            errors.append(f"source_rebind.{key} contains duplicate paths")
        if set(value) != expected_paths:
            errors.append(
                f"source_rebind.{key} set drift: expected {sorted(expected_paths)!r}, got {sorted(set(value))!r}"
            )
        count_key = SOURCE_REBIND_LIST_COUNTS.get(key)
        count_value = source_rebind.get(count_key) if count_key is not None else None
        if count_key is not None and type(count_value) is int and count_value != len(value):
            errors.append(
                f"source_rebind.{count_key} does not match {key} length: "
                f"{count_value!r} != {len(value)}"
            )

    active_parts = (
        source_rebind.get("byte_exact_path_count"),
        source_rebind.get("reconcile_current_protocol_path_count"),
        source_rebind.get("import_adapt_single_owner_path_count"),
        source_rebind.get("transplant_check_logic_path_count"),
        source_rebind.get("import_package_check_or_test_path_count"),
    )
    if all(type(value) is int for value in active_parts):
        active_total = sum(active_parts)
        if active_total != source_rebind.get("active_imported_source_paths"):
            errors.append(
                "source_rebind active partition drift: "
                f"{' + '.join(str(value) for value in active_parts)} = {active_total}, "
                f"active_imported_source_paths={source_rebind.get('active_imported_source_paths')!r}"
            )

    excluded_paths = source_rebind.get("excluded_stale_source_paths")
    if isinstance(excluded_paths, list):
        active_total = source_rebind.get("active_imported_source_paths")
        original_total = source_rebind.get("original_imported_source_paths")
        if type(active_total) is int and type(original_total) is int:
            rebound_total = active_total + len(excluded_paths)
            if rebound_total != original_total:
                errors.append(
                    "source_rebind original inventory drift: "
                    f"{active_total} + {len(excluded_paths)} = {rebound_total}, "
                    f"original_imported_source_paths={original_total!r}"
                )
    return errors


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
        "proved_with_axiom_rows": status_counts["proved_with_axiom"],
        "stated_rows": status_counts["stated"],
        "deferred_rows": status_counts["deferred"],
        "theorem_references": len(theorem_refs),
        "unique_theorem_names": len(unique_theorems),
        "reused_theorem_names": reused_theorems,
    }

    errors: list[str] = []
    for key, value in expected.items():
        if key == "proved_with_axiom_rows" and value == 0 and key not in summary:
            # Backward compatibility for unit fixtures and older zero-axiom registries.
            continue
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

    source_rebind_errors = validate_source_rebind(coverage)
    if source_rebind_errors:
        for err in source_rebind_errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

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
    if coverage.get("package_maturity") != PENDING_PACKAGE_MATURITY:
        return fail(
            "package_maturity must be experimental_pending_reverification in rubin-formal/proof_coverage.json"
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

    evidence_taxonomy = coverage.get("status_taxonomy")
    if not isinstance(evidence_taxonomy, dict) or set(evidence_taxonomy) != ALLOWED_EVIDENCE_LEVEL:
        return fail(
            "status_taxonomy keys drift in rubin-formal/proof_coverage.json: "
            f"expected {sorted(ALLOWED_EVIDENCE_LEVEL)}, "
            f"got {sorted(evidence_taxonomy) if isinstance(evidence_taxonomy, dict) else evidence_taxonomy}"
        )

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
        evidence_level = row.get("evidence_level")
        proof_trust = row.get("proof_trust")
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

        expected_evidence_level = REQUIRED_SECTION_EVIDENCE_LEVELS[key]
        if evidence_level != expected_evidence_level:
            print(
                f"ERROR: evidence_level drift for {key}: expected {expected_evidence_level}, got {evidence_level}",
                file=sys.stderr,
            )
            bad = True
        if proof_trust not in ALLOWED_PROOF_TRUST:
            print(
                f"ERROR: invalid proof_trust for {key}: {proof_trust}; expected one of {sorted(ALLOWED_PROOF_TRUST)}",
                file=sys.stderr,
            )
            bad = True
        if status == "proved_with_axiom" and evidence_level != "machine_checked_assumption_backed":
            print(
                f"ERROR: {key} has status=proved_with_axiom but evidence_level={evidence_level}",
                file=sys.stderr,
            )
            bad = True
        if evidence_level == "machine_checked_assumption_backed" and status != "proved_with_axiom":
            print(
                f"ERROR: {key} has assumption-backed evidence but status={status}; expected proved_with_axiom",
                file=sys.stderr,
            )
            bad = True

        if status in {"proved", "proved_with_axiom", "stated"}:
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
        if not has_canonical_import(index_txt, imp_vectors):
            print(
                f"ERROR: Conformance/Index.lean does not import vectors for {gate}: expected line '{imp_vectors}'",
                file=sys.stderr,
            )
            conf_bad = True
        if not has_canonical_import(index_txt, imp_replay):
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

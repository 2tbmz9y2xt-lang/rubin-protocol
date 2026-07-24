#!/usr/bin/env python3
from __future__ import annotations

import hashlib
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
CLAIM_BOUNDARY_EVIDENCE_LEVELS = {
    "machine_checked_assumption_backed",
    "machine_checked_model",
}
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
    "witness_commitment": "machine_checked_contract",
    "witness_commitment_crypto_residual": "machine_checked_assumption_backed",
    "sighash_v1": "machine_checked_universal",
    "sighash_v1_crypto_residual": "machine_checked_assumption_backed",
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
    "fork_choice": "machine_checked_model",
    "block_validation_order": "machine_checked_model",
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
    "original_imported_source_paths": 116,
    "active_imported_source_paths": 102,
    "byte_exact_path_count": 73,
    "reconcile_current_protocol_path_count": 19,
    "drop_retired_generated_source_path_count": 4, "drop_retired_source_path_count": 3, "drop_stale_source_path_count": 7,
    "import_adapt_single_owner_path_count": 1,
    "transplant_check_logic_path_count": 2,
    "import_package_check_or_test_path_count": 7,
    "active_partition_equation": "73 + 19 + 1 + 2 + 7 = 102",
    "original_inventory_equation": "102 + 4 + 3 + 7 = 116",
}
EXPECTED_SOURCE_MANIFEST_PIN_SHA256 = "62f58d1c3151e98f4252d5bfb570d141c03f64ab4feb070c1328912b6bbf39c1"
SOURCE_REBIND_COUNT_KEYS = {
    "original_imported_source_paths",
    "active_imported_source_paths",
    "byte_exact_path_count",
    "reconcile_current_protocol_path_count",
    "drop_retired_generated_source_path_count", "drop_retired_source_path_count", "drop_stale_source_path_count",
    "import_adapt_single_owner_path_count",
    "transplant_check_logic_path_count",
    "import_package_check_or_test_path_count",
}
EXPECTED_SOURCE_REBIND_PATHS = {
    "reconcile_current_protocol_paths": {
        "RubinFormal/BlockValidationOrder.lean",
        "RubinFormal/Conformance/CVVaultLifecycleReplay.lean",
        "RubinFormal/ConnectBlockFull.lean",
        "RubinFormal/ConnectBlockStrong.lean",
        "RubinFormal/CovenantRegistryExhaustive.lean",
        "RubinFormal/ErrorPriority.lean",
        "RubinFormal/FeatureActivationLiveBridge.lean",
        "RubinFormal/ForkChoiceSelect.lean",
        "RubinFormal/HtlcSpendStructuralLiveBridge.lean",
        "RubinFormal/PerTxStateMachine.lean",
        "RubinFormal/RefinementBridgeV1.lean",
        "RubinFormal/RotationPrelude.lean",
        "RubinFormal/SighashAssumptionBridge.lean",
        "RubinFormal/SpendGateLiveBridge.lean",
        "RubinFormal/StructuralRulesBehavioral.lean",
        "RubinFormal/ThresholdSpendSuiteGateBridge.lean",
        "RubinFormal/TxWireTxAfterDaCoreStep.lean",
        "RubinFormal/TxWireTxFinalizeContract.lean",
        "RubinFormal/VaultStateMachine.lean",
    },
    "import_adapt_single_owner_paths": {"REGISTRY_COMPLETENESS_POLICY.md"},
    "transplant_check_logic_paths": {"scripts/check.sh", "tools/check_formal_registry_truth.py"},
    "import_package_check_or_test_paths": {
        "tests/test_check_formal_registry_truth.py",
        "tests/test_integration.py",
        "tests/test_path_resolution.py",
        "tests/test_registry_extraction.py",
        "tests/test_scope_and_names.py",
        "tests/test_strip_lean_comments.py",
        "tests/test_validation.py",
    },
    "drop_retired_generated_source_paths": {"RubinFormal/Conformance/CVExtVectors.lean", "RubinFormal/Conformance/CVExtReplay.lean", "RubinFormal/Conformance/CVTxctxVectors.lean", "RubinFormal/Conformance/CVTxctxReplay.lean"},
    "drop_retired_source_paths": {"RubinFormal/CoreExtInvariants.lean", "RubinFormal/NativeExtIndependence.lean", "RubinFormal/GovernanceReplayToken.lean"},
    "drop_stale_source_paths": {"RubinFormal/ConsensusConstantsBehavioral.lean", "RubinFormal/FormalGap03.lean", "RubinFormal/TxWireTxPayloadContract.lean", "RubinFormal/TxWireTxWithWitnessContract.lean", "RubinFormal/TxWireTxAfterDaCoreContract.lean", "RubinFormal/TxWireTxBodyContract.lean", "RubinFormal/TxWireTxContract.lean"},
    "semantic_theorem_reconciliation_retired_paths": {"RubinFormal/CoreExtRefinement.lean"},
}


def claim_boundary_limitations_error(
    key: object, evidence_level: object, limitations: object
) -> str | None:
    if evidence_level not in CLAIM_BOUNDARY_EVIDENCE_LEVELS:
        return None
    if (
        not isinstance(limitations, list)
        or not limitations
        or not all(isinstance(item, str) and item.strip() for item in limitations)
    ):
        return (
            f"{key} has evidence_level={evidence_level} but limitations[] must be "
            "a non-empty list of non-empty strings"
        )
    return None
EXPECTED_ACTIVE_SOURCE_PATHS = frozenset("""
REGISTRY_COMPLETENESS_POLICY.md RubinFormal/BlockHeaderRoundtrip.lean RubinFormal/BlockTimestampBehavioral.lean RubinFormal/BlockValidationOrder.lean RubinFormal/BlockValidationOrderBehavioral.lean RubinFormal/ByteWireLegacy.lean RubinFormal/BytesEqLemmas.lean RubinFormal/ChainIdBehavioral.lean RubinFormal/ChainWorkV1.lean RubinFormal/CoinbaseBehavioral.lean RubinFormal/CoinbaseSubsidyBehavioral.lean
RubinFormal/Conformance/CVVaultLifecycleReplay.lean RubinFormal/ConnectBlockFull.lean RubinFormal/ConnectBlockStrong.lean RubinFormal/CovenantParserGaps.lean RubinFormal/CovenantRegistryExhaustive.lean RubinFormal/CreateSideLiveGateBridge.lean RubinFormal/DaIntegrityBehavioral.lean RubinFormal/DeterminismRequirements.lean RubinFormal/ErrorPriority.lean RubinFormal/FeatureActivationFSM.lean RubinFormal/FeatureActivationLiveBridge.lean
RubinFormal/ForkChoiceSelect.lean RubinFormal/ForkChoiceTiebreak.lean RubinFormal/ForkChoiceV1.lean RubinFormal/GenesisRuleBehavioral.lean RubinFormal/HtlcSpendCryptoAssumptionBridge.lean RubinFormal/HtlcSpendStructuralLiveBridge.lean RubinFormal/LegacySunset.lean RubinFormal/MerkleStructure.lean RubinFormal/NativeRegistryResolution.lean RubinFormal/NativeSpendCreateGate.lean RubinFormal/NativeSuiteRotation.lean RubinFormal/PerTxStateMachine.lean RubinFormal/PrimitiveEncodingRoundtrip.lean
RubinFormal/Refinement/AbortSoundness.lean RubinFormal/RefinementBridgeV1.lean RubinFormal/RegistryResolutionLiveBridge.lean RubinFormal/ReplayDomainBehavioral.lean RubinFormal/ReplayDomainUniversal.lean RubinFormal/RetargetBehavioral.lean RubinFormal/RotationPrelude.lean RubinFormal/SighashAssumptionBridge.lean RubinFormal/SighashRefinementUpgrade.lean RubinFormal/SpendGateLiveBridge.lean RubinFormal/SpendTxEndToEnd.lean RubinFormal/StructuralRulesBehavioral.lean RubinFormal/ThresholdSpendSuiteGateBridge.lean
RubinFormal/TransactionWireBehavioral.lean RubinFormal/TxContextBehavioral.lean RubinFormal/TxContextFormal.lean RubinFormal/TxIdBehavioral.lean RubinFormal/TxWeightBehavioral.lean RubinFormal/TxWireCompactSizeLemmas.lean RubinFormal/TxWireCompactSizeNineByteLemmas.lean RubinFormal/TxWireCompactSizeNineLemmas.lean RubinFormal/TxWireCompactSizeNineMidLemmas.lean RubinFormal/TxWireCompactSizeThreeLemmas.lean RubinFormal/TxWireDaCoreBase.lean
RubinFormal/TxWireDaCoreContract.lean RubinFormal/TxWireDaCoreKind1Contract.lean RubinFormal/TxWireDaCoreKind2Contract.lean RubinFormal/TxWireDaCoreKind2Info.lean RubinFormal/TxWireExtractExact.lean RubinFormal/TxWireFullContract.lean RubinFormal/TxWireInputBetweenContract.lean RubinFormal/TxWireInputPostContract.lean RubinFormal/TxWireListContract.lean RubinFormal/TxWireOutputBetweenContract.lean RubinFormal/TxWireOutputPostContract.lean RubinFormal/TxWirePrefixLemmas.lean
RubinFormal/TxWireRoundtrip.lean RubinFormal/TxWireShiftLemmas.lean RubinFormal/TxWireTxAfterDaCoreStep.lean RubinFormal/TxWireTxAfterLockDaCoreExtract.lean RubinFormal/TxWireTxAfterLockDaCoreRead.lean RubinFormal/TxWireTxAfterLockStep.lean RubinFormal/TxWireTxFinalizeContract.lean RubinFormal/TxWireTxWitnessReadContract.lean RubinFormal/TxWireWitnessBetweenContract.lean RubinFormal/TxWireWitnessContract.lean RubinFormal/TxWireWitnessPostContract.lean RubinFormal/UtxoMapProperties.lean
RubinFormal/UtxoSpendTxBehavioral.lean RubinFormal/ValueConservationBehavioral.lean RubinFormal/VaultStateMachine.lean RubinFormal/VaultThresholdBound.lean RubinFormal/WeightBehavioral.lean RubinFormal/WeightSuiteAware.lean RubinFormal/WitnessCommitmentPregate.lean RubinFormal/WitnessCommitmentV1.lean scripts/check.sh tests/test_check_formal_registry_truth.py tests/test_covenant_registry_disposition.py tests/test_integration.py tests/test_path_resolution.py tests/test_registry_extraction.py tests/test_scope_and_names.py tests/test_strip_lean_comments.py tests/test_validation.py tools/LOCAL_CODEX_EXEC_REVIEW.md tools/check_formal_registry_truth.py
""".split())
ACTIVE_SOURCE_DISPOSITIONS = {
    "reconcile_current_protocol_paths": "RECONCILE_CURRENT_PROTOCOL",
    "import_adapt_single_owner_paths": "IMPORT_ADAPT_SINGLE_OWNER",
    "transplant_check_logic_paths": "TRANSPLANT_CHECK_LOGIC",
    "import_package_check_or_test_paths": "IMPORT_PACKAGE_CHECK_OR_TEST",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_REBIND_LIST_COUNTS = {
    "reconcile_current_protocol_paths": "reconcile_current_protocol_path_count",
    "import_adapt_single_owner_paths": "import_adapt_single_owner_path_count",
    "transplant_check_logic_paths": "transplant_check_logic_path_count",
    "import_package_check_or_test_paths": "import_package_check_or_test_path_count",
    "drop_retired_generated_source_paths": "drop_retired_generated_source_path_count", "drop_retired_source_paths": "drop_retired_source_path_count", "drop_stale_source_paths": "drop_stale_source_path_count",
}
THEOREM_DECL_RE = re.compile(
    r"^\s*theorem\s+([A-Za-z_][A-Za-z0-9_'?!]*(?:\.[A-Za-z_][A-Za-z0-9_'?!]*)*)(?=\s|$|[:({\[])",
    re.MULTILINE,
)
NAMESPACE_RE = re.compile(r"^\s*namespace\s+([A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*)\s*$")
SECTION_RE = re.compile(r"^\s*section(?:\s+([A-Za-z_][A-Za-z0-9_']*))?\s*$")
END_RE = re.compile(r"^\s*end(?:\s+([A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*))?\s*$")
LEAN_IMPORT_RE = re.compile(r"^\s*import\s+(RubinFormal(?:\.[A-Za-z][A-Za-z0-9_']*)+)\s*$", re.MULTILINE)


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def _blank_lean_span(source: str, start: int, end: int, out: list[str]) -> None:
    out.extend("\n" if ch == "\n" else " " for ch in source[start:end])


def _consume_lean_string(source: str, start: int, out: list[str], *, blank: bool) -> int:
    i = start + 1
    while i < len(source):
        if source[i] == "\\" and i + 1 < len(source):
            i += 2
            continue
        if source[i] == '"':
            i += 1
            break
        i += 1
    if blank:
        _blank_lean_span(source, start, i, out)
    else:
        out.extend(source[start:i])
    return i


def _consume_lean_raw_string(source: str, start: int, out: list[str], *, blank: bool) -> int | None:
    quote = start + 1
    while quote < len(source) and source[quote] == "#":
        quote += 1
    if quote >= len(source) or source[quote] != '"':
        return None
    delimiter = "#" * (quote - start - 1)
    i = quote + 1
    while i < len(source):
        if source[i] == '"' and source.startswith(delimiter, i + 1):
            i += 1 + len(delimiter)
            break
        i += 1
    if blank:
        _blank_lean_span(source, start, i, out)
    else:
        out.extend(source[start:i])
    return i


def _strip_lean(source: str, *, blank_strings: bool) -> str:
    out: list[str] = []
    i = 0
    while i < len(source):
        if source[i] == "r":
            raw_end = _consume_lean_raw_string(source, i, out, blank=blank_strings)
            if raw_end is not None:
                i = raw_end
                continue
        if source[i] == '"':
            i = _consume_lean_string(source, i, out, blank=blank_strings)
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


def strip_lean_comments(source: str) -> str:
    """Blank Lean comments while preserving quoted strings and line positions."""
    return _strip_lean(source, blank_strings=False)


def blank_lean_comments_and_strings(source: str) -> str:
    """Blank Lean comments and quoted/raw strings while preserving line positions."""
    return _strip_lean(source, blank_strings=True)


def has_canonical_import(source: str, expected_line: str) -> bool:
    return any(line.strip() == expected_line for line in blank_lean_comments_and_strings(source).splitlines())


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

    retired_counts = [source_rebind.get(key) for key in ("drop_retired_generated_source_path_count", "drop_retired_source_path_count", "drop_stale_source_path_count")]
    if all(type(count) is int for count in retired_counts):
        active_total = source_rebind.get("active_imported_source_paths")
        original_total = source_rebind.get("original_imported_source_paths")
        if type(active_total) is int and type(original_total) is int:
            rebound_total = active_total + sum(retired_counts)
            if rebound_total != original_total:
                errors.append(
                    "source_rebind original inventory drift: "
                    f"{active_total} + {' + '.join(str(count) for count in retired_counts)} = {rebound_total}, "
                    f"original_imported_source_paths={original_total!r}"
                )
    return errors


def expected_active_source_dispositions() -> dict[str, str]:
    expected = {path: "BYTE_EXACT" for path in EXPECTED_ACTIVE_SOURCE_PATHS}
    for category, disposition in ACTIVE_SOURCE_DISPOSITIONS.items():
        for path in EXPECTED_SOURCE_REBIND_PATHS[category]:
            expected[path] = disposition
    return expected


def pinned_source_manifest_digest(source_oid: object, manifest: object) -> str | None:
    if not isinstance(source_oid, str) or not isinstance(manifest, dict):
        return None
    entries: list[str] = []
    for path in sorted(manifest):
        record = manifest[path]
        if not isinstance(path, str) or not isinstance(record, dict):
            return None
        source_hash = record.get("source_sha256")
        if not isinstance(source_hash, str):
            return None
        entries.append(f"{path}\0{source_hash}")
    payload = "\n".join([source_oid, *entries]).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_active_path_manifest(repo_root: Path, doc: dict) -> list[str]:
    source_rebind = doc.get("source_rebind")
    if not isinstance(source_rebind, dict): return []
    manifest = source_rebind.get("active_path_manifest")
    if not isinstance(manifest, dict): return ["source_rebind.active_path_manifest must be an object"]
    expected = expected_active_source_dispositions()
    errors: list[str] = []
    if pinned_source_manifest_digest(source_rebind.get("source_oid"), manifest) != EXPECTED_SOURCE_MANIFEST_PIN_SHA256:
        errors.append("source_rebind.active_path_manifest source digest drift")
    if len(manifest) != 102: errors.append(f"source_rebind.active_path_manifest count drift: expected 102, got {len(manifest)}")
    if set(manifest) != set(expected): errors.append("source_rebind.active_path_manifest key set drift")
    for path, disposition in expected.items():
        record = manifest.get(path)
        if not isinstance(record, dict):
            errors.append(f"source_rebind.active_path_manifest[{path}] must be an object"); continue
        if record.get("disposition") != disposition:
            errors.append(f"source_rebind.active_path_manifest[{path}].disposition drift: expected {disposition!r}, got {record.get('disposition')!r}")
        source_hash, candidate_hash = record.get("source_sha256"), record.get("candidate_sha256")
        for key, value in (("source_sha256", source_hash), ("candidate_sha256", candidate_hash)):
            if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
                errors.append(f"source_rebind.active_path_manifest[{path}].{key} must be lowercase SHA-256")
        candidate = repo_root / "rubin-formal" / path
        if not candidate.is_file():
            errors.append(f"source_rebind.active_path_manifest candidate missing: {path}")
        elif isinstance(candidate_hash, str) and SHA256_RE.fullmatch(candidate_hash) and hashlib.sha256(candidate.read_bytes()).hexdigest() != candidate_hash:
            errors.append(f"source_rebind.active_path_manifest candidate hash drift: {path}")
        if isinstance(source_hash, str) and isinstance(candidate_hash, str) and SHA256_RE.fullmatch(source_hash) and SHA256_RE.fullmatch(candidate_hash):
            equal = source_hash == candidate_hash
            if equal != (disposition == "BYTE_EXACT"):
                errors.append(f"source_rebind.active_path_manifest source/candidate disposition drift: {path}")
    return errors


def validate_retired_source_paths(repo_root: Path, doc: dict) -> list[str]:
    source_rebind = doc.get("source_rebind")
    if not isinstance(source_rebind, dict): return []
    retired = [path for key in ("drop_retired_generated_source_paths", "drop_retired_source_paths", "drop_stale_source_paths", "semantic_theorem_reconciliation_retired_paths") for path in source_rebind.get(key, []) if isinstance(path, str)]
    formal_root, entrypoint = repo_root / "rubin-formal", repo_root / "rubin-formal" / "RubinFormal.lean"
    if not entrypoint.exists(): return ["RubinFormal.lean missing while checking retired source paths"]

    reachable: set[str] = set()
    pending, visited = [entrypoint], {entrypoint.resolve()}
    while pending:
        path = pending.pop()
        for module in LEAN_IMPORT_RE.findall(blank_lean_comments_and_strings(path.read_text(encoding="utf-8"))):
            rel_path = f"{module.replace('.', '/')}.lean"
            reachable.add(rel_path)
            imported = formal_root / rel_path
            if imported.exists() and imported.resolve() not in visited:
                visited.add(imported.resolve()); pending.append(imported)

    errors = []
    for rel_path in retired:
        if (formal_root / rel_path).exists(): errors.append(f"retired source path remains in candidate tree: {rel_path}")
        if rel_path in reachable: errors.append(f"retired source path remains reachable from RubinFormal.lean: {rel_path}")
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
    source_rebind_errors.extend(validate_active_path_manifest(repo_root, coverage))
    source_rebind_errors.extend(validate_retired_source_paths(repo_root, coverage))
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
        if error := claim_boundary_limitations_error(
            key, evidence_level, row.get("limitations")
        ):
            print(f"ERROR: {error}", file=sys.stderr)
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

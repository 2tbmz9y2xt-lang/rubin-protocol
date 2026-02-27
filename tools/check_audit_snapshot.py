#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


ALLOWED_STATUS = {
    "OPEN",
    "DONE",
    "ALREADY_FIXED",
    "ACCEPTED_RISK",
    "DEFERRED",
    "DOC_FIX",
    "PARTIALLY_ADDRESSED",
    "WONTFIX",
    "RETRACTED",
}
ALLOWED_LAYER = {"spec", "repo", "ci"}


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate AUDIT_SNAPSHOT schema and consistency")
    parser.add_argument(
        "--context-root",
        default=".",
        help="Root directory that contains AUDIT_CONTEXT/AUDIT_SNAPSHOT (default: cwd)",
    )
    parser.add_argument(
        "--code-root",
        default=".",
        help="Root directory that contains CI workflow + proof_coverage.json (default: cwd)",
    )
    parser.add_argument("--snapshot", default="spec/AUDIT_SNAPSHOT.json", help="Snapshot JSON path (repo-relative)")
    parser.add_argument("--context", default="spec/AUDIT_CONTEXT.md", help="AUDIT_CONTEXT path (repo-relative)")
    parser.add_argument("--ci-workflow", default=".github/workflows/ci.yml", help="CI workflow path (repo-relative)")
    parser.add_argument("--proof-coverage", default="rubin-formal/proof_coverage.json", help="proof_coverage path (repo-relative)")
    args = parser.parse_args()

    context_root = Path(args.context_root).resolve()
    code_root = Path(args.code_root).resolve()

    snapshot_path = context_root / args.snapshot
    context_path = context_root / args.context
    ci_path = code_root / args.ci_workflow
    proof_path = code_root / args.proof_coverage

    for p in (snapshot_path, context_path, ci_path, proof_path):
        if not p.exists():
            # Keep the message simple and actionable (cross-repo split supported).
            return fail(f"required file not found: {p}")

    doc = json.loads(snapshot_path.read_text(encoding="utf-8", errors="strict"))

    if doc.get("schema_version") != 1:
        return fail("schema_version must be 1")
    if doc.get("source_file") != args.context:
        return fail(f"source_file mismatch: expected {args.context}, got {doc.get('source_file')}")

    expected_src_hash = file_sha256(context_path)
    if doc.get("source_sha256") != expected_src_hash:
        return fail("source_sha256 mismatch: snapshot stale vs AUDIT_CONTEXT.md")

    formal_status = doc.get("formal_status")
    if not isinstance(formal_status, dict):
        return fail("formal_status must be object")
    proof_doc = json.loads(proof_path.read_text(encoding="utf-8", errors="strict"))
    if formal_status.get("proof_level") != proof_doc.get("proof_level"):
        return fail("formal_status.proof_level mismatch vs proof_coverage.json")
    if formal_status.get("claim_level") != proof_doc.get("claim_level"):
        return fail("formal_status.claim_level mismatch vs proof_coverage.json")

    ci = doc.get("ci_enforcement")
    if not isinstance(ci, dict):
        return fail("ci_enforcement must be object")
    ci_text = ci_path.read_text(encoding="utf-8", errors="strict")
    expected_ci = {
        "ci_workflow_present": True,
        "section_hashes_check": "check-section-hashes.mjs" in ci_text,
        "formal_claims_lint_check": "check_formal_claims_lint.py" in ci_text,
        "conformance_bundle_check": "run_cv_bundle.py" in ci_text,
    }
    for key, expected in expected_ci.items():
        if ci.get(key) != expected:
            return fail(f"ci_enforcement.{key} mismatch: expected {expected}, got {ci.get(key)}")

    findings = doc.get("findings")
    if not isinstance(findings, list) or not findings:
        return fail("findings must be non-empty list")

    seen: set[str] = set()
    by_status: dict[str, int] = {}
    by_layer: dict[str, int] = {}
    by_severity: dict[str, int] = {}

    for idx, item in enumerate(findings):
        if not isinstance(item, dict):
            return fail(f"findings[{idx}] must be object")
        finding_id = item.get("finding_id")
        status = item.get("status")
        layer = item.get("layer")
        severity = item.get("severity")
        evidence = item.get("evidence")
        sources = item.get("sources")
        summary = item.get("summary")

        if not isinstance(finding_id, str) or not finding_id:
            return fail(f"findings[{idx}].finding_id invalid")
        if finding_id in seen:
            return fail(f"duplicate finding_id: {finding_id}")
        seen.add(finding_id)

        if status not in ALLOWED_STATUS:
            return fail(f"finding {finding_id}: invalid status {status}")
        if layer not in ALLOWED_LAYER:
            return fail(f"finding {finding_id}: invalid layer {layer}")
        if not isinstance(severity, str) or not severity:
            return fail(f"finding {finding_id}: severity must be non-empty string")
        if not isinstance(summary, str) or not summary:
            return fail(f"finding {finding_id}: summary must be non-empty string")
        if not isinstance(evidence, list) or len(evidence) == 0:
            return fail(f"finding {finding_id}: evidence must be non-empty list")
        if not isinstance(sources, list) or len(sources) == 0:
            return fail(f"finding {finding_id}: sources must be non-empty list")

        if "ALREADY_FIXED" in summary.upper() and status != "ALREADY_FIXED":
            return fail(
                f"finding {finding_id}: summary marks ALREADY_FIXED but status={status}"
            )

        # Для любого статуса должен быть минимум один source-line ref.
        has_source_line = any(isinstance(ref, str) and "#L" in ref for ref in evidence)
        if not has_source_line:
            return fail(f"finding {finding_id}: evidence must include at least one source line ref")

        by_status[status] = by_status.get(status, 0) + 1
        by_layer[layer] = by_layer.get(layer, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1

    stats = doc.get("stats")
    if not isinstance(stats, dict):
        return fail("stats must be object")
    if stats.get("total") != len(findings):
        return fail("stats.total mismatch")
    if stats.get("by_status") != by_status:
        return fail("stats.by_status mismatch")
    if stats.get("by_layer") != by_layer:
        return fail("stats.by_layer mismatch")
    if stats.get("by_severity") != by_severity:
        return fail("stats.by_severity mismatch")

    print(
        f"OK: audit snapshot valid ({len(findings)} findings; "
        f"OPEN={by_status.get('OPEN', 0)}, CLOSED={len(findings) - by_status.get('OPEN', 0)})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

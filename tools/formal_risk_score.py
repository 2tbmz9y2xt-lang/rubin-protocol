#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
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


@dataclass(frozen=True)
class RiskSummary:
    proof_level: str
    claim_level: str
    total_sections: int
    proved: int
    stated: int
    deferred: int
    risk_score: int
    risk_tier: str
    deferred_keys: list[str]
    stated_keys: list[str]


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def _risk_score(proof_level: str, stated: int, deferred: int) -> tuple[int, str]:
    # Simple monotonic score:
    # - proof_level contributes a base "model gap" risk.
    # - stated/deferred contribute coverage risk.
    proof_level_base = {
        "toy-model": 6,
        "spec-model": 3,
        "byte-model": 1,
        "refinement": 0,
    }[proof_level]
    score = proof_level_base + (2 * stated) + (5 * deferred)
    if score >= 8:
        tier = "HIGH"
    elif score >= 4:
        tier = "MEDIUM"
    else:
        tier = "LOW"
    return score, tier


def load_proof_coverage(repo_root: Path) -> dict:
    coverage_path = repo_root / "rubin-formal" / "proof_coverage.json"
    if not coverage_path.exists():
        raise FileNotFoundError("rubin-formal/proof_coverage.json not found")
    return json.loads(coverage_path.read_text(encoding="utf-8"))


def summarize(coverage_doc: dict) -> RiskSummary:
    proof_level = coverage_doc.get("proof_level")
    if proof_level not in ALLOWED_PROOF_LEVEL:
        raise ValueError(f"invalid proof_level: {proof_level}; expected one of {sorted(ALLOWED_PROOF_LEVEL)}")
    claim_level = coverage_doc.get("claim_level")
    if claim_level not in ALLOWED_CLAIM_LEVEL:
        raise ValueError(f"invalid claim_level: {claim_level}; expected one of {sorted(ALLOWED_CLAIM_LEVEL)}")
    expected_claim = EXPECTED_CLAIM_BY_PROOF.get(proof_level)
    if claim_level != expected_claim:
        raise ValueError(
            f"proof_level/claim_level mismatch: proof_level={proof_level} requires claim_level={expected_claim}, got {claim_level}"
        )

    rows = coverage_doc.get("coverage")
    if not isinstance(rows, list) or not rows:
        raise ValueError("coverage[] missing or empty")

    proved = stated = deferred = 0
    deferred_keys: list[str] = []
    stated_keys: list[str] = []

    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"coverage[{i}] is not an object")
        status = row.get("status")
        key = row.get("section_key")
        if status not in ALLOWED_STATUS:
            raise ValueError(f"invalid status for {key}: {status}; expected one of {sorted(ALLOWED_STATUS)}")
        if not isinstance(key, str) or not key:
            raise ValueError(f"missing/invalid section_key at coverage[{i}]")

        if status == "proved":
            proved += 1
        elif status == "stated":
            stated += 1
            stated_keys.append(key)
        else:
            deferred += 1
            deferred_keys.append(key)

    score, tier = _risk_score(proof_level, stated, deferred)
    return RiskSummary(
        proof_level=proof_level,
        claim_level=claim_level,
        total_sections=len(rows),
        proved=proved,
        stated=stated,
        deferred=deferred,
        risk_score=score,
        risk_tier=tier,
        deferred_keys=sorted(deferred_keys),
        stated_keys=sorted(stated_keys),
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute a simple formal-proof risk score from rubin-formal/proof_coverage.json"
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    try:
        doc = load_proof_coverage(repo_root)
        summary = summarize(doc)
    except Exception as e:
        return fail(str(e))

    if args.json:
        print(
            json.dumps(
                {
                    "proof_level": summary.proof_level,
                    "claim_level": summary.claim_level,
                    "total_sections": summary.total_sections,
                    "proved": summary.proved,
                    "stated": summary.stated,
                    "deferred": summary.deferred,
                    "risk_score": summary.risk_score,
                    "risk_tier": summary.risk_tier,
                    "stated_keys": summary.stated_keys,
                    "deferred_keys": summary.deferred_keys,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    print("FORMAL_RISK_SCORE")
    print(f"- proof_level: {summary.proof_level}")
    print(f"- claim_level: {summary.claim_level}")
    print(f"- coverage: total={summary.total_sections} proved={summary.proved} stated={summary.stated} deferred={summary.deferred}")
    print(f"- risk_score: {summary.risk_score}")
    print(f"- risk_tier: {summary.risk_tier}")
    if summary.stated_keys:
        print("- stated sections:")
        for k in summary.stated_keys:
            print(f"  - {k}")
    if summary.deferred_keys:
        print("- deferred sections:")
        for k in summary.deferred_keys:
            print(f"  - {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

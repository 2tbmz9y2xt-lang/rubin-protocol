#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from formal_risk_score import ALLOWED_PROOF_LEVEL, RiskSummary, load_proof_coverage, summarize


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def _require_claim_boundaries(doc: dict) -> None:
    claims = doc.get("claims")
    if not isinstance(claims, dict):
        raise ValueError("claims{} missing")
    allowed = claims.get("allowed")
    forbidden = claims.get("forbidden")
    if not isinstance(allowed, list) or len(allowed) == 0:
        raise ValueError("claims.allowed[] missing/empty (must prevent overclaims)")
    if not isinstance(forbidden, list) or len(forbidden) == 0:
        raise ValueError("claims.forbidden[] missing/empty (must prevent overclaims)")


def check_profile(profile: str, summary: RiskSummary) -> tuple[bool, str]:
    if summary.proof_level not in ALLOWED_PROOF_LEVEL:
        return False, f"invalid proof_level={summary.proof_level}"

    if profile in {"phase0", "devnet"}:
        if summary.deferred != 0:
            return False, f"{profile}: deferred sections are not allowed (deferred={summary.deferred})"
        return True, f"{profile}: OK (baseline present; proof_level={summary.proof_level}; tier={summary.risk_tier})"

    if profile == "audit":
        if summary.deferred != 0:
            return False, f"audit: deferred sections are not allowed (deferred={summary.deferred})"
        if summary.proof_level == "toy-model":
            return False, "audit: proof_level=toy-model is not acceptable for external audit claims"
        return True, f"audit: OK (proof_level={summary.proof_level}; tier={summary.risk_tier})"

    if profile == "freeze":
        if summary.deferred != 0 or summary.stated != 0:
            return False, f"freeze: stated/deferred must be 0 (stated={summary.stated}, deferred={summary.deferred})"
        if summary.proof_level not in {"byte-model", "refinement"}:
            return False, f"freeze: proof_level must be byte-model/refinement (got {summary.proof_level})"
        if summary.claim_level != "refined":
            return False, f"freeze: claim_level must be refined (got {summary.claim_level})"
        return True, f"freeze: OK (proof_level={summary.proof_level}; tier={summary.risk_tier})"

    return False, f"unknown profile: {profile}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail/pass gate for formal-proof readiness profiles.")
    parser.add_argument(
        "--profile",
        choices=["phase0", "devnet", "audit", "freeze"],
        default="phase0",
        help="Readiness profile (default: phase0).",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON summary + pass/fail")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    try:
        doc = load_proof_coverage(repo_root)
        _require_claim_boundaries(doc)
        summary = summarize(doc)
    except Exception as e:
        return fail(str(e))

    ok, msg = check_profile(args.profile, summary)

    if args.json:
        print(
            json.dumps(
                {
                    "profile": args.profile,
                    "ok": ok,
                    "message": msg,
                    "proof_level": summary.proof_level,
                    "claim_level": summary.claim_level,
                    "risk_tier": summary.risk_tier,
                    "risk_score": summary.risk_score,
                    "total_sections": summary.total_sections,
                    "proved": summary.proved,
                    "stated": summary.stated,
                    "deferred": summary.deferred,
                    "stated_keys": summary.stated_keys,
                    "deferred_keys": summary.deferred_keys,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"FORMAL_RISK_GATE profile={args.profile}: {'PASS' if ok else 'FAIL'}")
        print(msg)

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

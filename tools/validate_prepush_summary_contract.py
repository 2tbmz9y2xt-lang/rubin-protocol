#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED_KEYS = ("CHECK_TYPE", "ACTIVE_LENSES", "LENSES_COVERED", "NO_FINDINGS", "RATIONALE")
ALLOWED_CHECK_TYPES = {"consensus_critical", "formal_lean", "code_noncritical", "diff_only"}


def parse_csv(raw: str) -> list[str]:
    if raw.strip().lower() == "none":
        return []
    values: list[str] = []
    for item in raw.split(","):
        value = item.strip()
        if value and value not in values:
            values.append(value)
    return values


def parse_summary(summary: str) -> dict[str, str]:
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("summary must be a non-empty string")
    if "\n" in summary or "\r" in summary:
        raise ValueError("summary must be single-line")

    fields: dict[str, str] = {}
    for token in summary.split("|"):
        key, sep, value = token.partition("=")
        if not sep:
            raise ValueError(f"summary token missing '=': {token!r}")
        norm_key = key.strip()
        if not norm_key:
            raise ValueError("summary key must be non-empty")
        if norm_key in fields:
            raise ValueError(f"duplicate summary key: {norm_key}")
        fields[norm_key] = value.strip()

    missing = [key for key in REQUIRED_KEYS if key not in fields]
    if missing:
        raise ValueError(f"summary missing required keys: {', '.join(missing)}")

    return fields


def parse_lenses_covered(raw: str) -> dict[str, str]:
    raw = raw.strip()
    if not raw:
        return {}
    covered: dict[str, str] = {}
    for item in raw.split(";"):
        pair = item.strip()
        if not pair:
            continue
        lens, sep, status = pair.partition(":")
        if not sep:
            raise ValueError(f"LENSES_COVERED item missing ':': {pair!r}")
        lens_name = lens.strip()
        lens_status = status.strip().lower()
        if not lens_name:
            raise ValueError("LENSES_COVERED lens name must be non-empty")
        if not re.fullmatch(r"[a-z0-9._-]+", lens_name):
            raise ValueError(f"LENSES_COVERED lens name has unsupported chars: {lens_name!r}")
        covered[lens_name] = lens_status
    return covered


def validate_contract(
    *,
    summary: str,
    findings: list[object],
    expected_check_type: str,
    expected_active_lenses: list[str],
) -> list[str]:
    errors: list[str] = []

    if expected_check_type not in ALLOWED_CHECK_TYPES:
        errors.append(f"unsupported expected_check_type: {expected_check_type!r}")
        return errors

    try:
        fields = parse_summary(summary)
    except ValueError as exc:
        errors.append(str(exc))
        return errors

    actual_check_type = fields["CHECK_TYPE"]
    if actual_check_type != expected_check_type:
        errors.append(f"CHECK_TYPE mismatch: expected={expected_check_type} actual={actual_check_type}")

    summary_active_lenses = parse_csv(fields["ACTIVE_LENSES"])
    if set(summary_active_lenses) != set(expected_active_lenses):
        errors.append(
            "ACTIVE_LENSES mismatch: expected="
            f"{','.join(expected_active_lenses)} actual={','.join(summary_active_lenses)}"
        )

    try:
        covered = parse_lenses_covered(fields["LENSES_COVERED"])
    except ValueError as exc:
        errors.append(str(exc))
        covered = {}

    for lens in expected_active_lenses:
        status = covered.get(lens)
        if status != "ok":
            errors.append(f"LENSES_COVERED missing ok status for lens={lens!r}")

    no_findings_raw = fields["NO_FINDINGS"].lower()
    if no_findings_raw not in {"true", "false"}:
        errors.append(f"NO_FINDINGS must be true|false, got {fields['NO_FINDINGS']!r}")
        no_findings = False
    else:
        no_findings = no_findings_raw == "true"

    findings_empty = len(findings) == 0
    if no_findings != findings_empty:
        errors.append(f"NO_FINDINGS mismatch with findings payload: no_findings={no_findings} findings_empty={findings_empty}")

    rationale = fields["RATIONALE"]
    if not rationale:
        errors.append("RATIONALE must be non-empty")
    if no_findings:
        rationale_lc = rationale.lower()
        for lens in expected_active_lenses:
            if lens.lower() not in rationale_lc:
                errors.append(f"RATIONALE must mention active lens when NO_FINDINGS=true: {lens!r}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate fail-closed summary contract for pre-push model output.")
    parser.add_argument("--result-json", required=True)
    parser.add_argument("--expected-check-type", required=True)
    parser.add_argument("--active-lenses", default="")
    args = parser.parse_args()

    result = json.loads(Path(args.result_json).read_text(encoding="utf-8"))
    summary = result.get("summary", "")
    findings = result.get("findings", [])
    if not isinstance(findings, list):
        print("summary-contract: findings must be a list", file=sys.stderr)
        return 2

    expected_active_lenses = parse_csv(args.active_lenses)
    errors = validate_contract(
        summary=summary,
        findings=findings,
        expected_check_type=args.expected_check_type.strip(),
        expected_active_lenses=expected_active_lenses,
    )
    if errors:
        print("summary-contract: FAIL", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 2

    print("summary-contract: PASS", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


REQUIRED_SECTIONS = [
    "## 1) Intake and Disclosure Channels",
    "## 2) SLA Targets",
    "## 3) Patch Triage Procedure",
    "## 4) Release Evidence Requirements",
    "## 5) Controller Escalation Rule",
    "## 6) Closure Criteria",
]

REQUIRED_PHRASES = [
    "GitHub Security Advisory",
    "RUBIN_OPENSSL_FIPS_MODE=only",
    "Queue task updated to `DONE` with evidence reference",
    "НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА",
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate OpenSSL CVE response runbook coverage."
    )
    parser.add_argument(
        "--code-root",
        default=".",
        help="Path to repository root.",
    )
    args = parser.parse_args()

    root = Path(args.code_root).resolve()
    runbook = root / "scripts" / "crypto" / "openssl" / "CVE_RESPONSE_RUNBOOK.md"
    readme = root / "scripts" / "crypto" / "openssl" / "README.md"

    errors: list[str] = []

    if not runbook.exists():
        errors.append(f"missing required file: {runbook}")
    if not readme.exists():
        errors.append(f"missing required file: {readme}")

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    runbook_text = runbook.read_text(encoding="utf-8", errors="strict")
    readme_text = readme.read_text(encoding="utf-8", errors="strict")

    for section in REQUIRED_SECTIONS:
        if section not in runbook_text:
            errors.append(f"missing runbook section: {section!r}")

    for phrase in REQUIRED_PHRASES:
        if phrase not in runbook_text:
            errors.append(f"missing runbook phrase: {phrase!r}")

    if "CVE_RESPONSE_RUNBOOK.md" not in readme_text:
        errors.append("README must reference scripts/crypto/openssl/CVE_RESPONSE_RUNBOOK.md")

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    print("OK: OpenSSL CVE response runbook policy checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

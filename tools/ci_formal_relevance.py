#!/usr/bin/env python3
"""Decide whether a pull request must run formal CI jobs."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Callable, NamedTuple

PROTECTED_PREFIXES = (
    "rubin-formal/",
    "conformance/",
    "clients/go/",
    "clients/rust/crates/rubin-consensus/src/",
    "tools/formal/",
)
PROTECTED_EXACT = {
    ".github/workflows/ci.yml",
    "README.md",
    "SPEC_LOCATION.md",
    "scripts/crypto/openssl/build-openssl-bundle.sh",
    "tools/check_formal_claims_lint.py",
    "tools/check_formal_coverage.py",
    "tools/check_formal_refinement_bridge.py",
    "tools/check_formal_risk_gate.py",
    "tools/check_lean_conformance_staleness.py",
    "tools/check_map_iteration_determinism.py",
    "tools/ci_formal_relevance.py",
    "tools/formal_risk_score.py",
    "tools/tests/test_ci_formal_relevance.py",
}
SKIPPABLE_PREFIXES = ("tools/", "scripts/", "clients/rust/")
SKIPPABLE_EXACT = {
    f".github/workflows/{name}"
    for name in (
        "auto-approve.yml",
        "codacy-coverage.yml",
        "codeql.yml",
        "combined-load-nightly.yml",
        "dependency-review.yml",
        "dependency-submission.yml",
        "fips-only-nightly.yml",
        "fuzz-nightly.yml",
        "kani.yml",
        "parity-gate.yml",
        "runtime-perf-guardrails.yml",
        "sbom.yml",
        "security-supply-chain-nightly.yml",
        "spec-checks.yml",
        "workflow-hygiene.yml",
    )
} | {
    ".codacy.yml",
    ".coderabbit.yaml",
    ".jscpd.json",
    ".node-version",
    ".nvmrc",
    "CODACY_CCN_SUMMARY.md",
    "package-lock.json",
    "package.json",
    "tree-api.json",
}

class Decision(NamedTuple):
    run_formal: bool
    reason: str
    path_count: int = 0

def parse_name_status(data: bytes) -> tuple[list[str], str | None]:
    if not data or not data.endswith(b"\0"):
        return [], "empty or malformed diff"
    fields = data[:-1].split(b"\0")
    paths: list[str] = []
    index = 0
    while index < len(fields):
        try:
            status = fields[index].decode("ascii")
        except UnicodeDecodeError:
            return [], "malformed diff status"
        index += 1
        path_fields = 2 if status.startswith(("R", "C")) else 1
        if status[:1] not in {"A", "C", "D", "M", "R", "T"}:
            return [], f"unknown diff status: {status or '<empty>'}"
        if status[:1] not in {"R", "C"} and len(status) != 1:
            return [], f"malformed diff status: {status}"
        if status[:1] in {"R", "C"} and (
            len(status) != 4 or not status[1:].isdigit() or int(status[1:]) > 100
        ):
            return [], f"malformed diff status: {status}"
        if index + path_fields > len(fields):
            return [], "malformed diff record"
        try:
            record_paths = [field.decode("utf-8") for field in fields[index:index + path_fields]]
        except UnicodeDecodeError:
            return [], "malformed diff path"
        if any(not path or path.startswith("/") or "\0" in path for path in record_paths):
            return [], "malformed diff path"
        paths.extend(record_paths)
        index += path_fields
    return paths, None

def classify_paths(paths: list[str]) -> Decision:
    if not paths:
        return Decision(True, "empty or malformed diff")
    for path in paths:
        if path in PROTECTED_EXACT or path.startswith(PROTECTED_PREFIXES):
            return Decision(True, f"protected path: {path}", len(paths))
        if path not in SKIPPABLE_EXACT and not path.startswith(SKIPPABLE_PREFIXES):
            return Decision(True, f"path not in allowlist: {path}", len(paths))
    return Decision(False, "all paths are in allowlist", len(paths))

def decide(
    event_name: str,
    base_ref: str,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> Decision:
    if event_name != "pull_request":
        return Decision(True, f"event {event_name or '<missing>'} is not pull_request")
    if not base_ref:
        return Decision(True, "missing pull request base")
    base = f"origin/{base_ref}"
    verify = run(
        ["git", "rev-parse", "--verify", f"{base}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if verify.returncode:
        return Decision(True, f"missing pull request base: {base}")
    diff = run(
        ["git", "diff", "--name-status", "-z", "--find-renames", f"{base}..HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if diff.returncode:
        return Decision(True, f"git diff failed for {base}..HEAD")
    paths, error = parse_name_status(diff.stdout)
    return Decision(True, error) if error else classify_paths(paths)

def main() -> int:
    decision = decide(
        os.environ.get("GITHUB_EVENT_NAME", ""),
        os.environ.get("GITHUB_BASE_REF", ""),
    )
    if decision.run_formal:
        print(f"RUN: {decision.reason}")
    else:
        print(
            f"SKIP: formal-irrelevant diff "
            f"({decision.path_count} paths, all in allowlist)"
        )
    output = Path(os.environ["GITHUB_OUTPUT"])
    with output.open("a", encoding="utf-8") as stream:
        stream.write(f"run_formal={'true' if decision.run_formal else 'false'}\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

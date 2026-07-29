#!/usr/bin/env python3
"""Decide whether a pull request must run formal CI jobs."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
from typing import Callable, NamedTuple

JOBS = ("formal", "formal_refinement")
COMMON_EXACT = {
    ".github/workflows/ci.yml",
    "rubin-formal/RubinFormal.lean",
    "rubin-formal/lake-manifest.json",
    "rubin-formal/lakefile.lean",
    "rubin-formal/lean-toolchain",
    "tools/ci_formal_relevance.py",
}
FORMAL_EXACT = COMMON_EXACT | {
    "README.md", "SPEC_LOCATION.md", "conformance/MATRIX.md",
    "rubin-formal/PROOF_COVERAGE.md", "rubin-formal/README.md",
    "rubin-formal/REGISTRY_COMPLETENESS_POLICY.md",
    "rubin-formal/proof_coverage.json", "rubin-formal/refinement_bridge.json",
    "rubin-formal/scripts/check.sh",
    "rubin-formal/tools/LOCAL_CODEX_EXEC_REVIEW.md",
    "rubin-formal/tools/check_formal_registry_truth.py",
    "tools/check_formal_claims_lint.py",
    "tools/check_formal_coverage.py",
    "tools/check_formal_refinement_bridge.py",
    "tools/check_formal_risk_gate.py",
    "tools/check_map_iteration_determinism.py",
    "tools/formal_risk_score.py",
}
REFINEMENT_EXACT = COMMON_EXACT | {
    "clients/go/go.mod",
    "clients/go/consensus/live_binding_policy_v1_embedded.json",
    "scripts/crypto/openssl/build-openssl-bundle.sh",
    "scripts/crypto/openssl/source-checksums.sha256",
    "tools/check_lean_conformance_staleness.py",
    "tools/formal/gen_lean_conformance_vectors.py",
    "tools/formal/gen_lean_refinement_from_traces.py",
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

def is_common(path: str) -> bool:
    return path in COMMON_EXACT or (
        path.startswith("rubin-formal/RubinFormal/") and path.endswith(".lean")
    ) or (
        path.startswith("conformance/fixtures/CV-")
        and path.endswith(".json")
        and path.count("/") == 2
    )

def is_formal_input(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return is_common(path) or path in FORMAL_EXACT or (
        path.startswith("rubin-formal/tests/") and name.startswith("test_")
        and name.endswith(".py")
    ) or (
        path.startswith("clients/go/consensus/") and path.count("/") == 3
        and path.endswith(".go") and not path.endswith("_test.go")
    ) or (
        path.startswith("clients/rust/crates/rubin-consensus/src/")
        and path.endswith(".rs") and "/tests/" not in path
        and not name.endswith("_test.rs")
    )

def is_refinement_input(path: str) -> bool:
    return is_common(path) or path in REFINEMENT_EXACT or (
        path.startswith("clients/go/cmd/formal-trace/")
        and path.count("/") == 4 and path.endswith(".go")
        and not path.endswith("_test.go")
    ) or (
        path.startswith("clients/go/consensus/")
        and path.endswith(".go") and not path.endswith("_test.go")
    )

def classify_paths(paths: list[str], job: str) -> Decision:
    if not paths:
        return Decision(True, "empty or malformed diff")
    predicate = is_formal_input if job == "formal" else is_refinement_input
    for path in paths:
        if predicate(path):
            return Decision(True, f"{job} input: {path}", len(paths))
    return Decision(False, f"no {job} inputs", len(paths))

def decide(
    job: str,
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
        [
            "git", "diff", "--name-status", "-z", "--find-renames",
            "--find-copies", "--find-copies-harder", f"{base}..HEAD",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if diff.returncode:
        return Decision(True, f"git diff failed for {base}..HEAD")
    paths, error = parse_name_status(diff.stdout)
    return Decision(True, error) if error else classify_paths(paths, job)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", choices=JOBS, required=True)
    args = parser.parse_args()
    decision = decide(
        args.job,
        os.environ.get("GITHUB_EVENT_NAME", ""),
        os.environ.get("GITHUB_BASE_REF", ""),
    )
    if decision.run_formal:
        print(f"RUN: {decision.reason}")
    else:
        print(
            f"SKIP: {args.job}-irrelevant diff "
            f"({decision.path_count} paths, no profile inputs)"
        )
    output = Path(os.environ["GITHUB_OUTPUT"])
    with output.open("a", encoding="utf-8") as stream:
        stream.write(f"run_formal={'true' if decision.run_formal else 'false'}\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

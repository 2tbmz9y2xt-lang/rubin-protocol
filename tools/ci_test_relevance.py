#!/usr/bin/env python3
"""Fail-closed relevance gate for the expensive test CI job."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
from typing import Callable, NamedTuple


EXACT_INPUTS = {
    ".gitattributes",
    ".github/workflows/ci.yml",
    ".node-version",
    "go.work", "go.work.sum",
    "evidence/runtime-perf/RUST_RUNTIME_PERF_GUARDRAILS.md",
}
PREFIX_INPUTS = (".cargo/", ".github/actions/", "clients/", "conformance/", "scripts/", "tools/")


class Decision(NamedTuple):
    run_test: bool
    reason: str
    path_count: int = 0


def parse_name_status(data: bytes) -> tuple[list[str], str | None]:
    if not isinstance(data, bytes) or not data or not data.endswith(b"\0"):
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
        kind = status[:1]
        if kind in {"A", "D", "M", "T"} and len(status) == 1:
            path_count = 1
        elif kind in {"R", "C"} and len(status) == 4 and status[1:].isdigit() and int(status[1:]) <= 100:
            path_count = 2
        else:
            return [], f"malformed or unknown diff status: {status or '<empty>'}"
        if index + path_count > len(fields):
            return [], "malformed diff record"
        try:
            record_paths = [item.decode("utf-8") for item in fields[index:index + path_count]]
        except UnicodeDecodeError:
            return [], "malformed diff path"
        if any(
            not path or path.startswith(("/", "\\"))
            or (len(path) > 2 and path[1] == ":" and path[2] in "/\\")
            or any(part in {"", ".", ".."} for part in path.split("/"))
            for path in record_paths
        ):
            return [], "invalid diff path"
        paths.extend(record_paths)
        index += path_count
    return paths, None


def decide(
    event_name: str, base_sha: str,
    run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
) -> Decision:
    if event_name != "pull_request":
        return Decision(True, f"event {event_name or '<missing>'} is not pull_request")
    if not (isinstance(base_sha, str) and len(base_sha) == 40 and all(char in "0123456789abcdefABCDEF" for char in base_sha)):
        return Decision(True, "missing or invalid pull request base SHA")
    verify = run(["git", "rev-parse", "--verify", f"{base_sha}^{{commit}}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if verify.returncode:
        return Decision(True, f"missing pull request base SHA: {base_sha}")
    diff = run(["git", "diff", "--name-status", "-z", "--find-renames", "--find-copies", "--find-copies-harder", f"{base_sha}..HEAD"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if diff.returncode:
        return Decision(True, f"git diff failed for {base_sha}..HEAD")
    paths, error = parse_name_status(diff.stdout)
    if error:
        return Decision(True, error)
    for path in paths:
        if path in EXACT_INPUTS or path.startswith(PREFIX_INPUTS):
            return Decision(True, f"test input: {path}", len(paths))
    return Decision(False, "no test inputs", len(paths))


def main() -> int:
    decision = decide(os.environ.get("GITHUB_EVENT_NAME", ""), os.environ.get("RUBIN_TEST_RELEVANCE_BASE_SHA", ""))
    print(("RUN" if decision.run_test else "SKIP") + f": {decision.reason}")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"run_test={'true' if decision.run_test else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

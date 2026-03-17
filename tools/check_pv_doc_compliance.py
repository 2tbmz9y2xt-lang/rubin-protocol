#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path


GIT_REV_RE = re.compile(r"^[A-Fa-f0-9]{40,64}$")


PV_TOUCH_PREFIXES = (
    "clients/go/consensus/",
    "clients/go/node/",
    "clients/rust/crates/rubin-consensus/",
    "clients/rust/crates/rubin-node/",
    "conformance/fixtures/",
    "conformance/runner/",
)

PV_TOUCH_NEEDLES = (
    "parallel",
    "connect_block_parallel",
    "tx_dep_graph",
    "utxo_snapshot",
    "pv-",
    "cv-pv",
)

CORE_EXT_TOUCH_NEEDLES = (
    "core_ext",
    "cv-ext",
    "CORE_EXT",
    "verify_sig_ext",
)


REQ_MARKERS = [
    # Structural anchors.
    r"(?im)^\s*Refs:\s*Q-[A-Z0-9-]+\s*$",
    r"(?im)^\s*##\s*Summary\s*$",
    r"(?im)^\s*##\s*Scope\s*$",
]


def run_git(args: list[str]) -> str:
    proc = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git command failed")
    return proc.stdout


def detect_range_from_github_event() -> tuple[str, str, bool] | None:
    event_path = os.getenv("GITHUB_EVENT_PATH")
    event_name = os.getenv("GITHUB_EVENT_NAME", "")
    if not event_path or not Path(event_path).exists():
        return None
    payload = json.loads(Path(event_path).read_text(encoding="utf-8"))

    if event_name in {"pull_request", "pull_request_target"}:
        base = payload["pull_request"]["base"]["sha"]
        head = payload["pull_request"]["head"]["sha"]
        if not (GIT_REV_RE.fullmatch(base) and GIT_REV_RE.fullmatch(head)):
            return None
        return base, head, True

    if event_name == "push":
        base = payload.get("before", "")
        head = payload.get("after", "")
        if not base or set(base) == {"0"}:
            return None
        if not (GIT_REV_RE.fullmatch(base) and GIT_REV_RE.fullmatch(head)):
            return None
        return base, head, False

    return None


def changed_files(base: str, head: str, pr_mode: bool) -> list[str]:
    range_expr = f"{base}...{head}" if pr_mode else f"{base}..{head}"
    # Include additions/modifications/renames AND deletions; removing a PV/CORE_EXT
    # sensitive file must still go through the same documentation gate.
    out = run_git(["diff", "--name-only", "--diff-filter=ACMRD", range_expr])
    files = [line.strip() for line in out.splitlines() if line.strip()]
    return sorted(set(files))


def touches_pv_or_core_ext(paths: list[str]) -> bool:
    for p in paths:
        if not p.startswith(PV_TOUCH_PREFIXES):
            continue
        low = p.lower()
        if any(n in low for n in PV_TOUCH_NEEDLES):
            return True
        if any(n.lower() in low for n in CORE_EXT_TOUCH_NEEDLES):
            return True
    return False


def pr_number_from_event() -> int | None:
    event_path = os.getenv("GITHUB_EVENT_PATH")
    event_name = os.getenv("GITHUB_EVENT_NAME", "")
    if not event_path or not Path(event_path).exists():
        return None
    payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
    if event_name not in {"pull_request", "pull_request_target"}:
        return None
    return int(payload["pull_request"]["number"])


def fetch_pr_body(repo: str, pr_number: int) -> str:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required to fetch PR body")
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "rubin-policy-pv-doc-compliance",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    body = data.get("body") or ""
    return str(body)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Fail-closed PV/CORE_EXT doc compliance gate for PRs touching sensitive paths."
    )
    ap.add_argument("--repo", default=os.getenv("GITHUB_REPOSITORY", ""), help="owner/repo")
    args = ap.parse_args()

    detected = detect_range_from_github_event()
    if detected is None:
        print("PV_DOC_COMPLIANCE: SKIP (unable to detect diff range)")
        return 0
    base, head, pr_mode = detected
    files = changed_files(base, head, pr_mode)

    if not touches_pv_or_core_ext(files):
        print("PV_DOC_COMPLIANCE: SKIP (no PV/CORE_EXT sensitive paths touched)")
        return 0

    pr_number = pr_number_from_event()
    if pr_number is None:
        # This script is executed in both PR and push workflows.
        # Enforce strictly for PRs (where the PR body exists). For pushes (including main),
        # fail-closed enforcement via PR body isn't possible, so we skip to avoid mainline CI
        # going red post-merge for already-reviewed changes.
        print("PV_DOC_COMPLIANCE: SKIP (non-PR event; PR body not available)")
        return 0

    if not args.repo:
        print("PV_DOC_COMPLIANCE: FAIL (missing GITHUB_REPOSITORY)")
        return 1

    body = fetch_pr_body(args.repo, pr_number)
    missing: list[str] = []
    for pat in REQ_MARKERS:
        if not re.search(pat, body):
            missing.append(pat)

    boundary_errors: list[str] = []
    # Require explicit affirmative boundary lines to avoid YES/NO placeholders.
    consensus_line_re = re.compile(
        r"(?im)^\s*Consensus rules unchanged:\s*(YES|NO)\s*$"
    )
    sh_line_re = re.compile(
        r"(?im)^\s*SECTION_HASHES\.json unchanged:\s*(YES|NO)\s*$"
    )

    m_cons = consensus_line_re.search(body)
    m_sh = sh_line_re.search(body)

    if not m_cons:
        boundary_errors.append("missing line: 'Consensus rules unchanged: YES'")
    elif m_cons.group(1) != "YES":
        boundary_errors.append(
            "Consensus boundary must be explicitly affirmed: 'Consensus rules unchanged: YES'"
        )

    if not m_sh:
        boundary_errors.append("missing line: 'SECTION_HASHES.json unchanged: YES'")
    elif m_sh.group(1) != "YES":
        boundary_errors.append(
            "SECTION_HASHES.json boundary must be explicitly affirmed: 'SECTION_HASHES.json unchanged: YES'"
        )

    if missing or boundary_errors:
        print("PV_DOC_COMPLIANCE: FAIL")
        print("PR touches PV/CORE_EXT sensitive paths but is missing required PR-body markers.")
        if missing:
            print("Missing structural markers (regex):")
            for m in missing:
                print(f"- {m}")
        if boundary_errors:
            print("Boundary issues:")
            for msg in boundary_errors:
                print(f"- {msg}")
        print()
        print(
            "Fix: use the PV PR template and include Refs: Q-..., required sections,"
            " and boundary lines with explicit 'YES' values."
        )
        return 1

    print("PV_DOC_COMPLIANCE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


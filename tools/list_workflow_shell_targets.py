#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

WORKFLOW_SCRIPT_RE = re.compile(r"scripts/[A-Za-z0-9_./-]+\.sh")


def iter_workflows(workflow_dir: Path) -> list[Path]:
    return sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))


def collect_targets(repo_root: Path) -> list[str]:
    workflow_dir = repo_root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        raise FileNotFoundError(f"workflow directory is missing: {workflow_dir}")

    targets: set[str] = set()
    for workflow in iter_workflows(workflow_dir):
        text = workflow.read_text(encoding="utf-8")
        for match in WORKFLOW_SCRIPT_RE.findall(text):
            target = repo_root / match
            if not target.is_file():
                raise FileNotFoundError(
                    f"workflow references missing shell target {match} in {workflow.relative_to(repo_root)}"
                )
            targets.add(match)

    return sorted(targets)


def main(argv: list[str]) -> int:
    repo_root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[1]
    for target in collect_targets(repo_root):
        print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

CONTRACT_PATH = Path(__file__).resolve().with_name("prepush_review_contract.json")
MAX_GIT_OUTPUT_BYTES = 10 * 1024 * 1024
REVIEWABLE_PATHS = (
    "*.go",
    "*.rs",
    "*.c",
    "*.cc",
    "*.cpp",
    "*.h",
    "*.hpp",
    "*.lean",
    "*.proto",
    "*.sh",
    "*.py",
    "*.yml",
    "*.yaml",
    "*.json",
    "*.toml",
    "*.md",
)

BASE_PROMPT = """You are running RUBIN local self-audit before commit in FAIL-CLOSED mode.

INPUT BOUNDARY:
- Review ONLY the current staged diff and the changed-file list included below.
- Do not rationalize away known bot-review patterns.
- If a known pattern is touched by the staged diff, treat it as unresolved until you can point to the exact staged lines and the exact regression test that covers it.

SELF-AUDIT CONTRACT:
- Before writing a fresh self-audit receipt, replay every required pattern family below.
- For each family, decide one of:
  1) covered by exact staged guard + exact test,
  2) not applicable to this diff,
  3) still unresolved and must block commit.
- If any family is unresolved, do not refresh the receipt.

REVIEWER MINDSET:
- Think like the hostile PR bots that already flagged this repo: DeepSeek, Copilot, Claude, Codex.
- Prefer concrete adversarial cases: malformed config/genesis input, resource exhaustion, Go/Rust divergence, exact parameter drift, redundant validation ordering, and missing regression tests.
"""


def normalize_repo_root(repo_root: Path) -> Path:
    normalized = repo_root.resolve()
    if not normalized.is_absolute():
        raise ValueError("repo_root must be absolute")
    if not normalized.exists() or not normalized.is_dir():
        raise ValueError(f"repo_root must be an existing directory: {normalized}")
    if normalized.name.startswith("-"):
        raise ValueError(f"repo_root must not start with '-': {normalized}")
    git_marker = normalized / ".git"
    if not git_marker.exists():
        raise ValueError(f"repo_root is not a git worktree: {normalized}")
    return normalized


def _read_limited(handle: tempfile.TemporaryFile[bytes], *, label: str) -> str:
    handle.flush()
    size = handle.tell()
    if size > MAX_GIT_OUTPUT_BYTES:
        raise ValueError(f"{label} exceeds {MAX_GIT_OUTPUT_BYTES} bytes")
    handle.seek(0)
    return handle.read().decode("utf-8", errors="replace")


def run_git(repo_root: Path, *args: str) -> str:
    repo_root = normalize_repo_root(repo_root)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            stdout=stdout,
            stderr=stderr,
            check=False,
        )
        stdout_text = _read_limited(stdout, label=f"git {' '.join(args)} stdout")
        stderr_text = _read_limited(stderr, label=f"git {' '.join(args)} stderr")
    if proc.returncode != 0:
        msg = stderr_text.strip() or stdout_text.strip() or "unknown git error"
        raise RuntimeError(f"git {' '.join(args)} :: {msg}")
    return stdout_text


def load_self_audit_contract(path: Path = CONTRACT_PATH) -> dict[str, object]:
    if not path.exists():
        raise FileNotFoundError(f"self-audit contract missing: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"self-audit contract at {path} must decode to an object")
    section = data.get("self_audit")
    if not isinstance(section, dict):
        raise ValueError(f"self-audit contract at {path} must define self_audit object")
    version = str(section.get("prompt_pack_version") or "").strip()
    families = section.get("required_pattern_families")
    if not version:
        raise ValueError(f"self-audit contract at {path} must define prompt_pack_version")
    if not isinstance(families, list) or not families:
        raise ValueError(f"self-audit contract at {path} must define non-empty required_pattern_families")
    normalized: list[dict[str, object]] = []
    for raw in families:
        if not isinstance(raw, dict):
            raise ValueError(f"self-audit contract at {path} has non-object pattern family")
        family_id = str(raw.get("id") or "").strip()
        title = str(raw.get("title") or "").strip()
        checks_raw = raw.get("checks")
        if not family_id or not title or not isinstance(checks_raw, list) or not checks_raw:
            raise ValueError(f"self-audit contract at {path} has malformed pattern family")
        checks = [str(item).strip() for item in checks_raw if str(item).strip()]
        if not checks:
            raise ValueError(f"self-audit contract at {path} pattern family {family_id!r} has empty checks")
        normalized.append({"id": family_id, "title": title, "checks": checks})
    return {"prompt_pack_version": version, "required_pattern_families": normalized}


def staged_changed_files(repo_root: Path) -> list[str]:
    raw = run_git(repo_root, "diff", "--cached", "--name-only", "--find-renames", "--", *REVIEWABLE_PATHS)
    return [line.strip() for line in raw.splitlines() if line.strip()]


def staged_bundle(repo_root: Path) -> str:
    paths = staged_changed_files(repo_root)
    if not paths:
        raise ValueError("no staged reviewable diff")
    stat = run_git(repo_root, "diff", "--cached", "--stat=160", "--find-renames", "--", *paths)
    patch = run_git(repo_root, "diff", "--cached", "--no-color", "--unified=3", "--find-renames", "--", *paths)
    head = run_git(repo_root, "rev-parse", "--short", "HEAD").strip()
    lines = [
        f"HEAD={head}",
        "",
        "--- STAGED CHANGED FILES ---",
        *paths,
        "",
        "--- STAGED DIFF STAT ---",
        stat.rstrip(),
        "",
        "--- STAGED PATCH ---",
        patch.rstrip(),
        "",
    ]
    return "\n".join(lines)


def compose_prompt(*, contract: dict[str, object], bundle_text: str) -> str:
    version = str(contract["prompt_pack_version"])
    families = contract["required_pattern_families"]
    lines = [
        f"Prompt Pack: {version}",
        "",
        BASE_PROMPT.strip(),
        "",
        "Required pattern replay:",
    ]
    for family in families:
        lines.append(f"- {family['title']} [{family['id']}]")
        for check in family["checks"]:
            lines.append(f"  - {check}")
    lines.extend(
        [
            "",
            "Mandatory self-audit output before receipt refresh:",
            "- exact changed lines reviewed for each applicable pattern family",
            "- exact tests covering each new fail-closed guard",
            "- explicit note if a family is not applicable",
            "",
            "Staged diff bundle follows.",
            "",
            bundle_text.rstrip(),
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build RUBIN local self-audit prompt pack from staged diff.")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    repo_root = normalize_repo_root(Path(args.repo_root))
    output_path = Path(args.output).resolve()
    contract = load_self_audit_contract()
    prompt = compose_prompt(contract=contract, bundle_text=staged_bundle(repo_root))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(prompt, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

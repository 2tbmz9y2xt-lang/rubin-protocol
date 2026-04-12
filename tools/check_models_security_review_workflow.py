#!/usr/bin/env python3
"""Fail-closed contract checks for security review workflows.

Checks the shared reusable workflow for regressions: stale parity paths,
unsafe file reads, O(n) membership in hot loops, and payload budget mistakes.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SHARED_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security-review-shared.yml"
DEEPSEEK_CALLER = REPO_ROOT / ".github" / "workflows" / "models-security-review.yml"
QWEN_CALLER = REPO_ROOT / ".github" / "workflows" / "qwen-security-review.yml"
SECURITY_REVIEW_RUNNER = REPO_ROOT / ".github" / "workflows" / "security-review-runner.js"

PAIR_RE = re.compile(r"\['([^']+)',\s*'([^']+)'\]")

REQUIRED_WORKFLOW_SUBSTRINGS = [
    "require('./.github/workflows/security-review-runner.js')",
    "REVIEW_USES_GITHUB_MODELS:",
    "REVIEW_API_URL:",
    "REVIEW_MODEL_ID:",
    "REVIEW_MODEL_DISPLAY_NAME:",
    "REVIEW_ANTI_HALLUCINATION_RULES:",
    "REVIEW_MAX_TOKENS:",
    "REVIEW_NEEDS_JSON_MODE:",
    "REVIEW_BASE_SHA:",
    "REVIEW_HEAD_SHA:",
    "getSevIdx",
    "normSev",
]

REQUIRED_RUNNER_SUBSTRINGS = [
    "readChangedFile(repoRoot, repoRootReal, modRel, PER_FILE_CAP)",
    "separatorOverhead",
    "introOverhead",
    "changedFilesSet",
    "slice(0,",  # payload cap
    "jsonrepair(",
    "fromJSONEnv('REVIEW_MODEL_ID'",
    "--name-only', '-z'",
    "Missing required security-review environment contract:",
]

BANNED_RUNNER_SUBSTRINGS = [
    "fs.readFileSync(modFile",
    "changedFiles.includes(",
    "execSync(",
]

BANNED_WORKFLOW_SUBSTRINGS = [
    "sevOrder.indexOf(a.severity)",
]


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    print(f"WARN: {msg}", file=sys.stderr)


def load_yaml_module():
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        return None
    return yaml


def main() -> int:
    errors: list[str] = []

    # Check shared workflow exists
    if not SHARED_WORKFLOW.is_file():
        _fail(f"missing shared workflow: {SHARED_WORKFLOW}")
        return 1
    if not SECURITY_REVIEW_RUNNER.is_file():
        _fail(f"missing extracted runner script: {SECURITY_REVIEW_RUNNER}")
        return 1

    # Check callers exist AND actually invoke the shared reusable workflow
    # with the inputs the shared workflow requires. Existence alone is not
    # enough — a caller could drift away from `uses:` or drop a required
    # input and the gate would still pass.
    shared_workflow_ref = "uses: ./.github/workflows/security-review-shared.yml"
    required_caller_inputs = (
        "model_id:",
        "api_base_url:",
        "model_display_name:",
        "artifact_prefix:",
    )
    for caller in [DEEPSEEK_CALLER, QWEN_CALLER]:
        if not caller.is_file():
            errors.append(f"missing caller workflow: {caller}")
            continue
        caller_text = caller.read_text(encoding="utf-8")
        if shared_workflow_ref not in caller_text:
            errors.append(
                f"caller {caller.name} no longer invokes security-review-shared.yml"
            )
        for required_input in required_caller_inputs:
            if required_input not in caller_text:
                errors.append(
                    f"caller {caller.name} missing required input: {required_input}"
                )

    # Qwen authenticates via OpenRouter and the shared workflow gates the
    # review step on a non-empty API_KEY env var. The Qwen caller must
    # wire its repository secret into the reusable workflow's API_KEY
    # input, otherwise the check-key step will silently skip every Qwen
    # review on every PR. Verify both halves of the mapping.
    if QWEN_CALLER.is_file():
        qwen_text = QWEN_CALLER.read_text(encoding="utf-8")
        if "API_KEY:" not in qwen_text:
            errors.append(
                f"caller {QWEN_CALLER.name} must declare an `API_KEY:` entry under "
                f"`secrets:` to populate the reusable workflow's API_KEY input"
            )
        if "OPENROUTER_API_KEY_QWEN" not in qwen_text:
            errors.append(
                f"caller {QWEN_CALLER.name} must wire ${{{{ secrets.OPENROUTER_API_KEY_QWEN }}}} "
                f"into the shared workflow's API_KEY input"
            )

    text = SHARED_WORKFLOW.read_text(encoding="utf-8")
    runner_text = SECURITY_REVIEW_RUNNER.read_text(encoding="utf-8")

    yaml = load_yaml_module()
    if yaml is not None:
        try:
            yaml.safe_load(text)
        except yaml.YAMLError as exc:
            errors.append(f"invalid YAML in shared workflow: {exc}")

    for s in REQUIRED_WORKFLOW_SUBSTRINGS:
        if s not in text:
            errors.append(f"missing required invariant substring {s!r}")
    for s in REQUIRED_RUNNER_SUBSTRINGS:
        if s not in runner_text:
            errors.append(f"missing required runner invariant substring {s!r}")
    for s in BANNED_RUNNER_SUBSTRINGS:
        if s in runner_text:
            errors.append(f"banned regression substring present: {s!r}")
    for s in BANNED_WORKFLOW_SUBSTRINGS:
        if s in text:
            errors.append(f"banned workflow regression substring present: {s!r}")

    pairs = PAIR_RE.findall(runner_text)
    if len(pairs) < 10:
        errors.append(f"expected parityMap-style pairs, got only {len(pairs)}")

    missing_files: list[str] = []
    for a, b in pairs:
        for p in (a, b):
            fp = REPO_ROOT / p
            if not fp.is_file():
                missing_files.append(p)
    if missing_files:
        preview = ", ".join(missing_files[:25])
        extra = f" (+{len(missing_files) - 25} more)" if len(missing_files) > 25 else ""
        errors.append(f"parityMap references missing files: {preview}{extra}")

    node = shutil.which("node")
    require_node_syntax_check = os.environ.get("REQUIRE_NODE_SYNTAX_CHECK") == "1"
    if node is None:
        msg = "node not found; skipping extracted review runner syntax check"
        if require_node_syntax_check:
            errors.append(msg)
        else:
            _warn(msg)
    else:
        proc = subprocess.run(
            [node, "--check", str(SECURITY_REVIEW_RUNNER)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or "node --check failed"
            errors.append(f"invalid JS in extracted runner: {detail}")

    if errors:
        for e in errors:
            _fail(e)
        return 1

    syntax_check_status = (
        "extracted runner syntax checked" if node is not None
        else "extracted runner syntax check skipped (node missing)"
    )
    print(
        "OK: security-review-shared.yml contract "
        f"({len(pairs)} parity pairs, {syntax_check_status})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

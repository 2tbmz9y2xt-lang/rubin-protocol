#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path

from rubin_agent_contract import (
    find_drop_block_ranges,
    is_comment_line,
    is_production_loc_file,
    is_runtime_sensitive_path,
    is_test_file,
    line_in_ranges,
    load_manifest,
    parse_diff_patches,
    read_worktree_text,
    resolve_diff_range,
)


ENV_KNOB_PATTERNS = (
    re.compile(r"\bRUBIN_TEST_[A-Z0-9_]*\b"),
    re.compile(r"\b[A-Z0-9]+_TEST_[A-Z0-9_]+\b"),
)
FILE_LINE_ANCHOR_RE = re.compile(
    r"\b[\w./-]+\.(?:rs|go|py|sh|ts|js|tsx|jsx|lean):\d+\b"
)
TEST_CWD_PATTERNS = (
    re.compile(r"\bstd::env::set_current_dir\s*\("),
    re.compile(r"\bos\.Chdir\s*\("),
)
TEST_BRITTLE_PATTERNS = (
    re.compile(r"/nonexistent"),
    re.compile(r"Permission denied"),
    re.compile(r"read-only", re.IGNORECASE),
    re.compile(r"\bchmod\s*\("),
)
RUNTIME_UNWRAP_RE = re.compile(r"(?:\.|::)(unwrap|expect)\s*\(")
DROP_PANIC_RE = re.compile(
    r"\b(panic|todo|unimplemented)!\s*\(|(?:\.|::)(unwrap|expect)\s*\("
)
INLINE_COMMENT_PATTERNS = (
    re.compile(r"(^|[^:])(?P<comment>//.*)"),
    re.compile(r"(?P<comment>/\*.*)"),
    re.compile(r"(^|\s)(?P<comment>#.*)"),
    re.compile(r"(^|\s)(?P<comment>--.*)"),
)


def extract_comment_fragments(text: str) -> list[str]:
    fragments: list[str] = []
    stripped = text.lstrip()

    if (
        is_comment_line(text)
        or stripped.startswith("* ")
        or stripped == "*"
    ):
        fragments.append(stripped)

    for pattern in INLINE_COMMENT_PATTERNS:
        match = pattern.search(text)
        if match is None:
            continue
        fragment = match.group("comment")
        if fragment and fragment not in fragments:
            fragments.append(fragment)

    return fragments


def scan_invariants(
    manifest_path: str | Path, diff_range: str | None = None, fast: bool = False
) -> list[str]:
    _, repo_root, _ = load_manifest(manifest_path)
    resolved_diff_range = resolve_diff_range(repo_root, diff_range)
    patches = parse_diff_patches(repo_root, resolved_diff_range)

    blockers: list[str] = []
    drop_ranges_cache: dict[str, list[tuple[int, int]]] = {}

    for rel_path, patch in sorted(patches.items()):
        test_file = is_test_file(rel_path)
        production_file = is_production_loc_file(rel_path)
        runtime_sensitive = (
            production_file
            and rel_path.endswith(".rs")
            and is_runtime_sensitive_path(rel_path)
        )

        for added in patch.added_lines:
            text = added.text
            location = f"{rel_path}:{added.number}"

            if production_file:
                for pattern in ENV_KNOB_PATTERNS:
                    if pattern.search(text):
                        blockers.append(
                            f"{location}: hidden test knob in production path"
                        )
                        break

            comment_fragments = extract_comment_fragments(text)
            if production_file and any(
                FILE_LINE_ANCHOR_RE.search(fragment) for fragment in comment_fragments
            ):
                blockers.append(f"{location}: file:line anchor in added comment")

            if test_file:
                for pattern in TEST_CWD_PATTERNS:
                    if pattern.search(text):
                        blockers.append(f"{location}: brittle test CWD mutation")
                        break
                for pattern in TEST_BRITTLE_PATTERNS:
                    if pattern.search(text):
                        blockers.append(f"{location}: brittle test path or OS-string match")
                        break

            if runtime_sensitive and not is_comment_line(text) and RUNTIME_UNWRAP_RE.search(text):
                blockers.append(
                    f"{location}: unwrap/expect added in runtime-sensitive non-test path"
                )

        if fast or test_file or not rel_path.endswith(".rs"):
            continue

        try:
            drop_ranges = drop_ranges_cache.setdefault(
                rel_path, find_drop_block_ranges(read_worktree_text(repo_root, rel_path))
            )
        except FileNotFoundError:
            continue

        for added in patch.added_lines:
            if line_in_ranges(added.number, drop_ranges) and DROP_PANIC_RE.search(added.text):
                blockers.append(
                    f"{rel_path}:{added.number}: panic-like cleanup added inside impl Drop"
                )

    return blockers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="High-confidence invariant scan for repo-local Q manifests."
    )
    parser.add_argument("--q-manifest", required=True, help="Path to tools/agent_tasks/<Q-ID>.json")
    parser.add_argument(
        "--diff-range",
        help="Optional git diff range; defaults to the current worktree against git merge-base origin/main HEAD",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Skip full-file impl Drop context checks and scan added lines only.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        blockers = scan_invariants(args.q_manifest, args.diff_range, args.fast)
    except Exception as exc:
        print(f"BLOCKED: invariant scan failed: {exc}")
        return 1

    if blockers:
        print("BLOCKED: invariant scan found violations")
        for blocker in blockers:
            print(f"- {blocker}")
        return 1

    print("PASS: invariant scan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

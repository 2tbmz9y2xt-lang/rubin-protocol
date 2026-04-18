#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from rubin_agent_contract import (
    count_production_loc,
    list_changed_files,
    load_manifest,
    matches_any_glob,
    normalize_rel_path,
    parse_diff_patches,
    resolve_diff_range,
)


def evaluate_scope(manifest_path: str, diff_range: str | None = None) -> tuple[list[str], list[str]]:
    manifest_path_resolved, repo_root, manifest = load_manifest(manifest_path)
    resolved_diff_range = resolve_diff_range(repo_root, diff_range)

    changed_files = list_changed_files(repo_root, resolved_diff_range)
    allowed_files = {normalize_rel_path(path) for path in manifest["allowed_files"]}
    manifest_rel = manifest_path_resolved.resolve().relative_to(repo_root.resolve())
    allowed_files.add(normalize_rel_path(str(manifest_rel)))
    allowed_globs = [normalize_rel_path(pattern) for pattern in manifest.get("allowed_globs", [])]
    forbidden_globs = [
        normalize_rel_path(pattern) for pattern in manifest.get("forbidden_globs", [])
    ]

    blockers: list[str] = []
    warnings: list[str] = []

    for rel_path in changed_files:
        if forbidden_globs and matches_any_glob(rel_path, forbidden_globs):
            blockers.append(
                f"{rel_path}: touched forbidden surface declared in forbidden_globs"
            )
            continue
        if rel_path in allowed_files:
            continue
        if allowed_globs and matches_any_glob(rel_path, allowed_globs):
            continue
        blockers.append(
            f"{rel_path}: outside allowed_files/allowed_globs for {manifest['q_id']}"
        )

    production_loc = count_production_loc(parse_diff_patches(repo_root, resolved_diff_range))
    target_loc = manifest.get("target_production_loc")
    hard_loc = manifest["hard_production_loc"]
    if isinstance(target_loc, int) and production_loc > target_loc:
        warnings.append(
            f"production diff is {production_loc} LOC, above target_production_loc={target_loc}"
        )
    if production_loc > hard_loc:
        blockers.append(
            f"production diff is {production_loc} LOC, above hard_production_loc={hard_loc}"
        )

    return blockers, warnings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail-closed scope guard for repo-local Q manifests."
    )
    parser.add_argument("--q-manifest", required=True, help="Path to tools/agent_tasks/<Q-ID>.json")
    parser.add_argument(
        "--diff-range",
        help="Optional git diff range; defaults to the current worktree against git merge-base origin/main HEAD",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        blockers, warnings = evaluate_scope(args.q_manifest, args.diff_range)
    except Exception as exc:
        print(f"BLOCKED: scope guard failed: {exc}")
        return 1

    for warning in warnings:
        print(f"WARN: {warning}")

    if blockers:
        print("BLOCKED: scope guard found contract violations")
        for blocker in blockers:
            print(f"- {blocker}")
        return 1

    print("PASS: scope guard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

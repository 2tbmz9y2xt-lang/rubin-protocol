#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


STATE_SUBDIR = "local-security-review"
RECEIPT_NAME = "pre-pr-receipt.json"


def run_git(repo_root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip() or "unknown git error"
        raise RuntimeError(f"git {' '.join(args)} :: {msg}")
    return proc.stdout.strip()


def resolve_git_common_dir(repo_root: Path) -> Path:
    raw = run_git(repo_root, "rev-parse", "--git-common-dir")
    path = Path(raw)
    if not path.is_absolute():
        path = (repo_root / path).resolve()
    return path


def receipt_path(repo_root: Path) -> Path:
    return resolve_git_common_dir(repo_root) / STATE_SUBDIR / RECEIPT_NAME


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def current_head(repo_root: Path) -> str:
    return run_git(repo_root, "rev-parse", "HEAD")


def current_merge_base(repo_root: Path, base_ref: str) -> str:
    return run_git(repo_root, "merge-base", "HEAD", base_ref)


def tracked_worktree_clean(repo_root: Path) -> bool:
    return run_git(repo_root, "status", "--short", "--untracked-files=no") == ""


def write_receipt(repo_root: Path, *, base_ref: str, source: str) -> dict[str, object]:
    path = receipt_path(repo_root)
    payload = {
        "schema_version": 1,
        "note": "rubin-protocol pre-push preflight receipt",
        "source": source,
        "base_ref": base_ref,
        "repo_root": str(repo_root),
        "git_common_dir": str(resolve_git_common_dir(repo_root)),
        "head": current_head(repo_root),
        "merge_base": current_merge_base(repo_root, base_ref),
        "tracked_worktree_clean": tracked_worktree_clean(repo_root),
        "generated_at": now_utc_iso(),
        "steps": ["coverage-preflight"],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"fresh": True, "reason": "written", "receipt_path": str(path), "receipt": payload}


def check_receipt(repo_root: Path, *, base_ref: str) -> dict[str, object]:
    path = receipt_path(repo_root)
    result: dict[str, object] = {
        "fresh": False,
        "reason": "missing",
        "receipt_path": str(path),
    }
    if not path.exists():
        return result
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        result["reason"] = f"malformed:{exc.__class__.__name__}"
        return result
    if not isinstance(payload, dict):
        result["reason"] = "malformed:non-object"
        return result
    result["receipt"] = payload
    if int(payload.get("schema_version") or 0) != 1:
        result["reason"] = "schema-mismatch"
        return result
    if str(payload.get("base_ref") or "") != base_ref:
        result["reason"] = "base-ref-mismatch"
        return result
    if not tracked_worktree_clean(repo_root):
        result["reason"] = "dirty-worktree"
        return result
    head = current_head(repo_root)
    if str(payload.get("head") or "") != head:
        result["reason"] = "head-mismatch"
        result["current_head"] = head
        return result
    merge_base = current_merge_base(repo_root, base_ref)
    if str(payload.get("merge_base") or "") != merge_base:
        result["reason"] = "merge-base-mismatch"
        result["current_merge_base"] = merge_base
        return result
    result["fresh"] = True
    result["reason"] = "fresh"
    result["current_head"] = head
    result["current_merge_base"] = merge_base
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Read/write local rubin-protocol pre-push preflight receipts")
    sub = ap.add_subparsers(dest="command", required=True)

    write_ap = sub.add_parser("write")
    write_ap.add_argument("--repo-root", required=True)
    write_ap.add_argument("--base-ref", default="origin/main")
    write_ap.add_argument("--source", default="manual")

    check_ap = sub.add_parser("check")
    check_ap.add_argument("--repo-root", required=True)
    check_ap.add_argument("--base-ref", default="origin/main")

    args = ap.parse_args()
    repo_root = Path(args.repo_root).resolve()
    if args.command == "write":
        payload = write_receipt(repo_root, base_ref=args.base_ref, source=args.source)
    else:
        payload = check_receipt(repo_root, base_ref=args.base_ref)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

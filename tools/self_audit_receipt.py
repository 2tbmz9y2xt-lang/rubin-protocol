#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


STATE_SUBDIR = "local-security-review"
RECEIPT_NAME = "self-audit-receipt.json"
PROMPT_NAME = "self-audit-prompt.txt"
SCHEMA_VERSION = 2


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


def git_dir(repo_root: Path) -> Path:
    raw = run_git(repo_root, "rev-parse", "--git-dir")
    path = Path(raw)
    if not path.is_absolute():
        path = (repo_root / path).resolve()
    return path


def state_dir(repo_root: Path) -> Path:
    return git_dir(repo_root) / STATE_SUBDIR


def receipt_path(repo_root: Path) -> Path:
    return state_dir(repo_root) / RECEIPT_NAME


def prompt_path(repo_root: Path) -> Path:
    return state_dir(repo_root) / PROMPT_NAME


def prompt_tool_path(repo_root: Path) -> Path:
    return repo_root / "tools" / "self_audit_prompt_pack.py"


def review_contract_path(repo_root: Path) -> Path:
    return repo_root / "tools" / "prepush_review_contract.json"


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def current_branch(repo_root: Path) -> str:
    try:
        return run_git(repo_root, "symbolic-ref", "--quiet", "--short", "HEAD")
    except RuntimeError:
        return run_git(repo_root, "rev-parse", "--short", "HEAD")


def maybe_head(repo_root: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def maybe_head_tree(repo_root: Path) -> str:
    head = maybe_head(repo_root)
    if not head:
        return ""
    return run_git(repo_root, "rev-parse", "HEAD^{tree}")


def current_index_tree(repo_root: Path) -> str:
    return run_git(repo_root, "write-tree")


def tracked_worktree_clean(repo_root: Path) -> bool:
    return run_git(repo_root, "status", "--short", "--untracked-files=no") == ""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def ensure_self_audit_prompt(repo_root: Path) -> Path:
    tool = prompt_tool_path(repo_root)
    if not tool.exists():
        raise RuntimeError(f"missing self-audit prompt tool: {tool}")
    path = prompt_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["python3", str(tool), "--repo-root", str(repo_root), "--output", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        msg = proc.stderr.strip() or proc.stdout.strip() or "unknown prompt-pack error"
        raise RuntimeError(f"self-audit prompt build failed :: {msg}")
    return path


def build_payload(repo_root: Path, *, source: str) -> dict[str, object]:
    built_prompt_path = ensure_self_audit_prompt(repo_root)
    contract = review_contract_path(repo_root)
    return {
        "schema_version": SCHEMA_VERSION,
        "note": "rubin-protocol local self-audit receipt",
        "source": source,
        "repo_root": str(repo_root),
        "git_dir": str(git_dir(repo_root)),
        "branch": current_branch(repo_root),
        "head_at_write": maybe_head(repo_root),
        "staged_tree": current_index_tree(repo_root),
        "tracked_worktree_clean": tracked_worktree_clean(repo_root),
        "prompt_path": str(built_prompt_path),
        "prompt_sha256": file_sha256(built_prompt_path),
        "review_contract_path": str(contract),
        "review_contract_sha256": file_sha256(contract),
        "generated_at": now_utc_iso(),
    }


def write_receipt(repo_root: Path, *, source: str) -> dict[str, object]:
    payload = build_payload(repo_root, source=source)
    path = receipt_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"fresh": True, "reason": "written", "receipt_path": str(path), "receipt": payload}


def read_receipt(repo_root: Path) -> tuple[dict[str, object], dict[str, object] | None]:
    path = receipt_path(repo_root)
    result: dict[str, object] = {"fresh": False, "reason": "missing", "receipt_path": str(path)}
    if not path.exists():
        return result, None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        result["reason"] = f"malformed:{exc.__class__.__name__}"
        return result, None
    if not isinstance(payload, dict):
        result["reason"] = "malformed:non-object"
        return result, None
    result["receipt"] = payload
    try:
        schema_version = int(payload.get("schema_version") or 0)
    except (TypeError, ValueError):
        result["reason"] = "schema-malformed"
        return result, payload
    if schema_version != SCHEMA_VERSION:
        result["reason"] = "schema-mismatch"
        return result, payload
    return result, payload


def check_commit(repo_root: Path) -> dict[str, object]:
    result, payload = read_receipt(repo_root)
    if payload is None:
        return result
    branch = current_branch(repo_root)
    if str(payload.get("branch") or "") != branch:
        result["reason"] = "branch-mismatch"
        result["current_branch"] = branch
        return result
    head = maybe_head(repo_root)
    if str(payload.get("head_at_write") or "") != head:
        result["reason"] = "head-mismatch"
        result["current_head"] = head
        return result
    staged_tree = current_index_tree(repo_root)
    if str(payload.get("staged_tree") or "") != staged_tree:
        result["reason"] = "staged-tree-mismatch"
        result["current_staged_tree"] = staged_tree
        return result
    current_contract = review_contract_path(repo_root)
    if not current_contract.exists():
        result["reason"] = "missing-review-contract"
        return result
    if str(payload.get("review_contract_sha256") or "") != file_sha256(current_contract):
        result["reason"] = "review-contract-mismatch"
        return result
    current_prompt = prompt_path(repo_root)
    if not current_prompt.exists():
        result["reason"] = "missing-self-audit-prompt"
        result["prompt_path"] = str(current_prompt)
        return result
    if str(payload.get("prompt_sha256") or "") != file_sha256(current_prompt):
        result["reason"] = "self-audit-prompt-mismatch"
        result["prompt_path"] = str(current_prompt)
        return result
    result["fresh"] = True
    result["reason"] = "fresh"
    result["current_branch"] = branch
    result["current_head"] = head
    result["current_staged_tree"] = staged_tree
    return result


def check_push(repo_root: Path) -> dict[str, object]:
    result, payload = read_receipt(repo_root)
    if payload is None:
        return result
    branch = current_branch(repo_root)
    if str(payload.get("branch") or "") != branch:
        result["reason"] = "branch-mismatch"
        result["current_branch"] = branch
        return result
    if not tracked_worktree_clean(repo_root):
        result["reason"] = "dirty-worktree"
        return result
    head = maybe_head(repo_root)
    if not head:
        result["reason"] = "missing-head"
        return result
    head_tree = maybe_head_tree(repo_root)
    if str(payload.get("staged_tree") or "") != head_tree:
        result["reason"] = "head-tree-mismatch"
        result["current_head"] = head
        result["current_head_tree"] = head_tree
        return result
    current_contract = review_contract_path(repo_root)
    if not current_contract.exists():
        result["reason"] = "missing-review-contract"
        return result
    if str(payload.get("review_contract_sha256") or "") != file_sha256(current_contract):
        result["reason"] = "review-contract-mismatch"
        return result
    current_prompt = prompt_path(repo_root)
    if not current_prompt.exists():
        result["reason"] = "missing-self-audit-prompt"
        result["prompt_path"] = str(current_prompt)
        return result
    if str(payload.get("prompt_sha256") or "") != file_sha256(current_prompt):
        result["reason"] = "self-audit-prompt-mismatch"
        result["prompt_path"] = str(current_prompt)
        return result
    result["fresh"] = True
    result["reason"] = "fresh"
    result["current_branch"] = branch
    result["current_head"] = head
    result["current_head_tree"] = head_tree
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Read/write local rubin-protocol self-audit receipts")
    sub = ap.add_subparsers(dest="command", required=True)

    write_ap = sub.add_parser("write")
    write_ap.add_argument("--repo-root", required=True)
    write_ap.add_argument("--source", default="self-audit")

    check_commit_ap = sub.add_parser("check-commit")
    check_commit_ap.add_argument("--repo-root", required=True)

    check_push_ap = sub.add_parser("check-push")
    check_push_ap.add_argument("--repo-root", required=True)

    args = ap.parse_args()
    repo_root = Path(args.repo_root).resolve()
    if args.command == "write":
        payload = write_receipt(repo_root, source=args.source)
    elif args.command == "check-commit":
        payload = check_commit(repo_root)
    else:
        payload = check_push(repo_root)
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

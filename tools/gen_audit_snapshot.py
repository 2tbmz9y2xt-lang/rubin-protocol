#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ALLOWED_STATUSES = {
    "OPEN",
    "DONE",
    "ALREADY_FIXED",
    "ACCEPTED_RISK",
    "DEFERRED",
    "DOC_FIX",
    "PARTIALLY_ADDRESSED",
    "WONTFIX",
    "RETRACTED",
}

ID_PATTERNS = (
    re.compile(r"^(?:[A-Z]+(?:-[A-Z0-9]+)+)$"),
    re.compile(r"^ACCEPTED_RISK_[A-Z0-9_]+$"),
)
FORBIDDEN_REF_SUBSTRINGS = ("spec_snapshot_",)
LOCAL_HOME_PREFIXES = (
    "/" + "Users" + "/",
    "/" + "home" + "/",
    "C:" + "\\" + "Users" + "\\",
)


def is_finding_id(value: str) -> bool:
    value = value.strip()
    return any(rx.match(value) for rx in ID_PATTERNS)


def split_row(line: str) -> list[str]:
    raw = line.strip()
    if raw.startswith("|"):
        raw = raw[1:]
    if raw.endswith("|"):
        raw = raw[:-1]
    parts = re.split(r"(?<!\\)\|", raw)
    return [cell.strip().replace("\\|", "|") for cell in parts]


def to_slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "section"


def classify_layer(finding_id: str) -> str:
    if finding_id.startswith(("Q-SPEC", "F-CON", "F-SEM", "F-ARCH", "F-P2P", "ACCEPTED_RISK_")):
        return "spec"
    if finding_id.startswith(("Q-TOOLING", "Q-CI", "F-DEV")):
        return "ci"
    return "repo"


def normalize_status(raw: str | None, fallback: str = "OPEN") -> str:
    if not raw:
        return fallback
    token = raw.strip().upper()
    token = token.replace("-", "_")
    token = token.replace("(", " ").replace(")", " ")
    token = token.replace(",", " ").replace(";", " ")
    token = token.split()[0] if token.split() else ""
    if token in ALLOWED_STATUSES:
        return token
    return fallback


def harmonize_status_with_summary(status: str, summary: str) -> str:
    upper_summary = summary.upper()
    if "ALREADY_FIXED" in upper_summary and status == "OPEN":
        return "ALREADY_FIXED"
    return status


def extract_refs(text: str) -> list[str]:
    refs: list[str] = []

    for match in re.findall(r"`([^`]+)`", text):
        m = match.strip()
        if not m:
            continue
        if "/" in m or m.endswith((".md", ".json", ".yml", ".yaml", ".py", ".go", ".rs", ".lean")):
            refs.append(m)

    for _, link in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", text):
        link = link.strip()
        if link:
            refs.append(link)

    out: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        normalized = ref.strip()
        if not normalized:
            continue
        lower = normalized.lower()
        if any(token in lower for token in FORBIDDEN_REF_SUBSTRINGS):
            continue
        if any(normalized.startswith(prefix) for prefix in LOCAL_HOME_PREFIXES):
            continue
        if ref not in seen:
            out.append(ref)
            seen.add(ref)
    return out


def section_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect_ci_enforcement(code_root: Path) -> dict[str, bool]:
    ci_path = code_root / ".github" / "workflows" / "ci.yml"
    if not ci_path.exists():
        return {
            "ci_workflow_present": False,
            "section_hashes_check": False,
            "formal_claims_lint_check": False,
            "conformance_bundle_check": False,
        }

    text = ci_path.read_text(encoding="utf-8", errors="strict")
    return {
        "ci_workflow_present": True,
        "section_hashes_check": "check-section-hashes.mjs" in text,
        "formal_claims_lint_check": "check_formal_claims_lint.py" in text,
        "conformance_bundle_check": "run_cv_bundle.py" in text,
    }


def build_snapshot(context_root: Path, code_root: Path, context_rel: str) -> dict[str, Any]:
    context_path = context_root / context_rel
    if not context_path.exists():
        raise FileNotFoundError(f"missing context file: {context_rel}")

    proof_cov_path = code_root / "rubin-formal" / "proof_coverage.json"
    if not proof_cov_path.exists():
        raise FileNotFoundError("missing rubin-formal/proof_coverage.json")

    lines = context_path.read_text(encoding="utf-8", errors="strict").splitlines()
    by_id: dict[str, dict[str, Any]] = {}
    section = "root"
    table_no = 0
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped.startswith("## ") or stripped.startswith("### "):
            section = stripped.lstrip("#").strip()

        if (
            stripped.startswith("|")
            and i + 1 < len(lines)
            and lines[i + 1].strip().startswith("|")
            and "-" in lines[i + 1]
        ):
            headers = split_row(lines[i])
            table_no += 1
            i += 2

            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = split_row(lines[i])
                if len(cells) < len(headers):
                    cells += [""] * (len(headers) - len(cells))
                row = {headers[idx]: cells[idx] for idx in range(len(headers))}

                id_value = ""
                for key in ("ID", "Q-ID", "Risk ID"):
                    if key in row and row[key].strip():
                        id_value = row[key].strip()
                        break
                if not id_value:
                    for key in headers:
                        if "ID" in key and row.get(key, "").strip():
                            id_value = row[key].strip()
                            break

                if is_finding_id(id_value):
                    raw_status = (
                        row.get("Статус")
                        or row.get("Status")
                        or row.get("Final status")
                        or row.get("Final Status")
                    )
                    if not raw_status and "Q-ID" in row and row.get("Severity"):
                        raw_status = "OPEN"
                    severity = (row.get("Severity") or "UNSPECIFIED").strip().upper()

                    summary = ""
                    for key in ("Кратко", "Что закрыто", "Finding", "Где зафиксировано", "Тезис внешнего аудита"):
                        if key in row and row[key].strip():
                            summary = row[key].strip()
                            break
                    if not summary:
                        summary = " | ".join(cell for cell in cells[1:] if cell)
                    status = harmonize_status_with_summary(
                        normalize_status(raw_status, fallback="OPEN"),
                        summary,
                    )

                    source_ref = f"{context_rel}#L{i + 1}"
                    source_section = to_slug(section)
                    refs = extract_refs(" | ".join(cells))
                    evidence = [source_ref] + refs

                    current = by_id.get(id_value, {})
                    merged_sources = current.get("sources", [])
                    merged_evidence = current.get("evidence", [])

                    merged_sources.append(
                        {
                            "section": source_section,
                            "table_index": table_no,
                            "line": i + 1,
                        }
                    )
                    merged_evidence.extend(evidence)

                    # last-write-wins для статуса/summary, чтобы поздние секции контекста имели приоритет
                    by_id[id_value] = {
                        "finding_id": id_value,
                        "status": status,
                        "severity": severity or "UNSPECIFIED",
                        "layer": classify_layer(id_value),
                        "summary": summary,
                        "sources": merged_sources,
                        "evidence": sorted(set(merged_evidence)),
                    }
                i += 1
            continue
        i += 1

    findings = [by_id[k] for k in sorted(by_id.keys())]

    by_status: dict[str, int] = {}
    by_layer: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for item in findings:
        by_status[item["status"]] = by_status.get(item["status"], 0) + 1
        by_layer[item["layer"]] = by_layer.get(item["layer"], 0) + 1
        by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1

    proof_cov = json.loads(proof_cov_path.read_text(encoding="utf-8"))
    snapshot = {
        "schema_version": 1,
        "source_file": context_rel,
        "source_sha256": section_hash(context_path),
        "formal_status": {
            "proof_level": proof_cov.get("proof_level"),
            "claim_level": proof_cov.get("claim_level"),
        },
        "ci_enforcement": collect_ci_enforcement(code_root),
        "findings": findings,
        "stats": {
            "total": len(findings),
            "by_status": by_status,
            "by_layer": by_layer,
            "by_severity": by_severity,
        },
    }
    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check machine-readable audit snapshot from AUDIT_CONTEXT.md")
    parser.add_argument(
        "--context-root",
        default=".",
        help="Root directory that contains AUDIT_CONTEXT/AUDIT_SNAPSHOT (default: cwd)",
    )
    parser.add_argument(
        "--code-root",
        default=".",
        help="Root directory that contains CI workflow + proof_coverage.json (default: cwd)",
    )
    parser.add_argument("--context", default="spec/AUDIT_CONTEXT.md", help="Path to AUDIT_CONTEXT markdown (repo-relative)")
    parser.add_argument("--output", default="spec/AUDIT_SNAPSHOT.json", help="Output snapshot JSON path (repo-relative)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="Write snapshot file")
    mode.add_argument("--check", action="store_true", help="Check that snapshot file is up-to-date")
    args = parser.parse_args()

    context_root = Path(args.context_root).resolve()
    code_root = Path(args.code_root).resolve()
    output_path = context_root / args.output

    snapshot = build_snapshot(context_root, code_root, args.context)
    rendered = json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n"

    if args.check:
        if not output_path.exists():
            print(f"ERROR: snapshot file not found: {args.output}", file=sys.stderr)
            return 1
        current = output_path.read_text(encoding="utf-8", errors="strict")
        if current != rendered:
            print("ERROR: audit snapshot is stale. Re-generate with:", file=sys.stderr)
            print(f"  python3 tools/gen_audit_snapshot.py --write", file=sys.stderr)
            return 1
        print(f"OK: audit snapshot is up-to-date ({args.output})")
        return 0

    if args.write or not output_path.exists():
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        print(f"Updated {output_path}")
        return 0

    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

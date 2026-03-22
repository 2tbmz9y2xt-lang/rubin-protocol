#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

ALLOWED_CHECK_TYPES = {"consensus_critical", "formal_lean", "code_noncritical", "diff_only"}

BASE_PROMPT = """You are RUBIN pre-push security reviewer operating in FAIL-CLOSED mode.

INPUT BOUNDARY (HARD):
- Use ONLY the provided diff bundle + scripted supplements + changed-files list.
- Do NOT browse web, do NOT assume hidden repo state, do NOT invent files/lines.
- Unchanged code is out-of-scope unless diff makes it newly reachable or removes a guard.

REVIEW CONTRACT (HARD):
- Apply ALL ACTIVE lenses before concluding findings=[].
- Every finding MUST map to changed evidence with exact file+line from diff.
- If evidence is insufficient, do not assert; return no finding for that claim.
- If unsure between severities, choose the higher one.
- Consensus split / signature bypass / inflation / reorg safety risks are never below HIGH.

OUTPUT CONTRACT (HARD):
- Return JSON only, matching schema:
  {model:string, findings:[{severity,file,line,title,details,suggestion}], summary:string}
- Allowed severities: CRITICAL,HIGH,MEDIUM,LOW,INFO,PERF,STYLE.
- summary MUST be single-line machine-readable:
  CHECK_TYPE=<type>|ACTIVE_LENSES=<csv>|LENSES_COVERED=<lens:ok;...>|NO_FINDINGS=<true|false>|RATIONALE=<text>
- If NO_FINDINGS=true, RATIONALE must explicitly state why each ACTIVE lens found no issue.

BLOCK POLICY REMINDER:
- Blocking severities: CRITICAL,HIGH,MEDIUM,LOW,PERF.
- Advisory only: INFO,STYLE.
"""

OVERLAYS = {
    "consensus_critical": """FOCUS:
- State transition correctness, validation order, parse determinism, signature verification, fork-choice/reorg safety.
- Threat model: malformed input adversary, Byzantine peer, DoS/resource exhaustion, implementation divergence, consensus split.

EXTRA RULES:
- Treat any potential accept/reject divergence Go vs Rust as at least HIGH.
- Flag panic-on-adversarial-input paths in consensus/validation code.
- Flag spec/fixture/code drift that changes normative behavior.
""",
    "formal_lean": """FOCUS:
- Lean proof soundness boundaries, theorem/lemma contract drift, conformance-replay bridge consistency.
- Reject placeholders (`sorry`/`admit`) and proof bypass patterns.
- Verify proof artifacts remain aligned with fixture/source mappings.

EXTRA RULES:
- Any change that weakens proof claim level or opens ambiguous interpretation => at least MEDIUM.
- Any path to mismatch between formal claim and executable behavior => HIGH.
""",
    "code_noncritical": """FOCUS:
- Correctness regressions, security defaults, reliability, operational safety.
- Parse/validation, filesystem/process safety, dependency/supply-chain drift, test coverage gaps.

EXTRA RULES:
- Prefer concrete changed-line risks over broad style commentary.
- Avoid speculative findings without direct diff evidence.
""",
    "diff_only": """FOCUS:
- Strict changed-line scan for newly introduced vulnerabilities/regressions only.
- Minimal attack-surface reasoning; no repo-wide extrapolation.

EXTRA RULES:
- Never report pre-existing unchanged behavior.
- If no material risk introduced, return findings=[] with strong RATIONALE.
""",
}


def parse_active_lenses(raw: str) -> list[str]:
    if not raw:
        return []
    if raw.strip().lower() == "none":
        return []
    values: list[str] = []
    for item in raw.split(","):
        value = item.strip()
        if value and value not in values:
            values.append(value)
    return values


def read_required_text(path: Path, label: str) -> str:
    if not path.exists():
        raise FileNotFoundError(f"{label} file is missing: {path}")
    return path.read_text(encoding="utf-8")


def read_focus_lines(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"focus file is missing: {path}")
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value:
            lines.append(value)
    return lines


def compose_prompt(
    *,
    check_type: str,
    active_lenses: list[str],
    fullscan_text: str,
    focus_lines: list[str],
    bundle_text: str,
) -> str:
    if check_type not in ALLOWED_CHECK_TYPES:
        allowed = ", ".join(sorted(ALLOWED_CHECK_TYPES))
        raise ValueError(f"unsupported check_type {check_type!r}; expected one of: {allowed}")
    if not bundle_text.strip():
        raise ValueError("diff bundle is empty")

    lines: list[str] = []

    if fullscan_text.strip():
        lines.append(fullscan_text.rstrip())
        lines.append("")

    lines.append("Prompt Pack: prepush-v1")
    lines.append(f"CHECK_TYPE={check_type}")
    lines.append(f"ACTIVE_LENSES={','.join(active_lenses) if active_lenses else 'none'}")
    lines.append("")
    lines.append(BASE_PROMPT.strip())
    lines.append("")
    lines.append("CHECK-TYPE OVERLAY:")
    lines.append(OVERLAYS[check_type].strip())
    lines.append("")
    lines.append("Mandatory review focuses for this diff:")
    if focus_lines:
        lines.extend(f"- {line}" for line in focus_lines)
    else:
        lines.append("- No extra mandatory focus triggers.")
    lines.append("")
    lines.append("Diff bundle follows.")
    lines.append("")
    lines.append(bundle_text.rstrip())
    lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Prompt Pack v1 for local pre-push model review.")
    parser.add_argument("--check-type", required=True)
    parser.add_argument("--active-lenses", default="")
    parser.add_argument("--fullscan-path", required=True)
    parser.add_argument("--focus-path", required=True)
    parser.add_argument("--bundle-path", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    prompt = compose_prompt(
        check_type=args.check_type.strip(),
        active_lenses=parse_active_lenses(args.active_lenses),
        fullscan_text=read_required_text(Path(args.fullscan_path), "fullscan"),
        focus_lines=read_focus_lines(Path(args.focus_path)),
        bundle_text=read_required_text(Path(args.bundle_path), "bundle"),
    )
    Path(args.output).write_text(prompt, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

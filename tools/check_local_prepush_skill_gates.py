#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

MAX_RENDERED_CHANGED_PATHS = 25
MAX_RENDERED_PATH_CHARS = 160


@dataclass(frozen=True)
class ScanLens:
    name: str
    active: bool
    why: str
    guidance: str


def read_changed_files(path: Path) -> set[str]:
    if not path.exists():
        return set()
    raw = path.read_text(encoding="utf-8")
    parts = raw.split("\0") if "\0" in raw else raw.splitlines()
    return {part for part in parts if part}


def is_under(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def matches_any(path: str, prefixes: tuple[str, ...], suffixes: tuple[str, ...], exact: tuple[str, ...]) -> bool:
    return (
        path in exact
        or any(is_under(path, prefix) for prefix in prefixes)
        or any(path.endswith(suffix) for suffix in suffixes)
    )


def run_check(name: str, cmd: list[str], repo_root: Path) -> int:
    print(f"[local-prepush-gate] {name}: {shlex.join(cmd)}")
    proc = subprocess.run(cmd, cwd=repo_root, text=True, capture_output=True, check=False)
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.stderr:
        sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        print(f"[local-prepush-gate] {name}: FAIL ({proc.returncode})", file=sys.stderr)
    else:
        print(f"[local-prepush-gate] {name}: PASS")
    return proc.returncode


def sanitize_path_for_prompt(path: str) -> str:
    truncated = path if len(path) <= MAX_RENDERED_PATH_CHARS else path[: MAX_RENDERED_PATH_CHARS - 3] + "..."
    return shlex.quote(truncated).replace("\n", r"\n").replace("\r", r"\r").replace("\t", r"\t")


def build_plan(changed: set[str]) -> tuple[list[tuple[str, list[str]]], list[str], list[ScanLens]]:
    checks: list[tuple[str, list[str]]] = []
    seen_check_names: set[str] = set()
    focuses: list[str] = []
    lenses: list[ScanLens] = []

    def add_check(name: str, cmd: list[str]) -> None:
        if name in seen_check_names:
            return
        seen_check_names.add(name)
        checks.append((name, cmd))

    def add_focus(text: str) -> None:
        if text not in focuses:
            focuses.append(text)

    def add_lens(name: str, *, active: bool, active_why: str, guidance: str, inactive_why: str) -> None:
        lenses.append(
            ScanLens(
                name=name,
                active=active,
                why=active_why if active else inactive_why,
                guidance=guidance,
            )
        )

    fixture_json_changed = any(
        matches_any(
            path,
            prefixes=(),
            suffixes=(".json",),
            exact=(),
        )
        and is_under(path, "conformance/fixtures")
        and Path(path).name.startswith("CV-")
        for path in changed
    )

    conformance_hygiene_related = fixture_json_changed or any(
        matches_any(
            path,
            prefixes=(),
            suffixes=(),
            exact=(
                "conformance/fixtures/CHANGELOG.md",
                "conformance/MATRIX.md",
                "tools/gen_conformance_matrix.py",
                "tools/check_conformance_fixtures_policy.py",
            ),
        )
        for path in changed
    )
    if conformance_hygiene_related:
        add_focus("Conformance hygiene: fixture changes must keep CHANGELOG.md and conformance/MATRIX.md synchronized.")
        add_check("conformance_fixtures_policy", ["python3", "tools/check_conformance_fixtures_policy.py"])
        add_check("conformance_matrix", ["python3", "tools/gen_conformance_matrix.py", "--check"])

    formal_bridge_related = any(
        matches_any(
            path,
            prefixes=(
                "tools/formal",
                "rubin-formal/RubinFormal/Conformance",
                "rubin-formal/RubinFormal/Refinement",
            ),
            suffixes=(),
            exact=(
                "conformance/runner/run_cv_bundle.py",
                "rubin-formal/refinement_bridge.json",
            ),
        )
        or fixture_json_changed
        for path in changed
    )
    if formal_bridge_related:
        add_focus("Formal bridge sync: executable fixtures, generated Lean vectors, and refinement bridge mappings must stay aligned.")
        add_check("lean_conformance_staleness", ["python3", "tools/check_lean_conformance_staleness.py"])
        add_check("formal_refinement_bridge", ["python3", "tools/check_formal_refinement_bridge.py"])

    conformance_runtime_related = any(
        matches_any(
            path,
            prefixes=("conformance/cmd", "conformance/devnetcv"),
            suffixes=(".go",),
            exact=("conformance/replay_test.go", "conformance/runner/run_cv_bundle.py"),
        )
        for path in changed
    )
    if conformance_runtime_related:
        add_focus("Local runner parity: local helper semantics must stay consistent with executable Go/Rust CLI accept/reject behavior.")
        add_check(
            "conformance_go_tests",
            ["scripts/dev-env.sh", "--", "bash", "-lc", "cd conformance && go test ./..."],
        )

    openssl_related = any(
        matches_any(
            path,
            prefixes=("scripts/crypto/openssl",),
            suffixes=(),
            exact=(
                ".github/workflows/ci.yml",
                "tools/check_consensus_openssl_isolation.py",
                "scripts/dev-env.sh",
                "clients/go/consensus/verify_sig_openssl.go",
                "clients/go/consensus/verify_sig_openssl_bootstrap_test.go",
                "clients/go/consensus/verify_sig_openssl_additional_test.go",
                "clients/go/consensus/openssl_signer.go",
                "clients/go/consensus/openssl_signer_additional_test.go",
                "clients/rust/crates/rubin-consensus/src/verify_sig_openssl.rs",
            ),
        )
        for path in changed
    )
    if openssl_related:
        add_focus("Consensus OpenSSL isolation: inherited OPENSSL_CONF/OPENSSL_MODULES plus RUBIN_OPENSSL_* env must not alter consensus verify semantics.")
        consensus_openssl_sources = [
            path
            for path in sorted(changed)
            if path
            in {
                "clients/go/consensus/verify_sig_openssl.go",
                "clients/rust/crates/rubin-consensus/src/verify_sig_openssl.rs",
            }
        ]
        if consensus_openssl_sources:
            add_check(
                "consensus_openssl_source_policy",
                ["python3", "tools/check_consensus_openssl_isolation.py", *consensus_openssl_sources],
            )
        if any(
            path in {".github/workflows/ci.yml", "tools/check_consensus_openssl_isolation.py"}
            for path in changed
        ):
            add_check(
                "consensus_openssl_tooling_self_test",
                ["python3", "tools/check_consensus_openssl_isolation.py", "--self-test"],
            )
        add_check(
            "go_verify_sig_smoke",
            [
                "scripts/dev-env.sh",
                "--",
                "bash",
                "-lc",
                'cd clients/go && go test ./consensus -run "TestVerifySig_(FIPSReadyModeValid|FIPSOnlyModeValidOrSkip|OpenSSLBackendErrorMapsToSigInvalid)$" -count=1',
            ],
        )
        add_check(
            "rust_verify_sig_smoke",
            [
                "scripts/dev-env.sh",
                "--",
                "bash",
                "-lc",
                "cd clients/rust && cargo test -p rubin-consensus verify_sig_openssl::tests::",
            ],
        )

    rust_perf_related = any(
        path in {
            "clients/rust/crates/rubin-consensus/src/sighash.rs",
            "clients/rust/crates/rubin-consensus/src/spend_verify.rs",
            "clients/rust/crates/rubin-consensus/src/tx_helpers.rs",
            "clients/rust/crates/rubin-consensus/src/utxo_basic.rs",
            "clients/rust/crates/rubin-consensus/src/core_ext.rs",
            "clients/rust/crates/rubin-consensus/src/htlc.rs",
            "clients/rust/crates/rubin-consensus/src/stealth.rs",
        }
        for path in changed
    )
    if rust_perf_related:
        add_focus("Rust perf-with-parity: cache/allocation optimizations must preserve digest bytes, error ordering, and Go parity.")
        add_check(
            "rust_consensus_tests",
            ["scripts/dev-env.sh", "--", "bash", "-lc", "cd clients/rust && cargo test -p rubin-consensus"],
        )

    has_scan_surface = any(
        path.endswith((".go", ".rs", ".py", ".sh", ".yml", ".yaml", ".json", ".toml", ".md"))
        for path in changed
    )
    go_related = any(path.endswith(".go") for path in changed)
    python_related = any(path.endswith(".py") for path in changed)
    rust_dependency_related = any(Path(path).name in {"Cargo.toml", "Cargo.lock"} for path in changed)
    internal_tooling_related = any(
        path.startswith(("tools/", "scripts/", ".github/workflows/", ".git/hooks-disabled/"))
        for path in changed
    )
    coverage_related = any(
        matches_any(
            path,
            prefixes=("clients/go", "clients/rust", "conformance", "tools/formal"),
            suffixes=(".go", ".rs", ".lean"),
            exact=("conformance/runner/run_cv_bundle.py",),
        )
        for path in changed
    )

    add_lens(
        "code-review",
        active=True,
        active_why="Always-on baseline pass for correctness, regressions, changed-line security impact, and reviewable behavioral drift.",
        guidance="Do a primary correctness/regression/security review of the diff before considering any specialized lens complete.",
        inactive_why="Never inactive.",
    )
    add_lens(
        "diff-scan",
        active=True,
        active_why="Always-on diff-focused pass over the exact changed bundle.",
        guidance="Treat the diff bundle as the trusted attack surface; look for newly introduced changed-line issues and do not promote unchanged code to findings unless the diff makes it newly reachable.",
        inactive_why="Never inactive.",
    )
    add_lens(
        "combined-security-scan",
        active=has_scan_surface or internal_tooling_related,
        active_why="Code/config/tooling files changed, so the review should synthesize multiple security and reliability passes into one conclusion.",
        guidance="Synthesize crypto misuse, parse/serialization, auth/config, filesystem/process, resource-exhaustion, and supply-chain angles before returning findings=[].",
        inactive_why="No code/config/tooling scan surface changed in this push.",
    )
    add_lens(
        "semgrep-scan",
        active=has_scan_surface or internal_tooling_related,
        active_why="Code/config/tooling files changed, so pattern-style security checks are relevant.",
        guidance="Emulate semgrep-style pattern review over changed files: dangerous command execution, path handling, weak validation, auth bypass, unsafe deserialization, and config drift.",
        inactive_why="No code/config/tooling files changed that justify semgrep-style pattern review.",
    )
    add_lens(
        "gosec-scan",
        active=go_related,
        active_why="Go source changed in this push.",
        guidance="Apply gosec-style scrutiny for command execution, weak randomness, temp/file permission handling, unsafe conversions, nil/error handling, and network/security defaults in Go paths.",
        inactive_why="No Go source changed in this push.",
    )
    add_lens(
        "cargo-audit-scan",
        active=rust_dependency_related,
        active_why="Rust dependency manifests or lockfiles changed, so supply-chain/advisory drift is in scope.",
        guidance="Review dependency changes as a cargo-audit lens: advisories, vulnerable crate upgrades/downgrades, and new dependency surface introduced by the diff.",
        inactive_why="No Rust dependency manifest or lockfile changed in this push.",
    )
    add_lens(
        "security-best-practices",
        active=go_related or python_related,
        active_why="Go or Python source changed, so secure-defaults guidance is relevant.",
        guidance="Check secure defaults, input validation, error handling, timeouts, resource limits, and denial-of-service hardening for the changed Go/Python paths.",
        inactive_why="No Go or Python source changed in this push.",
    )
    add_lens(
        "rubin-coverage",
        active=coverage_related,
        active_why="Consensus/runtime/conformance paths changed, so test reachability and coverage regressions are part of push risk.",
        guidance="Look for missing tests, dead branches behind non-public surfaces, and changes that expand runtime risk without matching executable coverage evidence.",
        inactive_why="No consensus/runtime/conformance path changed that requires a coverage lens.",
    )
    add_lens(
        "internal-tools",
        active=internal_tooling_related,
        active_why="Tooling, hooks, scripts, or workflow files changed in this push.",
        guidance="Review operational safety, fail-closed behavior, idempotence, path handling, and local-vs-canonical truth boundaries for changed tooling.",
        inactive_why="No tooling/workflow files changed in this push.",
    )

    return checks, focuses, lenses


def render_fullscan(changed: set[str], checks: list[tuple[str, list[str]]], lenses: list[ScanLens]) -> str:
    active = [lens for lens in lenses if lens.active]
    standby = [lens for lens in lenses if not lens.active]
    lines: list[str] = [
        "Skill-backed full-scan supplement:",
        "- These entries are scripted review lenses. They are not claims that external tools or Codex skills were auto-executed unless a deterministic local gate below already ran.",
        "- Apply every ACTIVE lens before returning findings=[].",
        "- Keep findings grounded in the diff bundle and changed-line evidence contract.",
    ]

    if changed:
        lines.extend(["", "Changed files in scope:"])
        sorted_paths = sorted(changed)
        rendered = sorted_paths[:MAX_RENDERED_CHANGED_PATHS]
        lines.extend(f"- {sanitize_path_for_prompt(path)}" for path in rendered)
        remaining = len(sorted_paths) - len(rendered)
        if remaining > 0:
            lines.append(f"- +{remaining} more files omitted from the supplement; rely on the diff bundle for the complete path set.")

    if checks:
        lines.extend(["", "Deterministic local gates already executed before model review:"])
        lines.extend(f"- {name}" for name, _ in checks)

    lines.extend(["", "ACTIVE review lenses:"])
    if active:
        for lens in active:
            lines.append(f"- {lens.name}: {lens.why}")
            lines.append(f"  Pass: {lens.guidance}")
    else:
        lines.append("- None. Use the baseline review rules only.")

    if standby:
        lines.extend(["", "STANDBY review lenses (inactive for this push):"])
        for lens in standby:
            lines.append(f"- {lens.name}: {lens.why}")
            lines.append(f"  If activated later: {lens.guidance}")

    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--changed-files", required=True)
    ap.add_argument("--focus-output", required=True)
    ap.add_argument("--fullscan-output", required=True)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    changed = read_changed_files(Path(args.changed_files))
    focus_output = Path(args.focus_output)
    fullscan_output = Path(args.fullscan_output)

    checks, focuses, lenses = build_plan(changed)

    focus_output.write_text("\n".join(focuses) + ("\n" if focuses else ""), encoding="utf-8")
    fullscan_output.write_text(render_fullscan(changed, checks, lenses), encoding="utf-8")

    if not checks:
        print("[local-prepush-gate] no extra local gates triggered")
        return 0

    failures = 0
    for name, cmd in checks:
        failures |= 1 if run_check(name, cmd, repo_root) != 0 else 0
    return failures


if __name__ == "__main__":
    raise SystemExit(main())

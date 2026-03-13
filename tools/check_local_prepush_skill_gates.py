#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path


def read_changed_files(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}


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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--changed-files", required=True)
    ap.add_argument("--focus-output", required=True)
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    changed = read_changed_files(Path(args.changed_files))
    focus_output = Path(args.focus_output)

    checks: list[tuple[str, list[str]]] = []
    seen_check_names: set[str] = set()
    focuses: list[str] = []

    def add_check(name: str, cmd: list[str]) -> None:
        if name in seen_check_names:
            return
        seen_check_names.add(name)
        checks.append((name, cmd))

    def add_focus(text: str) -> None:
        if text not in focuses:
            focuses.append(text)

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

    focus_output.write_text("\n".join(focuses) + ("\n" if focuses else ""), encoding="utf-8")

    if not checks:
        print("[local-prepush-gate] no extra local gates triggered")
        return 0

    failures = 0
    for name, cmd in checks:
        failures |= 1 if run_check(name, cmd, repo_root) != 0 else 0
    return failures


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

MAX_RENDERED_CHANGED_PATHS = 25
MAX_RENDERED_PATH_CHARS = 160
CONTRACT_PATH = Path(__file__).resolve().with_name("prepush_review_contract.json")
TOOLS_REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWED_REASONING = {"low", "medium", "high", "xhigh"}
ALLOWED_CHECK_TYPES = {"auto", "consensus_critical", "formal_lean", "code_noncritical", "diff_only"}

RUST_FUZZ_TARGET_PREFIX = "clients/rust/fuzz/fuzz_targets/"
RUST_FUZZ_CARGO_PATH = "clients/rust/fuzz/Cargo.toml"
RUST_BENCH_PREFIX = "clients/rust/crates/rubin-consensus/benches/"
RUST_CONSENSUS_CARGO_PATH = "clients/rust/crates/rubin-consensus/Cargo.toml"
WORKFLOW_HELPER_EXACT_PATHS = (
    "tools/list_workflow_shell_targets.py",
    "tools/tests/test_list_workflow_shell_targets.py",
)

try:
    from list_workflow_shell_targets import collect_targets as collect_workflow_shell_targets
except ModuleNotFoundError:
    from tools.list_workflow_shell_targets import collect_targets as collect_workflow_shell_targets

RUST_FUZZ_RUNTIME_MAP: dict[str, tuple[str, ...]] = {
    "clients/rust/crates/rubin-consensus/src/block.rs": ("parse_block_bytes", "block_header_surface"),
    "clients/rust/crates/rubin-consensus/src/block_basic.rs": ("validate_block_basic",),
    "clients/rust/crates/rubin-consensus/src/compact_relay.rs": ("compact_shortid",),
    "clients/rust/crates/rubin-consensus/src/compactsize.rs": ("compactsize",),
    "clients/rust/crates/rubin-consensus/src/connect_block_inmem.rs": ("connect_block_inmem",),
    "clients/rust/crates/rubin-consensus/src/connect_block_parallel.rs": (
        "connect_block_parallel_determinism",
        "connect_block_parallel_worker_parity",
    ),
    "clients/rust/crates/rubin-consensus/src/covenant_genesis.rs": ("covenant_genesis",),
    "clients/rust/crates/rubin-consensus/src/da_chunk_hash.rs": ("da_chunk_hash_verify",),
    "clients/rust/crates/rubin-consensus/src/da_payload_commit.rs": ("da_payload_commit_verify",),
    "clients/rust/crates/rubin-consensus/src/featurebits.rs": ("featurebits_state",),
    "clients/rust/crates/rubin-consensus/src/flagday.rs": ("flagday_helpers",),
    "clients/rust/crates/rubin-consensus/src/fork_choice.rs": ("fork_work",),
    "clients/rust/crates/rubin-consensus/src/pow.rs": ("pow_check",),
    "clients/rust/crates/rubin-consensus/src/sig_cache.rs": ("sig_cache_structural", "sig_cache_concurrent"),
    "clients/rust/crates/rubin-consensus/src/sighash.rs": ("sighash",),
    "clients/rust/crates/rubin-consensus/src/spend_verify.rs": ("spend_dispatch_structural",),
    "clients/rust/crates/rubin-consensus/src/suite_registry.rs": ("suite_registry_surface",),
    "clients/rust/crates/rubin-consensus/src/tx.rs": ("parse_tx", "parse_tx_determinism", "marshal_tx_roundtrip"),
    "clients/rust/crates/rubin-consensus/src/tx_dep_graph.rs": ("tx_dep_graph",),
    "clients/rust/crates/rubin-consensus/src/txcontext.rs": ("txcontext_bundle",),
    "clients/rust/crates/rubin-consensus/src/tx_validate_worker.rs": ("validate_tx_local",),
    "clients/rust/crates/rubin-consensus/src/verify_sig_openssl.rs": ("sig_verify_openssl",),
    "clients/rust/crates/rubin-node/src/p2p/relay.rs": ("tx_relay_announce", "tx_relay_receive"),
    "clients/rust/crates/rubin-node/src/p2p/version.rs": ("p2p_version_payload",),
    "clients/rust/crates/rubin-node/src/p2p/wire.rs": ("p2p_wire_message",),
}

RUST_BENCH_RUNTIME_MAP: dict[str, tuple[str, ...]] = {
    "clients/rust/crates/rubin-consensus/src/sig_cache.rs": ("sig_cache",),
    "clients/rust/crates/rubin-consensus/src/connect_block_parallel.rs": ("connect_block_parallel",),
    "clients/rust/crates/rubin-consensus/src/sig_queue.rs": ("connect_block_parallel",),
    "clients/rust/crates/rubin-consensus/src/spend_verify.rs": ("connect_block_parallel", "combined_load"),
    "clients/rust/crates/rubin-consensus/src/verify_sig_openssl.rs": ("connect_block_parallel",),
    "clients/rust/crates/rubin-consensus/src/da_verify_parallel.rs": ("combined_load",),
    "clients/rust/crates/rubin-consensus/src/da_rules.rs": ("combined_load",),
}


@dataclass(frozen=True)
class ScanLens:
    name: str
    active: bool
    why: str
    guidance: str


@dataclass(frozen=True)
class ReviewProfile:
    name: str
    check_type: str
    why: str
    model: str = ""
    model_reasoning_effort: str = ""
    stall_seconds: int = 0
    combine_review_units_when_at_most: int = 0
    required_lenses: tuple[str, ...] = ()
    conditional_lenses: tuple[str, ...] = ()


def load_profile_contract(profile_name: str, path: Path = CONTRACT_PATH) -> ReviewProfile:
    default_profile = ReviewProfile(
        name=profile_name,
        check_type=profile_name,
        why="Default local review contract.",
        model="gpt-5.4-mini",
        model_reasoning_effort="xhigh",
        stall_seconds=75,
        combine_review_units_when_at_most=12,
        required_lenses=("code-review", "diff-scan"),
        conditional_lenses=(),
    )
    if not path.exists():
        raise ValueError(f"review contract at {path} is missing")

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"review contract at {path} must decode to an object")

    try:
        schema_version = int(data.get("schema_version") or 1)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"review contract at {path} has non-numeric schema_version") from exc
    if schema_version < 3:
        raise ValueError(f"review contract at {path} must use schema_version >= 3")

    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError(f"review contract at {path} must define non-empty profiles")
    profile_data = profiles.get(profile_name)
    if not isinstance(profile_data, dict):
        raise ValueError(f"review contract at {path} has no profile named {profile_name!r}")

    model = str(profile_data.get("model") or default_profile.model).strip()
    reasoning = str(profile_data.get("model_reasoning_effort") or default_profile.model_reasoning_effort).strip().lower()
    if reasoning not in ALLOWED_REASONING:
        raise ValueError(
            f"review contract at {path} has unsupported model_reasoning_effort={reasoning!r} for profile {profile_name!r}"
        )

    def read_int_field(field: str, default: int) -> int:
        raw = profile_data.get(field)
        return default if raw is None else int(raw)

    try:
        stall_seconds = read_int_field("stall_seconds", default_profile.stall_seconds)
        combine_threshold = read_int_field(
            "combine_review_units_when_at_most",
            default_profile.combine_review_units_when_at_most,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"review contract at {path} has non-numeric thresholds for profile {profile_name!r}") from exc
    if stall_seconds < 30:
        raise ValueError(f"review contract at {path} profile {profile_name!r} has stall_seconds={stall_seconds}, expected >= 30")
    if combine_threshold < 1:
        raise ValueError(
            f"review contract at {path} profile {profile_name!r} has combine_review_units_when_at_most={combine_threshold}, expected >= 1"
        )

    def read_lens_list(field: str) -> tuple[str, ...]:
        raw = profile_data.get(field)
        if raw is None:
            raw = []
        if not isinstance(raw, list):
            raise ValueError(f"review contract at {path} field {field!r} for profile {profile_name!r} must be a list")
        values: list[str] = []
        for item in raw:
            value = str(item).strip()
            if not value:
                raise ValueError(f"review contract at {path} field {field!r} for profile {profile_name!r} contains empty lens")
            if value not in values:
                values.append(value)
        return tuple(values)

    required_lenses = read_lens_list("required_lenses")
    conditional_lenses = read_lens_list("conditional_lenses")
    if not required_lenses:
        raise ValueError(f"review contract at {path} profile {profile_name!r} must define non-empty required_lenses")

    return ReviewProfile(
        name=profile_name,
        check_type=profile_name,
        why=default_profile.why,
        model=model,
        model_reasoning_effort=reasoning,
        stall_seconds=stall_seconds,
        combine_review_units_when_at_most=combine_threshold,
        required_lenses=required_lenses,
        conditional_lenses=conditional_lenses,
    )


def ensure_known_profile_lenses(profile: ReviewProfile, lenses: list[ScanLens]) -> None:
    known_lenses = {lens.name for lens in lenses}
    unknown = [name for name in (*profile.required_lenses, *profile.conditional_lenses) if name not in known_lenses]
    if unknown:
        raise ValueError(
            f"profile {profile.name!r} references unknown review lenses: {', '.join(sorted(set(unknown)))}"
        )


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


def available_rust_fuzz_targets(repo_root: Path = TOOLS_REPO_ROOT) -> set[str]:
    root = repo_root / "clients" / "rust" / "fuzz" / "fuzz_targets"
    if not root.exists():
        return set()
    return {path.stem for path in root.glob("*.rs")}


def available_rust_bench_targets(repo_root: Path = TOOLS_REPO_ROOT) -> set[str]:
    root = repo_root / "clients" / "rust" / "crates" / "rubin-consensus" / "benches"
    if not root.exists():
        return set()
    return {path.stem for path in root.glob("*.rs")}


def resolve_rust_fuzz_targets(changed: set[str], repo_root: Path = TOOLS_REPO_ROOT) -> tuple[set[str], bool]:
    available = available_rust_fuzz_targets(repo_root)
    if not available:
        return set(), False

    targets: set[str] = set()
    build_all = RUST_FUZZ_CARGO_PATH in changed
    for path in changed:
        if path.startswith(RUST_FUZZ_TARGET_PREFIX):
            stem = Path(path).stem
            if stem in available:
                targets.add(stem)
        mapped = RUST_FUZZ_RUNTIME_MAP.get(path)
        if mapped:
            targets.update(name for name in mapped if name in available)
    if build_all:
        targets = set(available)
    return targets, build_all


def resolve_rust_bench_targets(changed: set[str], repo_root: Path = TOOLS_REPO_ROOT) -> tuple[set[str], set[str], bool]:
    available = available_rust_bench_targets(repo_root)
    if not available:
        return set(), set(), False

    direct_changes: set[str] = set()
    targets: set[str] = set()
    build_all = RUST_CONSENSUS_CARGO_PATH in changed
    for path in changed:
        if path.startswith(RUST_BENCH_PREFIX):
            stem = Path(path).stem
            if stem in available:
                direct_changes.add(stem)
                targets.add(stem)
        mapped = RUST_BENCH_RUNTIME_MAP.get(path)
        if mapped:
            targets.update(name for name in mapped if name in available)
    if build_all:
        targets = set(available)
    return targets, direct_changes, build_all


def current_workflow_shell_targets(repo_root: Path = TOOLS_REPO_ROOT) -> set[str]:
    try:
        return set(collect_workflow_shell_targets(repo_root))
    except FileNotFoundError:
        # The actual local gate re-runs the helper and fails closed.
        # For planning, keep routing conservative and avoid crashing early.
        return set()


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


def build_plan(
    changed: set[str],
    *,
    repo_root: Path = TOOLS_REPO_ROOT,
    check_type_override: str = "auto",
) -> tuple[list[tuple[str, list[str]]], list[str], list[ScanLens], ReviewProfile]:
    if check_type_override not in ALLOWED_CHECK_TYPES:
        allowed = ", ".join(sorted(ALLOWED_CHECK_TYPES))
        raise ValueError(f"unsupported check_type {check_type_override!r}; expected one of: {allowed}")

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

    workflow_shell_targets = current_workflow_shell_targets(repo_root)
    changed_workflow_files = {
        path
        for path in changed
        if is_under(path, ".github/workflows") and path.endswith((".yml", ".yaml"))
    }
    workflow_hygiene_related = bool(changed_workflow_files) or any(
        path in WORKFLOW_HELPER_EXACT_PATHS or path in workflow_shell_targets for path in changed
    )
    if workflow_hygiene_related:
        add_focus(
            "Workflow hygiene parity: local push runs deterministic companions for this surface "
            "(workflow YAML syntax, shell-target integrity, helper tests), while actionlint and "
            "shellcheck remain the server-side required truth."
        )
        if changed_workflow_files:
            add_check(
                "workflow_yaml_syntax",
                [
                    "ruby",
                    "-e",
                    'require "yaml"; ARGV.each { |path| YAML.load_file(path) }',
                    *sorted(changed_workflow_files),
                ],
            )
        add_check(
            "workflow_target_helper_tests",
            ["python3", "-m", "unittest", "tools.tests.test_list_workflow_shell_targets"],
        )
        add_check("workflow_shell_target_integrity", ["python3", "tools/list_workflow_shell_targets.py"])

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
        (
            (is_under(path, "conformance/cmd") or is_under(path, "conformance/devnetcv"))
            and path.endswith(".go")
        )
        or path in {"conformance/replay_test.go", "conformance/runner/run_cv_bundle.py"}
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

    rust_fuzz_targets, rust_fuzz_all = resolve_rust_fuzz_targets(changed)
    if rust_fuzz_targets:
        add_focus("Rust native fuzz companions are mandatory local gates: touched fuzz surfaces must at least build before push, otherwise push is blocked.")
        if rust_fuzz_all:
            add_check(
                "rust_fuzz_build_all",
                ["scripts/dev-env.sh", "--", "bash", "-lc", "cd clients/rust/fuzz && cargo build --bins"],
            )
        else:
            for target in sorted(rust_fuzz_targets):
                add_check(
                    f"rust_fuzz_build:{target}",
                    ["scripts/dev-env.sh", "--", "bash", "-lc", f"cd clients/rust/fuzz && cargo build --bin {shlex.quote(target)}"],
                )

    rust_bench_targets, rust_direct_bench_changes, rust_bench_all = resolve_rust_bench_targets(changed)
    if rust_bench_targets:
        add_focus("Rust benchmark companions are mandatory local gates: perf-sensitive surfaces with dedicated benches must compile locally before push, and edited bench files must get a tiny smoke run.")
        if rust_bench_all:
            add_check(
                "rust_bench_norun_all",
                ["scripts/dev-env.sh", "--", "bash", "-lc", "cd clients/rust && cargo bench -p rubin-consensus --benches --no-run"],
            )
        else:
            for target in sorted(rust_bench_targets):
                add_check(
                    f"rust_bench_norun:{target}",
                    ["scripts/dev-env.sh", "--", "bash", "-lc", f"cd clients/rust && cargo bench -p rubin-consensus --bench {shlex.quote(target)} --no-run"],
                )
        for target in sorted(rust_direct_bench_changes):
            add_check(
                f"rust_bench_smoke:{target}",
                [
                    "scripts/dev-env.sh",
                    "--",
                    "bash",
                    "-lc",
                    f"cd clients/rust && cargo bench -p rubin-consensus --bench {shlex.quote(target)} -- --sample-size 10 --measurement-time 0.01 --warm-up-time 0.01",
                ],
            )

    formal_bridge_exact_paths = {
        "tools/check_formal_refinement_bridge.py",
        "tools/check_lean_conformance_staleness.py",
        "rubin-formal/refinement_bridge.json",
    }

    consensus_core_related = any(
        matches_any(
            path,
            prefixes=(
                "clients/go/consensus",
                "clients/rust/crates/rubin-consensus",
                "clients/go/cmd/rubin-consensus-cli",
                "clients/rust/crates/rubin-consensus-cli",
                "conformance",
                "tools/formal",
            ),
            suffixes=(".lean",),
            exact=tuple(formal_bridge_exact_paths),
        )
        for path in changed
    )
    consensus_nonformal_core_related = any(
        not path.endswith(".lean")
        and path not in formal_bridge_exact_paths
        and matches_any(
            path,
            prefixes=(
                "clients/go/consensus",
                "clients/rust/crates/rubin-consensus",
                "clients/go/cmd/rubin-consensus-cli",
                "clients/rust/crates/rubin-consensus-cli",
                "conformance",
                "tools/formal",
            ),
            suffixes=(),
            exact=(),
        )
        for path in changed
    )
    crypto_related = any(
        any(token in path for token in ("verify_sig", "openssl", "mldsa", "sighash", "suite_registry", "rotation_descriptor"))
        for path in changed
    )
    core_ext_related = any("core_ext" in path for path in changed)

    runtime_source_related = any(
        (path.endswith(".go") and not path.endswith("_test.go"))
        or (path.endswith(".rs") and not path.endswith("_test.rs"))
        for path in changed
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
    rust_required_check_related = any(is_under(path, "clients/rust") for path in changed)
    coverage_related = any(
        matches_any(
            path,
            prefixes=("clients/go", "clients/rust", "conformance", "tools/formal"),
            suffixes=(".go", ".rs", ".lean"),
            exact=("conformance/runner/run_cv_bundle.py",),
        )
        for path in changed
    )
    if rust_required_check_related:
        add_focus(
            "Required server-side Kani remains final truth on clients/rust surfaces: local push does "
            "not run cargo kani and must not claim proof parity from companion tests alone."
        )
    if internal_tooling_related or workflow_hygiene_related:
        add_focus(
            "Server-only required checks still remain server-only here unless explicitly mirrored: "
            "CodeQL, dependency-review, hostile security-review, and semgrep."
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

    lean_related = any(path.endswith(".lean") for path in changed)
    formal_profile_related = formal_bridge_related or lean_related
    consensus_priority_related = any(
        (
            consensus_nonformal_core_related,
            openssl_related,
            conformance_runtime_related,
            crypto_related,
            core_ext_related,
            rust_perf_related,
        )
    )

    detected_check_type = "diff_only"
    if check_type_override != "auto":
        detected_check_type = check_type_override
    elif formal_profile_related and not consensus_priority_related:
        # Pure formal/proof/bridge changes should prefer the formal profile.
        detected_check_type = "formal_lean"
    elif any((consensus_core_related, openssl_related, conformance_hygiene_related, conformance_runtime_related, crypto_related, core_ext_related, rust_perf_related)):
        detected_check_type = "consensus_critical"
    elif runtime_source_related:
        detected_check_type = "code_noncritical"

    if detected_check_type == "consensus_critical":
        profile = ReviewProfile(
            name="consensus_critical",
            check_type=detected_check_type,
            why="Consensus/core/crypto/CORE_EXT/conformance-sensitive surface changed; run the strictest fail-closed review pack.",
        )
    elif detected_check_type == "formal_lean":
        profile = ReviewProfile(
            name="formal_lean",
            check_type=detected_check_type,
            why="Formal Lean/proof bridge surface changed; enforce formal-heavy fail-closed review pack.",
        )
    elif detected_check_type == "code_noncritical":
        profile = ReviewProfile(
            name="code_noncritical",
            check_type=detected_check_type,
            why="Runtime/application code changed outside consensus-critical buckets; use non-critical code profile.",
        )
    else:
        profile = ReviewProfile(
            name="diff_only",
            check_type=detected_check_type,
            why="Only patch/tooling/docs diff surface changed; use strict diff-only profile.",
        )
    contract_profile = load_profile_contract(profile.name)
    profile = ReviewProfile(
        name=profile.name,
        check_type=profile.check_type,
        why=profile.why,
        model=contract_profile.model,
        model_reasoning_effort=contract_profile.model_reasoning_effort,
        stall_seconds=contract_profile.stall_seconds,
        combine_review_units_when_at_most=contract_profile.combine_review_units_when_at_most,
        required_lenses=contract_profile.required_lenses,
        conditional_lenses=contract_profile.conditional_lenses,
    )
    ensure_known_profile_lenses(profile, lenses)
    return checks, focuses, lenses, profile


def active_lens_names(lenses: list[ScanLens], profile: ReviewProfile) -> list[str]:
    by_name = {lens.name: lens for lens in lenses}
    names: list[str] = []
    for name in profile.required_lenses:
        lens = by_name.get(name)
        if lens is not None and lens.active and name not in names:
            names.append(name)
    for name in profile.conditional_lenses:
        lens = by_name.get(name)
        if lens is not None and lens.active and name not in names:
            names.append(name)
    for lens in lenses:
        if lens.active and lens.name not in names:
            names.append(lens.name)
    return names


def render_fullscan(changed: set[str], checks: list[tuple[str, list[str]]], lenses: list[ScanLens], profile: ReviewProfile) -> str:
    by_name = {lens.name: lens for lens in lenses}
    active_lenses = active_lens_names(lenses, profile)
    profile_required = [by_name[name] for name in profile.required_lenses if name in by_name]
    profile_conditional_active = [
        by_name[name] for name in profile.conditional_lenses if name in by_name and by_name[name].active
    ]
    active_names = {lens.name for lens in profile_required if lens.active} | {lens.name for lens in profile_conditional_active}
    active = [lens for lens in lenses if lens.active and lens.name not in active_names]
    standby = [lens for lens in lenses if not lens.active]
    lines: list[str] = [
        "Skill-backed full-scan supplement:",
        "- These entries are scripted review lenses. They are not claims that external tools or Codex skills were auto-executed unless a deterministic local gate below already ran.",
        "- Apply every ACTIVE lens before returning findings=[].",
        "- Keep findings grounded in the diff bundle and changed-line evidence contract.",
        f"- Selected review profile: {profile.name}.",
        f"- Check type: {profile.check_type}.",
        f"- Profile rationale: {profile.why}",
        f"- Model route: {profile.model} ({profile.model_reasoning_effort}), combine-if-paths<={profile.combine_review_units_when_at_most}.",
        f"- ACTIVE_LENSES: {','.join(active_lenses) if active_lenses else 'none'}",
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

    lines.extend(["", "PROFILE-REQUIRED review lenses (apply in this order):"])
    for lens in profile_required:
        lines.append(f"- {lens.name}: {lens.why}")
        lines.append(f"  Pass: {lens.guidance}")

    lines.extend(["", "PROFILE-CONDITIONAL active review lenses:"])
    if profile_conditional_active:
        for lens in profile_conditional_active:
            lines.append(f"- {lens.name}: {lens.why}")
            lines.append(f"  Pass: {lens.guidance}")
    else:
        lines.append("- None triggered for this push.")

    lines.extend(["", "ADDITIONAL ACTIVE review lenses:"])
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
    ap.add_argument("--profile-output")
    ap.add_argument("--check-type", default="auto")
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    changed = read_changed_files(Path(args.changed_files))
    focus_output = Path(args.focus_output)
    fullscan_output = Path(args.fullscan_output)
    profile_output = Path(args.profile_output).resolve() if args.profile_output else None

    try:
        checks, focuses, lenses, profile = build_plan(changed, check_type_override=args.check_type)
    except ValueError as exc:
        print(f"[local-prepush-gate] contract: FAIL ({exc})", file=sys.stderr)
        return 2

    focus_output.write_text("\n".join(focuses) + ("\n" if focuses else ""), encoding="utf-8")
    fullscan_output.write_text(render_fullscan(changed, checks, lenses, profile), encoding="utf-8")
    if profile_output is not None:
        profile_output.write_text(
            json.dumps(
                {
                    "combine_review_units_when_at_most": profile.combine_review_units_when_at_most,
                    "conditional_lenses": list(profile.conditional_lenses),
                    "check_type": profile.check_type,
                    "active_lenses": active_lens_names(lenses, profile),
                    "model": profile.model,
                    "model_reasoning_effort": profile.model_reasoning_effort,
                    "profile": profile.name,
                    "required_lenses": list(profile.required_lenses),
                    "stall_seconds": profile.stall_seconds,
                    "why": profile.why,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    if not checks:
        print("[local-prepush-gate] no extra local gates triggered")
        return 0

    failures = 0
    for name, cmd in checks:
        failures |= 1 if run_check(name, cmd, repo_root) != 0 else 0
    return failures


if __name__ == "__main__":
    raise SystemExit(main())

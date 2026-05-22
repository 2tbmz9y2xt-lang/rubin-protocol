#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

CLAIMED_PRESENT_STATUSES = {"present", "covered", "complete"}
KNOWN_ABSENT_STATUSES = {"absent", "deferred", "not_claimed", "not-applicable", "not_applicable"}
RUNTIME_EVIDENCE_MAX_SOURCE_BYTES = 1_000_000
RUNTIME_EVIDENCE_DISCOVERY_TIMEOUT_SECS = 120


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def load_json(path: Path, *, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} must contain valid JSON: {exc}") from exc


def json_object(value: object, *, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def proof_domain_map(proof_coverage: dict) -> dict[str, dict]:
    domains = proof_coverage.get("edge_property_domains", [])
    if not isinstance(domains, list):
        raise ValueError("proof_coverage.json edge_property_domains must be a list")
    result: dict[str, dict] = {}
    for domain in domains:
        if not isinstance(domain, dict):
            raise ValueError("proof_coverage.json edge_property_domains entries must be objects")
        name = domain.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("proof_coverage.json edge_property_domains entries need non-empty name")
        if name in result:
            raise ValueError(f"proof_coverage.json duplicate edge_property_domain: {name}")
        result[name] = domain
    return result


def coverage_status(value: object, *, field_name: str, field_present: bool) -> tuple[str, str | None]:
    if not field_present:
        return "", None
    if not isinstance(value, dict):
        return "", f"{field_name} must be object"
    if "status" not in value:
        return "", f"{field_name}.status must be present when {field_name} is present"
    status = value.get("status")
    if not isinstance(status, str) or not status.strip():
        return "", f"{field_name}.status must be non-empty string"
    return status, None


def string_list(value: object, *, field_name: str, require_non_empty: bool = False) -> tuple[list[str], str | None]:
    if not isinstance(value, list):
        return [], f"{field_name} must be list"
    if require_non_empty and not value:
        return [], f"{field_name} must be non-empty list"
    strings: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return [], f"{field_name} entries must be non-empty strings"
        strings.append(item)
    if len(set(strings)) != len(strings):
        return [], f"{field_name} entries must be unique"
    return strings, None


def path_contains_symlink(repo_root: Path, rel_path: Path) -> bool:
    current = repo_root
    for part in rel_path.parts:
        current /= part
        if current.is_symlink():
            return True
    return False


def runtime_source_path_errors(raw_path: str, *, repo_root: Path) -> list[str]:
    rel_path = Path(raw_path)
    if rel_path.is_absolute():
        return ["runtime_evidence source path must be repo-relative"]
    if ".." in raw_path:
        return ["runtime_evidence source path must not contain '..'"]

    parts = rel_path.parts
    if len(parts) < 2 or parts[0] != "clients" or parts[1] not in {"go", "rust"}:
        return ["runtime_evidence source path must be under clients/go or clients/rust"]
    if parts[1] == "go" and not raw_path.endswith("_test.go"):
        return ["Go runtime evidence paths must end with _test.go"]
    if parts[1] == "rust" and not raw_path.endswith(".rs"):
        return ["Rust runtime evidence paths must end with .rs"]
    source_path = repo_root / rel_path
    if path_contains_symlink(repo_root, rel_path):
        return ["runtime_evidence source path must not contain symlinks"]
    try:
        resolved = source_path.resolve(strict=True)
    except FileNotFoundError:
        return ["runtime_evidence source path does not exist"]
    except OSError as exc:
        return [f"runtime_evidence source path cannot be resolved: {exc}"]

    if not resolved.is_relative_to(repo_root):
        return ["runtime_evidence source path escapes repo root"]
    try:
        source_stat = source_path.stat()
    except OSError as exc:
        return [f"runtime_evidence source path cannot be statted: {exc}"]
    if not stat.S_ISREG(source_stat.st_mode):
        return ["runtime_evidence source path must be a regular file"]
    if source_stat.st_size > RUNTIME_EVIDENCE_MAX_SOURCE_BYTES:
        return ["runtime_evidence source file exceeds max size"]
    return []


def go_package_arg(raw_path: str) -> str:
    package_dir = Path(raw_path).parent.relative_to("clients/go")
    if str(package_dir) == ".":
        return "."
    return f"./{package_dir.as_posix()}"


def run_discovery_command(
    cmd: list[str],
    *,
    cwd: Path,
    command_runner,
    env: dict[str, str | None] | None = None,
    merge_stderr: bool = True,
) -> tuple[str, str | None]:
    command_env = None
    if env is not None:
        command_env = dict(os.environ)
        for key, value in env.items():
            if value is None:
                command_env.pop(key, None)
            else:
                command_env[key] = value
        for key in list(command_env):
            if key.startswith("CARGO_TARGET_") and key != "CARGO_TARGET_DIR":
                command_env.pop(key, None)
    try:
        completed = command_runner(
            cmd,
            cwd=cwd,
            env=command_env,
            text=True,
            capture_output=True,
            timeout=RUNTIME_EVIDENCE_DISCOVERY_TIMEOUT_SECS,
        )
    except FileNotFoundError:
        return "", f"runtime_evidence discovery command missing: {cmd[0]}"
    except OSError as exc:
        return "", f"runtime_evidence discovery command failed to start: {cmd[0]}: {exc}"
    except subprocess.TimeoutExpired:
        return "", "runtime_evidence discovery command timed out"
    if completed.returncode != 0:
        return "", f"runtime_evidence discovery command failed: {cmd[0]} exit {completed.returncode}"
    if not isinstance(completed.stdout, str) or not isinstance(completed.stderr, str):
        return "", "runtime_evidence discovery command produced malformed stdout/stderr"
    output = completed.stdout + completed.stderr if merge_stderr else completed.stdout
    return output, None


def go_discovery_env(temp_dir: str) -> dict[str, str]:
    return {
        "GOENV": "off",
        "GOFLAGS": "-buildvcs=false",
        "GOTMPDIR": temp_dir,
    }


def rust_discovery_env(temp_dir: str) -> dict[str, str | None]:
    return {
        "CARGO_INCREMENTAL": "0",
        "CARGO_HOME": str(Path(temp_dir) / "cargo-home"), "HOME": temp_dir,
        "CARGO_TARGET_DIR": str(Path(temp_dir) / "target"),
        "CARGO_BUILD_TARGET": None,
        "CARGO_BUILD_RUSTC_WRAPPER": None,
        "CARGO_BUILD_RUSTFLAGS": None,
        "CARGO_ENCODED_RUSTFLAGS": None,
        "CARGO_NET_OFFLINE": None,
        "RUSTC": None,
        "RUSTC_WRAPPER": None,
        "RUSTC_WORKSPACE_WRAPPER": None,
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
        "RUSTFLAGS": None,
    }


def go_testmain_declared_tests(work_output: str, temp_dir: Path) -> tuple[set[str], str | None]:
    work_root = None
    for line in work_output.splitlines():
        if line.startswith("WORK="):
            work_root = Path(line.removeprefix("WORK=").strip()).resolve()
            break
    if work_root is None:
        return set(), "runtime_evidence discovery command did not report Go work directory"
    if not work_root.is_relative_to(temp_dir.resolve()):
        return set(), "runtime_evidence discovery command reported unsafe Go work directory"
    candidates = sorted(work_root.glob("**/_testmain.go"))
    if not candidates:
        return set(), "runtime_evidence discovery command did not produce Go testmain"
    try:
        testmain = candidates[0].read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return set(), f"runtime_evidence discovery command produced unreadable Go testmain: {exc}"
    tests = set()
    for match in re.finditer(r'\{"(Test[A-Za-z0-9_]*)",\s*_(x?test)\.(Test[A-Za-z0-9_]*)\}', testmain):
        if match.group(1) == match.group(3):
            tests.add(match.group(1))
    return tests, None


def go_objdump_matches_source(stdout: str, *, source_path: Path, repo_root: Path) -> bool:
    absolute = source_path.resolve().as_posix()
    try:
        relative = source_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        relative = source_path.name
    for line in stdout.splitlines():
        if not line.startswith("TEXT "):
            continue
        _, separator, emitted = line.rstrip().partition(") ")
        if not separator:
            continue
        emitted = emitted.replace("\\", "/")
        if emitted == absolute or emitted == relative or emitted.endswith(f"/{relative}"):
            return True
    return False


def go_file_discovered_tests(
    raw_path: str,
    *,
    repo_root: Path,
    expected_tests: list[str],
    command_runner,
) -> tuple[set[str], str | None]:
    package_arg = go_package_arg(raw_path)
    go_root = repo_root / "clients" / "go"
    with tempfile.TemporaryDirectory(prefix="rubin-go-testbin-") as temp_dir:
        test_binary = Path(temp_dir) / "package.test"
        compile_output, compile_error = run_discovery_command(
            ["go", "test", "-c", "-work", "-o", str(test_binary), package_arg],
            cwd=go_root,
            env=go_discovery_env(temp_dir),
            command_runner=command_runner,
        )
        if compile_error is not None:
            return set(), compile_error
        registered_tests, registry_error = go_testmain_declared_tests(compile_output, Path(temp_dir))
        if registry_error is not None:
            return set(), registry_error
        file_tests: set[str] = set()
        for test_name in sorted(expected_tests):
            if test_name not in registered_tests:
                continue
            symbol_re = rf".*\.{re.escape(test_name)}$"
            objdump_stdout, objdump_error = run_discovery_command(
                ["go", "tool", "objdump", "-s", symbol_re, str(test_binary)],
                cwd=go_root,
                env=go_discovery_env(temp_dir),
                command_runner=command_runner,
            )
            if objdump_error is not None:
                return set(), objdump_error
            if go_objdump_matches_source(objdump_stdout, source_path=repo_root / raw_path, repo_root=repo_root):
                file_tests.add(test_name)
    return file_tests, None


def discovered_runtime_tests(
    raw_path: str,
    *,
    repo_root: Path,
    expected_tests: list[str],
    verify_rust_discovery: bool,
    cargo_cache: dict[str, tuple[set[str], str | None]],
    command_runner,
) -> tuple[set[str], str | None]:
    if raw_path.startswith("clients/go/"):
        return go_file_discovered_tests(raw_path, repo_root=repo_root, expected_tests=expected_tests, command_runner=command_runner)
    if verify_rust_discovery and raw_path.startswith("clients/rust/"):
        return rust_file_discovered_tests(
            raw_path,
            repo_root=repo_root,
            expected_tests=expected_tests,
            cargo_cache=cargo_cache,
            command_runner=command_runner,
        )
    return set(), None


def rust_package_name(crate_root: Path) -> tuple[str, str | None]:
    cargo_toml = crate_root / "Cargo.toml"
    try:
        lines = cargo_toml.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        return "", f"runtime_evidence could not read Cargo.toml: {exc}"
    in_package = False
    for line in lines:
        stripped = line.strip()
        if stripped == "[package]":
            in_package = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_package = False
            continue
        if in_package:
            match = re.match(r'name\s*=\s*"([^"]+)"\s*$', stripped)
            if match:
                return match.group(1), None
    return "", "runtime_evidence discovery command could not determine Rust package name"


def rust_module_scope(raw_path: str) -> tuple[Path, str, str | None]:
    parts = Path(raw_path).parts
    if len(parts) < 6 or parts[:3] != ("clients", "rust", "crates"):
        return Path(), "", "unsupported Rust runtime evidence source scope"
    try:
        src_index = parts.index("src", 4)
    except ValueError:
        return Path(), "", "unsupported Rust runtime evidence source scope"
    crate_root = Path(*parts[:src_index])
    source_parts = parts[src_index + 1 :]
    if not source_parts or source_parts[0] == "bin" or source_parts[-1] in {"lib.rs", "main.rs", "mod.rs"}:
        return Path(), "", "unsupported Rust runtime evidence source scope"
    module_parts = list(source_parts)
    module_parts[-1] = Path(module_parts[-1]).stem
    return crate_root, "::".join(module_parts), None


def rust_listed_test_paths(output: str) -> set[str]:
    tests: set[str] = set()
    for line in output.splitlines():
        stripped = line.strip()
        match = re.match(r"([^:][^ ]*(?:::[^ ]+)*)\: test$", stripped)
        if match is None:
            continue
        tests.add(match.group(1))
    return tests


def rust_source_declared_tests(source_path: Path) -> tuple[set[str], str | None]:
    try:
        source = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return set(), f"runtime_evidence could not read Rust source: {exc}"
    if re.search(r"(?m)^\s*(?:#\[[^\n]*\]\s*)*mod\s+tests\s*;", source):
        return set(), "unsupported Rust runtime evidence source scope"
    match = re.search(r"(?s)#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*mod\s+tests\s*\{(?P<body>.*)\n\}", source)
    if match is None:
        return set(), "unsupported Rust runtime evidence source scope"
    body = match.group("body")
    if re.search(r"(?m)^\s*(?:pub\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:;|\{)", body):
        return set(), "unsupported Rust runtime evidence source scope"
    return set(re.findall(r"(?m)^\s*#\s*\[\s*test\s*\]\s*(?:#\[[^\n]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", body)), None


def rust_file_discovered_tests(
    raw_path: str,
    *,
    repo_root: Path,
    expected_tests: list[str],
    cargo_cache: dict[str, tuple[set[str], str | None]],
    command_runner,
) -> tuple[set[str], str | None]:
    crate_rel, module_scope, scope_error = rust_module_scope(raw_path)
    if scope_error is not None:
        return set(), scope_error
    package, package_error = rust_package_name(repo_root / crate_rel)
    if package_error is not None:
        return set(), package_error
    rust_root = repo_root / "clients" / "rust"
    for root in [rust_root, *rust_root.parents]:
        if (root / ".cargo" / "config").exists() or (root / ".cargo" / "config.toml").exists():
            return set(), "unsupported Rust runtime evidence Cargo config"
        if root == repo_root:
            break
    if package not in cargo_cache:
        with tempfile.TemporaryDirectory(prefix="rubin-rust-test-list-") as temp_dir:
            env = rust_discovery_env(temp_dir)
            output, error = run_discovery_command(
                ["cargo", "test", "--locked", "-p", package, "--lib", "--", "--list"],
                cwd=rust_root,
                env=env,
                command_runner=command_runner,
                merge_stderr=False,
            )
            if error is not None:
                cargo_cache[package] = (set(), error)
            else:
                ignored_output, ignored_error = run_discovery_command(
                    ["cargo", "test", "--locked", "-p", package, "--lib", "--", "--ignored", "--list"],
                    cwd=rust_root,
                    env=env,
                    command_runner=command_runner,
                    merge_stderr=False,
                )
                cargo_cache[package] = (
                    rust_listed_test_paths(output) - rust_listed_test_paths(ignored_output),
                    ignored_error,
                )
    active_test_paths, cargo_error = cargo_cache[package]
    if cargo_error is not None:
        return set(), cargo_error
    source_tests, source_error = rust_source_declared_tests(repo_root / raw_path)
    if source_error is not None:
        return set(), source_error
    prefix = f"{module_scope}::tests::"
    active_tests = {suffix for path in active_test_paths if path.startswith(prefix) for suffix in [path.removeprefix(prefix)] if "::" not in suffix and suffix in source_tests}
    return {name for name in expected_tests if name in active_tests}, None


def runtime_evidence_errors(
    value: object,
    *,
    repo_root: Path,
    verify_go_discovery: bool,
    verify_rust_discovery: bool,
    command_runner,
) -> list[str]:
    if not isinstance(value, dict):
        return ["runtime_evidence must be object"]
    if "tests_by_file" not in value:
        return ["runtime_evidence.tests_by_file must be present"]

    tests_by_file = value.get("tests_by_file")
    if not isinstance(tests_by_file, dict) or not tests_by_file:
        return ["runtime_evidence.tests_by_file must be non-empty object"]

    errors: list[str] = []
    cargo_cache: dict[str, tuple[set[str], str | None]] = {}
    for raw_path, raw_tests in tests_by_file.items():
        if not isinstance(raw_path, str) or not raw_path.strip() or raw_path != raw_path.strip():
            errors.append("runtime_evidence.tests_by_file keys must be non-empty repo-relative strings")
            continue
        tests, tests_error = string_list(
            raw_tests,
            field_name=f"runtime_evidence.tests_by_file[{raw_path}]",
            require_non_empty=True,
        )
        path_errors = runtime_source_path_errors(raw_path, repo_root=repo_root)
        if tests_error is not None:
            errors.append(tests_error)
        errors.extend(path_errors)
        if (
            (verify_go_discovery and raw_path.startswith("clients/go/"))
            or (verify_rust_discovery and raw_path.startswith("clients/rust/"))
        ) and tests_error is None and not path_errors:
            present, discovery_error = discovered_runtime_tests(
                raw_path,
                repo_root=repo_root,
                expected_tests=tests,
                verify_rust_discovery=verify_rust_discovery,
                cargo_cache=cargo_cache,
                command_runner=command_runner,
            )
            if discovery_error is not None:
                errors.append(discovery_error)
                continue
            missing = [name for name in tests if name not in present]
            if missing:
                errors.append(f"missing runtime evidence tests: {', '.join(missing)}")
    return errors


def main(argv: list[str] | None = None, *, command_runner=subprocess.run) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--verify-runtime-evidence-go",
        action="store_true",
        help="run opt-in Go toolchain discovery for Go runtime_evidence test names",
    )
    parser.add_argument(
        "--verify-runtime-evidence-rust",
        action="store_true",
        help="run opt-in Rust/Cargo discovery for Rust runtime_evidence test names",
    )
    args = parser.parse_args([] if argv is None else argv)

    repo_root = Path(".").resolve()
    baseline_path = repo_root / "conformance" / "EDGE_PACK_BASELINE.json"
    fixtures_dir = repo_root / "conformance" / "fixtures"
    proof_coverage_path = repo_root / "proof_coverage.json"

    if not baseline_path.exists():
        return fail("conformance/EDGE_PACK_BASELINE.json not found")
    if not fixtures_dir.exists():
        return fail("conformance/fixtures directory not found")
    if not proof_coverage_path.exists():
        return fail("proof_coverage.json not found")

    try:
        baseline = json_object(load_json(baseline_path, label="EDGE_PACK_BASELINE.json"), label="EDGE_PACK_BASELINE.json")
        proof_coverage = json_object(load_json(proof_coverage_path, label="proof_coverage.json"), label="proof_coverage.json")
        proof_domains = proof_domain_map(proof_coverage)
    except ValueError as exc:
        return fail(str(exc))
    if baseline.get("schema_version") != 1:
        return fail("EDGE_PACK_BASELINE.json schema_version must be 1")

    domains = baseline.get("domains")
    if not isinstance(domains, list) or not domains:
        return fail("EDGE_PACK_BASELINE.json must contain non-empty domains list")

    seen_domain_names: set[str] = set()
    fixture_gate_to_ids: dict[str, set[str]] = {}
    fixture_gate_to_count: dict[str, int] = {}
    for fixture in fixtures_dir.glob("CV-*.json"):
        try:
            fixture_label = str(fixture.relative_to(repo_root))
            data = json_object(load_json(fixture, label=fixture_label), label=fixture_label)
        except ValueError as exc:
            return fail(str(exc))
        gate = data.get("gate")
        vectors = data.get("vectors", [])
        if not isinstance(gate, str) or not gate.strip():
            return fail(f"{fixture.relative_to(repo_root)} has invalid gate")
        if not isinstance(vectors, list):
            return fail(f"{fixture.relative_to(repo_root)} vectors must be a list")
        ids = set()
        for vec in vectors:
            if not isinstance(vec, dict):
                return fail(f"{fixture.relative_to(repo_root)} vector entry must be object")
            vec_id = vec.get("id")
            if not isinstance(vec_id, str) or not vec_id.strip():
                return fail(f"{fixture.relative_to(repo_root)} contains vector with invalid id")
            ids.add(vec_id)
        fixture_gate_to_ids[gate] = ids
        fixture_gate_to_count[gate] = len(vectors)

    failures = 0
    for domain in domains:
        domain_failures_before = failures
        if not isinstance(domain, dict):
            print("ERROR: domain entry must be object", file=sys.stderr)
            failures += 1
            continue

        name = domain.get("name")
        gates = domain.get("gates")
        min_vectors_total = domain.get("min_vectors_total")
        required_vectors_by_gate = domain.get("required_vectors_by_gate", {})
        coverage_accounting = domain.get("coverage_accounting")

        if not isinstance(name, str) or not name.strip():
            print("ERROR: domain name missing/invalid", file=sys.stderr)
            failures += 1
            continue
        if name in seen_domain_names:
            print(f"ERROR: duplicate domain name: {name}", file=sys.stderr)
            failures += 1
            continue
        seen_domain_names.add(name)
        gate_names, gate_names_error = string_list(gates, field_name=f"domain {name} gates", require_non_empty=True)
        if gate_names_error is not None:
            print(f"ERROR: domain {name}: {gate_names_error}", file=sys.stderr)
            failures += 1
            continue
        if not isinstance(min_vectors_total, int) or min_vectors_total < 0:
            print(f"ERROR: domain {name}: min_vectors_total must be non-negative integer", file=sys.stderr)
            failures += 1
            continue
        if not isinstance(required_vectors_by_gate, dict):
            print(f"ERROR: domain {name}: required_vectors_by_gate must be object", file=sys.stderr)
            failures += 1
            continue
        if coverage_accounting is not None and not isinstance(coverage_accounting, dict):
            print(f"ERROR: domain {name}: coverage_accounting must be object", file=sys.stderr)
            failures += 1
            continue

        if "runtime_evidence" in domain:
            for error in runtime_evidence_errors(
                domain.get("runtime_evidence"),
                repo_root=repo_root,
                verify_go_discovery=args.verify_runtime_evidence_go,
                verify_rust_discovery=args.verify_runtime_evidence_rust,
                command_runner=command_runner,
            ):
                print(f"ERROR: domain {name}: {error}", file=sys.stderr)
                failures += 1

        total = 0
        missing_gates: list[str] = []
        for gate in gate_names:
            if gate not in fixture_gate_to_count:
                missing_gates.append(gate)
                continue
            total += fixture_gate_to_count[gate]

        if missing_gates:
            print(f"FAIL: domain {name}: missing gate fixtures: {', '.join(missing_gates)}", file=sys.stderr)
            failures += 1

        if total < min_vectors_total:
            print(
                f"FAIL: domain {name}: total vectors {total} < min_vectors_total {min_vectors_total}",
                file=sys.stderr,
            )
            failures += 1

        for gate, raw_required_ids in required_vectors_by_gate.items():
            if not isinstance(gate, str) or not gate.strip():
                print(f"ERROR: domain {name}: required_vectors_by_gate keys must be non-empty strings", file=sys.stderr)
                failures += 1
                continue
            if gate not in fixture_gate_to_ids:
                print(f"FAIL: domain {name}: required gate not found: {gate}", file=sys.stderr)
                failures += 1
                continue
            required_ids, required_ids_error = string_list(
                raw_required_ids,
                field_name=f"required_vectors_by_gate[{gate}]",
                require_non_empty=True,
            )
            if required_ids_error is not None:
                print(f"ERROR: domain {name}: {required_ids_error}", file=sys.stderr)
                failures += 1
                continue
            present = fixture_gate_to_ids[gate]
            missing = [rid for rid in required_ids if rid not in present]
            if missing:
                print(
                    f"FAIL: domain {name}: gate {gate} missing required vectors: {', '.join(missing)}",
                    file=sys.stderr,
                )
                failures += 1

        if coverage_accounting is not None:
            proof_domain_name = coverage_accounting.get("proof_coverage_domain")
            if not isinstance(proof_domain_name, str) or not proof_domain_name.strip():
                print(
                    f"ERROR: domain {name}: coverage_accounting.proof_coverage_domain must be non-empty string",
                    file=sys.stderr,
                )
                failures += 1
            elif proof_domain_name not in proof_domains:
                print(
                    f"FAIL: domain {name}: missing proof_coverage edge_property_domain {proof_domain_name}",
                    file=sys.stderr,
                )
                failures += 1
            else:
                proof_domain = proof_domains[proof_domain_name]
                proof_gates, proof_gates_error = string_list(
                    proof_domain.get("conformance_gates"),
                    field_name="proof_coverage conformance_gates",
                )
                if proof_gates_error is not None:
                    print(
                        f"ERROR: domain {name}: {proof_gates_error}",
                        file=sys.stderr,
                    )
                    failures += 1
                elif sorted(proof_gates) != sorted(gate_names):
                    print(
                        f"FAIL: domain {name}: proof_coverage gates do not match EDGE baseline gates",
                        file=sys.stderr,
                    )
                    failures += 1
                proof_vector_ids, proof_vector_ids_error = string_list(
                    proof_domain.get("vector_ids"),
                    field_name="proof_coverage vector_ids",
                )
                if proof_vector_ids_error is not None:
                    print(
                        f"ERROR: domain {name}: {proof_vector_ids_error}",
                        file=sys.stderr,
                    )
                    failures += 1
                else:
                    present_for_domain: set[str] = set()
                    for gate in gate_names:
                        present_for_domain.update(fixture_gate_to_ids.get(gate, set()))
                    missing_proof_ids = [
                        vid
                        for vid in proof_vector_ids
                        if isinstance(vid, str) and vid not in present_for_domain
                    ]
                    if missing_proof_ids:
                        print(
                            f"FAIL: domain {name}: proof_coverage references missing vector IDs: {', '.join(missing_proof_ids)}",
                            file=sys.stderr,
                        )
                        failures += 1
                    for gate, raw_required_ids in required_vectors_by_gate.items():
                        if not isinstance(gate, str) or not gate.strip():
                            continue
                        required_ids, required_ids_error = string_list(
                            raw_required_ids,
                            field_name=f"required_vectors_by_gate[{gate}]",
                            require_non_empty=True,
                        )
                        if required_ids_error is not None:
                            continue
                        missing_from_proof = [rid for rid in required_ids if rid not in proof_vector_ids]
                        if missing_from_proof:
                            print(
                                f"FAIL: domain {name}: proof_coverage missing vector IDs: {', '.join(missing_from_proof)}",
                                file=sys.stderr,
                            )
                            failures += 1

                fuzz_status, fuzz_status_error = coverage_status(
                    proof_domain.get("fuzz"),
                    field_name="proof_coverage fuzz",
                    field_present="fuzz" in proof_domain,
                )
                if fuzz_status_error is not None:
                    print(f"ERROR: domain {name}: {fuzz_status_error}", file=sys.stderr)
                    failures += 1
                elif fuzz_status in CLAIMED_PRESENT_STATUSES:
                    print(
                        f"FAIL: domain {name}: proof_coverage claims fuzz={fuzz_status}; committed fuzz evidence validation is not supported in this edge-pack checker",
                        file=sys.stderr,
                    )
                    failures += 1
                elif fuzz_status and fuzz_status not in KNOWN_ABSENT_STATUSES:
                    print(
                        f"ERROR: domain {name}: unknown fuzz coverage status {fuzz_status}",
                        file=sys.stderr,
                    )
                    failures += 1

                formal_status, formal_status_error = coverage_status(
                    proof_domain.get("formal"),
                    field_name="proof_coverage formal",
                    field_present="formal" in proof_domain,
                )
                if formal_status_error is not None:
                    print(f"ERROR: domain {name}: {formal_status_error}", file=sys.stderr)
                    failures += 1
                elif formal_status in CLAIMED_PRESENT_STATUSES:
                    print(
                        f"FAIL: domain {name}: proof_coverage claims formal={formal_status}; committed formal evidence validation is not supported in this edge-pack checker",
                        file=sys.stderr,
                    )
                    failures += 1
                elif formal_status and formal_status not in KNOWN_ABSENT_STATUSES:
                    print(
                        f"ERROR: domain {name}: unknown formal coverage status {formal_status}",
                        file=sys.stderr,
                    )
                    failures += 1

        if failures == domain_failures_before:
            print(f"OK: domain {name} total_vectors={total} min={min_vectors_total}")

    if failures:
        print(f"FAILED: edge-pack check found {failures} issue(s)", file=sys.stderr)
        return 1

    print("OK: conformance edge-pack baseline satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

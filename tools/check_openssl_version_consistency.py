#!/usr/bin/env python3
"""Check the finite registry of literal OpenSSL version owners."""
from __future__ import annotations
import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
VERSION_RE = r"[0-9]+\.[0-9]+\.[0-9]+"
BUILDER = "scripts/crypto/openssl/build-openssl-bundle.sh"
CACHE_ACTION = "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9"
CHECKSUM_EXPR = "${{ hashFiles('scripts/crypto/openssl/source-checksums.sha256') }}"
MAX_WORKFLOW_YAML_BYTES = 2 * 1024 * 1024
MAX_WORKFLOW_FILES = 64

@dataclass(frozen=True)
class WorkflowOwner:
    path: str
    job: str
    key_prefix: str = "openssl-bundle"
    key_revision: str = "v3"
    title_suffix: str = ""


WORKFLOW_OWNERS = (
    WorkflowOwner(".github/workflows/ci.yml", "test"),
    WorkflowOwner(".github/workflows/ci.yml", "go_race_node"),
    WorkflowOwner(".github/workflows/ci.yml", "formal_refinement"),
    WorkflowOwner(".github/workflows/ci.yml", "conformance_fixtures_drift"),
    WorkflowOwner(".github/workflows/codacy-coverage.yml", "coverage", title_suffix=" (PQC-enabled)"),
    WorkflowOwner(".github/workflows/combined-load-nightly.yml", "combined-load"),
    WorkflowOwner(".github/workflows/fips-only-nightly.yml", "fips-only-smoke"),
    WorkflowOwner(
        ".github/workflows/fuzz-nightly.yml",
        "fuzz-stage2",
        key_prefix="openssl-bundle-mldsa-verified",
        key_revision="v1",
    ),
    WorkflowOwner(".github/workflows/runtime-perf-guardrails.yml", "runtime-perf"),
)


def read(root: Path, path: str | Path) -> str:
    root = root.resolve()
    candidate = Path(path)
    candidate = candidate if candidate.is_absolute() else root / candidate
    try:
        resolved = candidate.resolve(strict=True)
        if resolved != candidate or not resolved.is_relative_to(root) or not resolved.is_file():
            raise ValueError(f"owner must be a regular in-repository path: {candidate}")
        return resolved.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ValueError(f"missing file: {candidate}") from exc
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read {candidate}: {exc}") from exc


def one_match(text: str, pattern: str, label: str) -> str:
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"{label}: expected exactly one supported owner, found {len(matches)}")
    return matches[0]


def load_workflow(root: Path, path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise ValueError("PyYAML is required to validate workflow structure") from exc
    try:
        source = read(root, path)
        if len(source.encode("utf-8")) > MAX_WORKFLOW_YAML_BYTES:
            raise ValueError(f"{path}: workflow exceeds {MAX_WORKFLOW_YAML_BYTES} bytes")
    except OSError as exc:
        raise ValueError(f"{path}: cannot scan workflow YAML: {exc}") from exc

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader: Any, node: Any, deep: bool = False) -> dict[Any, Any]:
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in result
            except TypeError as exc:
                raise ValueError(f"{path}: unhashable YAML key") from exc
            if duplicate:
                raise ValueError(f"{path}: duplicate YAML key {key!r}")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    try:
        value = yaml.load(source, Loader=UniqueKeyLoader)
    except (yaml.YAMLError, TypeError, ValueError) as exc:
        raise ValueError(f"{path}: malformed workflow YAML: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("jobs"), dict):
        raise ValueError(f"{path}: workflow must contain a jobs mapping")
    return value


def strings(value: Any, trail: tuple[Any, ...] = ()) -> Iterator[tuple[tuple[Any, ...], str]]:
    if isinstance(value, str):
        yield trail, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from strings(item, trail + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from strings(item, trail + (index,))


def selected_version(root: Path) -> str:
    text = read(root, BUILDER)
    active = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    assignments = [
        line for line in active
        if re.match(r"^(?:(?:export|readonly|declare|typeset)(?:\s+-[A-Za-z]+)*\s+)?OPENSSL_VERSION\s*=", line)
    ]
    if len(assignments) != 1:
        raise ValueError(f"builder default: expected one active assignment, found {len(assignments)}")
    match = re.fullmatch(rf'OPENSSL_VERSION="\$\{{OPENSSL_VERSION:-({VERSION_RE})\}}"', assignments[0])
    if not match:
        raise ValueError("builder default: unsupported or dynamic assignment")
    first_function = next(
        (index for index, line in enumerate(active) if re.match(r"^(?:function\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*\(\s*\))?|[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\))\s*(?:\{|$)", line)),
        len(active),
    )
    if active.index(assignments[0]) >= first_function:
        raise ValueError("builder default: authority must be in the preamble")
    return match.group(1)


def check_checksum(root: Path, version: str) -> list[str]:
    lines = [
        line for line in read(root, "scripts/crypto/openssl/source-checksums.sha256").splitlines()
        if line and not line.startswith("#")
    ]
    malformed = [line for line in lines if not re.fullmatch(rf"[0-9a-f]{{64}}  openssl-{VERSION_RE}\.tar\.gz", line)]
    selected = [line for line in lines if line.endswith(f"  openssl-{version}.tar.gz")]
    errors = ["checksum allowlist contains malformed entries"] if malformed else []
    if len(selected) != 1:
        errors.append(f"selected checksum: expected one entry for {version}, found {len(selected)}")
    return errors


def normalized_if(step: dict[str, Any], label: str) -> str:
    value = step.get("if", "")
    if not isinstance(value, str):
        raise ValueError(f"{label}: if must be absent or a string")
    return value.strip()


def check_workflow_owner(owner: WorkflowOwner, workflow: dict[str, Any], version: str) -> list[str]:
    label = f"{owner.path}:{owner.job}"
    job = workflow["jobs"].get(owner.job)
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        return [f"{label}: missing registered job or steps"]
    steps = job["steps"]
    builder_indexes = [
        index for index, step in enumerate(steps)
        if isinstance(step, dict) and BUILDER in str(step.get("run", ""))
    ]
    if len(builder_indexes) != 1:
        return [f"{label}: expected one registered builder step, found {len(builder_indexes)}"]
    build_index = builder_indexes[0]
    if build_index == 0 or not isinstance(steps[build_index - 1], dict):
        return [f"{label}: registered cache must immediately precede the builder"]
    build, cache = steps[build_index], steps[build_index - 1]
    run = build.get("run")
    if not isinstance(run, str):
        return [f"{label}: builder run must be a string"]
    canonical = f'OPENSSL_VERSION={version} PREFIX="$PREFIX" bash {BUILDER}'
    cache_with = cache.get("with")
    if not isinstance(cache_with, dict):
        return [f"{label}: cache with must be a mapping"]
    minor = ".".join(version.split(".")[:2])
    expected_paths = [
        f"~/.cache/rubin-openssl/bundle-{version}",
        f"~/.cache/rubin-openssl/work/openssl-{version}.tar.gz",
    ]
    expected_key = (
        f"{owner.key_prefix}-${{{{ runner.os }}}}-{version}-{owner.key_revision}-{CHECKSUM_EXPR}"
    )
    open_ssl_caches = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        step_with = step.get("with")
        cache_path = str(step_with.get("path", "")) if isinstance(step_with, dict) else ""
        cache_key = str(step_with.get("key", "")) if isinstance(step_with, dict) else ""
        if (str(step.get("name", "")).startswith("Cache OpenSSL ")
                or "rubin-openssl" in cache_path or cache_key.startswith("openssl-bundle")):
            open_ssl_caches.append(step)
    checks = {
        "single cache": len(open_ssl_caches) == 1 and open_ssl_caches[0] is cache,
        "cache adjacency": steps[build_index - 1] is cache,
        "cache action pin": cache.get("uses") == CACHE_ACTION,
        "matching if": normalized_if(cache, label) == normalized_if(build, label),
        "cache title": cache.get("name") == f"Cache OpenSSL {minor} bundle",
        "build title": build.get("name") == f"Build OpenSSL {version} bundle{owner.title_suffix}",
        "cache paths": [line.strip() for line in str(cache_with.get("path", "")).splitlines() if line.strip()] == expected_paths,
        "cache key": cache_with.get("key") == expected_key,
        "no restore-key fallback": not any(str(key).startswith("restore-key") for key in cache_with),
        "bundle prefix": [line.strip() for line in run.splitlines() if re.match(r'^(?:(?:export|readonly|declare|typeset)(?:\s+-[A-Za-z]+)*\s+)?PREFIX\s*=', line.strip())] == [f'PREFIX="$HOME/.cache/rubin-openssl/bundle-{version}"'],
        "single literal selector": sum(bool(re.match(rf'^(?:(?:export|readonly|declare|typeset)(?:\s+-[A-Za-z]+)*\s+)?OPENSSL_VERSION\s*=\s*["\']?{VERSION_RE}["\']?(?:\s|$)', line.strip())) for line in run.splitlines()) == 1,
        "canonical builder line": run.count(BUILDER) == 1
        and sum(line.strip() == canonical for line in run.splitlines()) == 1,
    }
    return [f"{label}: invalid or missing {name}" for name, ok in checks.items() if not ok]


def check_workflows(root: Path, version: str) -> list[str]:
    errors: list[str] = []
    paths = sorted((root / ".github/workflows").glob("*.y*ml"))
    if len(paths) > MAX_WORKFLOW_FILES:
        return [f"workflow file count exceeds {MAX_WORKFLOW_FILES}"]
    loaded: dict[str, dict[str, Any]] = {}
    for path in paths:
        relative = path.relative_to(root).as_posix()
        try:
            loaded[relative] = load_workflow(root, path)
        except ValueError as exc:
            errors.append(str(exc))
    registry = {(owner.path, owner.job): owner for owner in WORKFLOW_OWNERS}
    if len(registry) != len(WORKFLOW_OWNERS):
        errors.append("workflow registry contains duplicate identifiers")
    allowed_trails: dict[tuple[str, str], tuple[Any, ...]] = {}
    for owner in WORKFLOW_OWNERS:
        workflow = loaded.get(owner.path)
        if workflow is None:
            errors.append(f"{owner.path}:{owner.job}: missing registered workflow")
        else:
            try:
                errors.extend(check_workflow_owner(owner, workflow, version))
                job = workflow["jobs"].get(owner.job)
                if isinstance(job, dict) and isinstance(job.get("steps"), list):
                    indexes = [i for i, step in enumerate(job["steps"]) if isinstance(step, dict) and BUILDER in str(step.get("run", ""))]
                    if len(indexes) == 1:
                        allowed_trails[(owner.path, owner.job)] = ("jobs", owner.job, "steps", indexes[0], "run")
            except ValueError as exc:
                errors.append(str(exc))
    for relative, workflow in loaded.items():
        for trail, value in strings(workflow):
            if BUILDER not in value:
                continue
            job = trail[1] if len(trail) > 1 and trail[0] == "jobs" else None
            if trail != allowed_trails.get((relative, job)):
                errors.append(f"{relative}:{job or '<workflow>'}: unregistered literal builder owner")
    return errors


def module_versions(root: Path, path: Path) -> list[str]:
    try:
        tree = ast.parse(read(root, path), filename=str(path))
    except SyntaxError as exc:
        raise ValueError(f"{path}: cannot parse Python owner module: {exc}") from exc
    values: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if any(isinstance(target, ast.Name) and target.id == "VERSION" for target in targets):
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    values.append(value.value)
                else:
                    values.append("<dynamic>")
    return values


def check_non_workflow_owners(root: Path, version: str) -> list[str]:
    errors: list[str] = []
    owners = (
        ("README command", "scripts/crypto/openssl/README.md", rf"^OPENSSL_VERSION=({VERSION_RE}) scripts/dev-env\.sh -- bash {re.escape(BUILDER)}$", version),
        ("dev-env example", "scripts/dev-env.sh", rf'^\s*#\s+RUBIN_OPENSSL_PREFIX="\$HOME/\.cache/rubin-openssl/bundle-({VERSION_RE})" scripts/dev-env\.sh -- openssl version -a$', version),
        ("speed benchmark", "scripts/crypto/openssl/bench-pq-speed.py", rf'default=str\(Path\.home\(\) / "\.cache" / "rubin-openssl" / "bundle-({VERSION_RE})" / "bin" / "openssl"\)', version),
        ("pkeyutl benchmark", "scripts/crypto/openssl/bench-pq-pkeyutl.py", rf'default=str\(Path\.home\(\) / "\.cache" / "rubin-openssl" / "bundle-({VERSION_RE})" / "bin" / "openssl"\)', version),
        ("bundle contract", "tools/tests/test_openssl_bundle_contract.py", rf'^VERSION = "({VERSION_RE})"$', version),
    )
    for label, relative, pattern, wanted in owners:
        try:
            found = one_match(read(root, relative), pattern, label)
            if found != wanted:
                errors.append(f"{label}: owner selects {found}, expected {wanted}")
        except ValueError as exc:
            errors.append(str(exc))
    contract = read(root, "tools/tests/test_openssl_bundle_contract.py")
    pin_owner = r'^\s*self\.assertIn\(f"\{PUBLISHED_SHA256\}  openssl-\{VERSION\}\.tar\.gz",\n\s*CHECKSUM_PATH\.read_text\(encoding="utf-8"\)\)$'
    if len(re.findall(pin_owner, contract, re.MULTILINE)) != 1:
        errors.append("bundle contract: selected pin binding is missing or ambiguous")
    runbook = read(root, "scripts/crypto/openssl/CVE_RESPONSE_RUNBOOK.md")
    escaped = re.escape(version)
    checks = {
        "runbook selector grep": re.findall(r"`git grep -n 'OPENSSL_VERSION=([^']+)'`", runbook) == [escaped],
        "runbook cache grep": re.findall(r"`git grep -nE 'bundle-([^|']+)\|openssl-([^|']+)\\\.tar\\\.gz\|([^|']+)-v\[0-9\]' -- \.github/workflows`", runbook) == [(escaped, escaped, escaped)],
        "runbook final grep": re.findall(r"also inspect\s+`git grep -n '([^']+)'`", runbook) == [escaped],
        "runbook PyYAML prerequisite": "python3 -m pip install 'PyYAML==6.0.3'" in runbook,
        "runbook checker command": len(re.findall(r"^\s*`python3 tools/check_openssl_version_consistency\.py --repo-root \.` checks the$", runbook, re.MULTILINE)) == 1,
        "runbook checker guarantee": bool(re.search(r"checks the\s+finite registered OpenSSL literal-owner topology", runbook)),
        "dev-env registry closure": re.findall(r'RUBIN_OPENSSL_PREFIX="\$HOME/\.cache/rubin-openssl/bundle-(' + VERSION_RE + r')"', read(root, "scripts/dev-env.sh")) == [version],
    }
    errors.extend(name for name, ok in checks.items() if not ok)

    expected_families = {
        "markdown builder": {"scripts/crypto/openssl/README.md"},
        "benchmark default": {
            "scripts/crypto/openssl/bench-pq-speed.py",
            "scripts/crypto/openssl/bench-pq-pkeyutl.py",
        },
        "bundle-test VERSION": {"tools/tests/test_openssl_bundle_contract.py"},
    }
    discovered = {name: set() for name in expected_families}
    for path in sorted((root / "scripts/crypto/openssl").glob("*.md")):
        if re.search(rf"OPENSSL_VERSION={VERSION_RE}[^\n]*{re.escape(BUILDER)}", read(root, path)):
            discovered["markdown builder"].add(path.relative_to(root).as_posix())
    for path in sorted((root / "scripts/crypto/openssl").glob("bench-pq-*.py")):
        if re.search(rf'["\']bundle-{VERSION_RE}["\'] / ["\']bin["\'] / ["\']openssl["\']', read(root, path)):
            discovered["benchmark default"].add(path.relative_to(root).as_posix())
    for path in sorted((root / "tools/tests").glob("test_openssl_bundle*.py")):
        if module_versions(root, path):
            discovered["bundle-test VERSION"].add(path.relative_to(root).as_posix())
    for name, expected in expected_families.items():
        if discovered[name] != expected:
            errors.append(f"{name}: registry closure mismatch: {sorted(discovered[name])}")
    return errors


def check_repo(root: Path) -> list[str]:
    try:
        root = root.resolve()
        version = selected_version(root)
        errors = check_checksum(root, version)
        errors.extend(check_workflows(root, version))
        errors.extend(check_non_workflow_owners(root, version))
        return sorted(set(errors))
    except ValueError as exc:
        return [str(exc)]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args(argv[1:])
    errors = check_repo(args.repo_root.resolve())
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: registered OpenSSL literal owners are consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

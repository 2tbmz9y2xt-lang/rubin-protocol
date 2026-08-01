#!/usr/bin/env python3
"""Fail closed when active OpenSSL bundle sites disagree on the selected version."""
from __future__ import annotations

import argparse
import re
import shlex
import sys
from pathlib import Path
from typing import Any

VERSION_RE = r"[0-9]+\.[0-9]+\.[0-9]+"
CHECKSUM_EXPR = "${{ hashFiles('scripts/crypto/openssl/source-checksums.sha256') }}"
BUILDER = "scripts/crypto/openssl/build-openssl-bundle.sh"
MAX_WORKFLOW_YAML_BYTES = 2 * 1024 * 1024
MAX_WORKFLOW_FILES = 64


def read(path: Path) -> str:
    try:
        if not path.is_file():
            raise ValueError(f"missing file: {path}")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc


def one_match(text: str, pattern: str, label: str) -> str:
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"{label}: expected exactly one literal match, found {len(matches)}")
    return matches[0]


def load_workflow(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise ValueError("PyYAML is required to validate workflow structure") from exc
    try:
        if path.stat().st_size > MAX_WORKFLOW_YAML_BYTES:
            raise ValueError(f"{path}: workflow exceeds {MAX_WORKFLOW_YAML_BYTES} bytes")
        source = read(path)
    except (OSError, UnicodeError, yaml.YAMLError, TypeError) as exc:
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
    except (yaml.YAMLError, TypeError) as exc:
        raise ValueError(f"{path}: malformed workflow YAML: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("jobs"), dict):
        raise ValueError(f"{path}: workflow must contain a jobs mapping")
    return value


def shell_lines(run: str) -> list[str]:
    """Remove only paired, simple heredoc bodies; leave shell tokenization to shlex."""
    result: list[str] = []
    delimiter: str | None = None
    for line in run.splitlines():
        if delimiter is not None:
            if line.strip() == delimiter:
                delimiter = None
            continue
        result.append(line)
        match = re.search(r"(?<!<)<<(?!=)-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1(?:\s|$)", line)
        if match:
            delimiter = match.group(2)
    if delimiter is not None:
        raise ValueError("unterminated supported heredoc")
    return result


def builder_occurrences(run: str) -> int:
    count = 0
    for line in shell_lines(run):
        if "build-openssl-" not in line:
            continue
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
            lexer.whitespace_split = True
            lexer.commenters = "#"
            tokens = list(lexer)
        except ValueError as exc:
            raise ValueError(f"unsupported shell quoting: {exc}") from exc
        segment_start = 0
        for index, token in enumerate(tokens):
            if token and all(char in ";&|()" for char in token):
                segment_start = index + 1
            elif token == BUILDER or token.endswith("/" + BUILDER):
                segment = tokens[segment_start:index]
                command = next((item for item in segment if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", item)), "")
                if command not in ("echo", "printf"):
                    count += 1
    return count


def check_workflows(root: Path, version: str) -> tuple[list[str], int]:
    errors: list[str] = []
    site_count = 0
    minor = ".".join(version.split(".")[:2])
    paths = sorted((root / ".github/workflows").glob("*.y*ml"))
    if len(paths) > MAX_WORKFLOW_FILES:
        return [f"workflow file count exceeds {MAX_WORKFLOW_FILES}"], 0
    for path in paths:
        try:
            workflow = load_workflow(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        for job_name, job in workflow["jobs"].items():
            if not isinstance(job, dict) or not isinstance(job.get("steps", []), list):
                errors.append(f"{path}:{job_name}: steps must be a list")
                continue
            pending_caches: list[tuple[int, dict[str, Any]]] = []
            for index, step in enumerate(job.get("steps", [])):
                if not isinstance(step, dict):
                    errors.append(f"{path}:{job_name}: step {index} must be a mapping")
                    continue
                cache_with = step.get("with")
                cache_name_field = str(step.get("name", ""))
                cache_path_field = str(cache_with.get("path", "")) if isinstance(cache_with, dict) else ""
                cache_key_field = str(cache_with.get("key", "")) if isinstance(cache_with, dict) else ""
                if str(step.get("uses", "")).startswith("actions/cache@") and (
                    cache_name_field.startswith("Cache OpenSSL ") or "rubin-openssl" in cache_path_field
                    or "openssl-bundle-" in cache_key_field
                ):
                    pending_caches.append((index, step))
                run = str(step.get("run", ""))
                try:
                    occurrences = builder_occurrences(run)
                except ValueError as exc:
                    errors.append(f"{path}:{job_name}:step {index}: {exc}")
                    continue
                calls = re.findall(
                    rf"(?m)^\s*OPENSSL_VERSION=({VERSION_RE}) PREFIX=\"\$PREFIX\" bash {re.escape(BUILDER)}\s*$",
                    run,
                )
                if not occurrences:
                    continue
                label = f"{path}:{job_name}:step {index}"
                if occurrences != len(calls):
                    errors.append(f"{label}: unsupported builder invocation")
                    continue
                site_count += len(calls)
                if len(calls) != 1 or len(pending_caches) != 1:
                    errors.append(f"{label}: ambiguous or missing associated OpenSSL cache")
                    pending_caches.clear()
                    continue
                _, cache = pending_caches.pop()
                pending_caches.clear()
                cache_with = cache.get("with")
                if not isinstance(cache_with, dict):
                    errors.append(f"{label}: cache with must be a mapping")
                    continue
                cache_name = str(cache.get("name", ""))
                build_name = str(step.get("name", ""))
                paths = str(cache_with.get("path", ""))
                key = str(cache_with.get("key", ""))
                selector = calls[0]
                prefixes = re.findall(rf'(?m)^\s*PREFIX="\$HOME/\.cache/rubin-openssl/bundle-({VERSION_RE})"\s*$', run)
                cache_title = re.fullmatch(rf"Cache OpenSSL ([0-9]+\.[0-9]+) bundle", cache_name)
                build_title = re.fullmatch(rf"Build OpenSSL ({VERSION_RE}) bundle(?: \(PQC-enabled\))?", build_name)
                cache_path_lines = [line.strip() for line in paths.splitlines() if line.strip()]
                key_versions = re.findall(rf"-({VERSION_RE})-v[0-9]+-", key)
                checks = {
                    "cache title": bool(cache_title and cache_title.group(1) == minor),
                    "build title": bool(build_title and build_title.group(1) == version),
                    "literal selector": selector == version,
                    "bundle prefix": prefixes == [version],
                    "cache paths": cache_path_lines == [f"~/.cache/rubin-openssl/bundle-{version}", f"~/.cache/rubin-openssl/work/openssl-{version}.tar.gz"],
                    "cache key": key_versions == [version] and all(item == version for item in re.findall(VERSION_RE, key)) and "openssl-bundle-" in key,
                    "checksum hashFiles": key.count(CHECKSUM_EXPR) == 1,
                    "no restore-key fallback": not any(str(k).startswith("restore-key") for k in cache_with),
                }
                for name, ok in checks.items():
                    if not ok:
                        errors.append(f"{label}: invalid or missing {name}")
            for cache_index, _ in pending_caches:
                errors.append(f"{path}:{job_name}:step {cache_index}: orphan OpenSSL cache")
    if site_count == 0:
        errors.append("no active workflow OpenSSL builder sites found")
    return errors, site_count


def check_repo(root: Path) -> list[str]:
    errors: list[str] = []
    try:
        builder = read(root / "scripts/crypto/openssl/build-openssl-bundle.sh")
        active = [(index, line) for index, line in enumerate(builder.splitlines()) if line.strip() and not line.lstrip().startswith("#")]
        owners = [(index, line) for index, line in active if "OPENSSL_VERSION=" in line]
        functions = [index for index, line in active if re.match(r"^\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_]*(?:\(\))?\s*\{", line)]
        if len(owners) != 1 or (functions and owners[0][0] > functions[0]):
            raise ValueError("builder default: expected one active authority before functions")
        version = one_match(owners[0][1], rf'^OPENSSL_VERSION="\$\{{OPENSSL_VERSION:-({VERSION_RE})\}}"$', "builder default")
    except ValueError as exc:
        return [str(exc)]

    checksum_lines = [
        line for line in read(root / "scripts/crypto/openssl/source-checksums.sha256").splitlines()
        if line and not line.startswith("#")
    ]
    malformed = [line for line in checksum_lines if not re.fullmatch(rf"[0-9a-f]{{64}}  openssl-{VERSION_RE}\.tar\.gz", line)]
    selected = [line for line in checksum_lines if line.endswith(f"  openssl-{version}.tar.gz")]
    if malformed:
        errors.append("checksum allowlist contains malformed active entries")
    if len(selected) != 1:
        errors.append(f"selected checksum: expected one entry for {version}, found {len(selected)}")

    workflow_errors, _ = check_workflows(root, version)
    errors.extend(workflow_errors)
    minor = ".".join(version.split(".")[:2])
    owned = {
        "README": (root / "scripts/crypto/openssl/README.md", rf"(?m)^OPENSSL_VERSION=({VERSION_RE}) scripts/dev-env\.sh -- bash {re.escape(BUILDER)}$", version),
        "README heading": (root / "scripts/crypto/openssl/README.md", r"(?m)^## Build local bundle \(OpenSSL ([0-9]+\.[0-9]+)\+\)$", minor),
        "dev-env example": (root / "scripts/dev-env.sh", rf'(?m)^\s*#\s+RUBIN_OPENSSL_PREFIX="\$HOME/\.cache/rubin-openssl/bundle-({VERSION_RE})" scripts/dev-env\.sh -- openssl version -a$', version),
        "speed benchmark": (root / "scripts/crypto/openssl/bench-pq-speed.py", rf'default=str\(Path\.home\(\) / "\.cache" / "rubin-openssl" / "bundle-({VERSION_RE})" / "bin" / "openssl"\)', version),
        "pkeyutl benchmark": (root / "scripts/crypto/openssl/bench-pq-pkeyutl.py", rf'default=str\(Path\.home\(\) / "\.cache" / "rubin-openssl" / "bundle-({VERSION_RE})" / "bin" / "openssl"\)', version),
        "bundle contract": (root / "tools/tests/test_openssl_bundle_contract.py", rf'(?m)^VERSION = "({VERSION_RE})"$', version),
    }
    for label, (path, pattern, wanted) in owned.items():
        try:
            found = one_match(read(path), pattern, label)
            if found != wanted:
                errors.append(f"{label}: owner selects {found}, expected {wanted}")
        except ValueError as exc:
            errors.append(str(exc))
    runbook = read(root / "scripts/crypto/openssl/CVE_RESPONSE_RUNBOOK.md")
    escaped = version.replace(".", r"\.")
    try:
        if escaped != one_match(runbook, r"(?m)^\s*`git grep -n 'OPENSSL_VERSION=([^']+)'`,$", "runbook selector grep"):
            errors.append("runbook selector grep is stale")
    except ValueError as exc:
        errors.append(str(exc))
    cache_pattern = r"(?m)^\s*`git grep -nE 'bundle-([^|']+)\|openssl-([^|']+)\\\.tar\\\.gz\|([^|']+)-v\[0-9\]' -- \.github/workflows`\.$"
    if re.findall(cache_pattern, runbook) != [(escaped, escaped, escaped)]:
        errors.append("runbook cache grep is stale or ambiguous")
    if re.findall(r"(?m)^\s*completeness; also inspect `git grep -n '([^']+)'` and$", runbook) != [escaped]:
        errors.append("runbook final grep is stale or ambiguous")
    if not re.search(r"`python3 tools/check_openssl_version_consistency\.py --repo-root \.` enforces bump\s+completeness", runbook):
        errors.append("runbook checker guard statement is missing")
    contract = read(root / "tools/tests/test_openssl_bundle_contract.py")
    pin_owner = r'(?m)^\s*self\.assertIn\(f"\{PUBLISHED_SHA256\}  openssl-\{VERSION\}\.tar\.gz",\n\s*CHECKSUM_PATH\.read_text\(encoding="utf-8"\)\)$'
    if len(re.findall(pin_owner, contract)) != 1:
        errors.append("bundle contract: selected pin binding is missing or ambiguous")
    return errors


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args(argv[1:])
    try:
        errors = check_repo(args.repo_root.resolve())
    except ValueError as exc:
        errors = [str(exc)]
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print("OK: active OpenSSL version sites are complete and consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

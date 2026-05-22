#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import stat
import sys
from pathlib import Path

CLAIMED_PRESENT_STATUSES = {"present", "covered", "complete"}
KNOWN_ABSENT_STATUSES = {"absent", "deferred", "not_claimed", "not-applicable", "not_applicable"}
GO_TEST_FUNC_RE = re.compile(
    r"(?m)^func\s+(Test[A-Za-z0-9_]*)\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"
    r"\*([A-Za-z_][A-Za-z0-9_]*)\.T\s*\)\s*\{"
)
GO_IMPORT_BLOCK_RE = re.compile(r"^import\s*\(\s*$")
GO_IMPORT_SPEC_RE = re.compile(r'^(?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*|\.)\s+)?"testing"\s*$')
GO_SINGLE_IMPORT_RE = re.compile(r'^import\s+(?:(?P<alias>[A-Za-z_][A-Za-z0-9_]*|\.)\s+)?"testing"\s*$')
RUST_ATTR_RE = re.compile(r"^#\s*\[[^\]]+\]\s*$")
RUST_TEST_ATTR_RE = re.compile(r"^#\s*\[\s*test\s*\]\s*$")
RUST_CFG_ATTR_RE = re.compile(r"^#\s*\[\s*cfg\s*\(")
RUST_CFG_TEST_ATTR_RE = re.compile(r"^#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*$")
RUST_IGNORE_ATTR_RE = re.compile(r"^#\s*\[\s*ignore(?:\s*(?:\([^]]*\)|=[^]]+))?\s*\]\s*$")
RUST_CFG_ATTR_IGNORE_RE = re.compile(r"^#\s*\[\s*cfg_attr\s*\([^]]*\bignore\b")
RUST_FN_RE = re.compile(
    r"^(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:const\s+)*"
    r'(?:extern\s+(?:"[^"]+"\s+)?)?'
    r"(?:const\s+)*"
    r"fn\s+((?:r#)?[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)\s*(?P<tail>.*)$"
)
RUST_EXTERNAL_MOD_RE = re.compile(r"(?m)^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
RUST_INLINE_MOD_RE = re.compile(r"^(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\b")
RUST_NON_MODULE_SCOPE_RE = re.compile(
    r"^(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:(?:const|async|unsafe)\s+)*"
    r'(?:extern\s+(?:"[^"]+"\s+)?)?'
    r"(?:(?:const|async|unsafe)\s+)*"
    r"(?:fn|impl|trait|struct|enum|union)\b"
)
GO_KNOWN_GOOS = {
    "aix",
    "android",
    "darwin",
    "dragonfly",
    "freebsd",
    "hurd",
    "illumos",
    "ios",
    "js",
    "linux",
    "netbsd",
    "openbsd",
    "plan9",
    "solaris",
    "wasip1",
    "windows",
}
GO_KNOWN_GOARCH = {
    "386",
    "amd64",
    "amd64p32",
    "arm",
    "arm64",
    "arm64be",
    "loong64",
    "mips",
    "mips64",
    "mips64le",
    "mips64p32",
    "mips64p32le",
    "mipsle",
    "ppc",
    "ppc64",
    "ppc64le",
    "riscv",
    "riscv64",
    "s390",
    "s390x",
    "sparc",
    "sparc64",
    "wasm",
}


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


def relative_source_path(value: object, *, field_name: str) -> tuple[Path, str | None]:
    if not isinstance(value, str) or not value.strip():
        return Path(), f"{field_name} must be non-empty string"
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        return Path(), f"{field_name} must be relative and must not contain '..'"
    return path, None


def safe_regular_file_error(repo_root: Path, path: Path) -> str | None:
    try:
        file_stat = path.lstat()
    except OSError as exc:
        return f"could not stat {path.relative_to(repo_root)}: {exc}"
    if stat.S_ISLNK(file_stat.st_mode):
        return f"{path.relative_to(repo_root)} must not be a symlink"
    if not stat.S_ISREG(file_stat.st_mode):
        return f"{path.relative_to(repo_root)} must be a regular file"
    try:
        path.resolve(strict=True).relative_to(repo_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        return f"{path.relative_to(repo_root)} must resolve inside repo root: {exc}"
    return None


def mask_non_code(source: str, *, language: str) -> str:
    out: list[str] = []
    i = 0
    n = len(source)
    block_depth = 0
    state = "code"
    raw_hashes = 0

    def put_space(ch: str) -> None:
        out.append("\n" if ch == "\n" else " ")

    def rust_char_literal_end(start: int) -> int | None:
        if source.startswith("b'", start):
            quote = start + 1
        elif source[start] == "'":
            quote = start
        else:
            return None

        j = quote + 1
        if j >= n:
            return None
        if source[j] == "\\":
            j += 1
            if j >= n:
                return None
            if source[j] == "u" and j + 1 < n and source[j + 1] == "{":
                j += 2
                while j < n and source[j] != "}":
                    j += 1
                if j >= n:
                    return None
                j += 1
            elif source[j] == "x":
                j += 3
            else:
                j += 1
        else:
            j += 1
        if j < n and source[j] == "'":
            return j + 1
        return None

    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if state == "line_comment":
            put_space(ch)
            if ch == "\n":
                state = "code"
            i += 1
            continue

        if state == "block_comment":
            if language == "rust" and ch == "/" and nxt == "*":
                put_space(ch)
                put_space(nxt)
                block_depth += 1
                i += 2
                continue
            if ch == "*" and nxt == "/":
                put_space(ch)
                put_space(nxt)
                block_depth -= 1
                i += 2
                if block_depth == 0:
                    state = "code"
                continue
            put_space(ch)
            i += 1
            continue

        if state == "double_string":
            put_space(ch)
            if ch == "\\" and i + 1 < n:
                put_space(source[i + 1])
                i += 2
                continue
            if ch == '"':
                state = "code"
            i += 1
            continue

        if state == "single_string":
            put_space(ch)
            if ch == "\\" and i + 1 < n:
                put_space(source[i + 1])
                i += 2
                continue
            if ch == "'":
                state = "code"
            i += 1
            continue

        if state == "go_raw_string":
            put_space(ch)
            if ch == "`":
                state = "code"
            i += 1
            continue

        if state == "rust_raw_string":
            put_space(ch)
            if ch == '"' and source.startswith("#" * raw_hashes, i + 1):
                for j in range(raw_hashes):
                    put_space(source[i + 1 + j])
                i += raw_hashes + 2
                state = "code"
                continue
            i += 1
            continue

        if ch == "/" and nxt == "/":
            put_space(ch)
            put_space(nxt)
            state = "line_comment"
            i += 2
            continue
        if ch == "/" and nxt == "*":
            put_space(ch)
            put_space(nxt)
            state = "block_comment"
            block_depth = 1
            i += 2
            continue
        if language == "go" and ch == "`":
            put_space(ch)
            state = "go_raw_string"
            i += 1
            continue
        if language == "rust" and ch == "r":
            j = i + 1
            while j < n and source[j] == "#":
                j += 1
            if j < n and source[j] == '"':
                for k in range(i, j + 1):
                    put_space(source[k])
                raw_hashes = j - i - 1
                state = "rust_raw_string"
                i = j + 1
                continue
        if ch == '"':
            put_space(ch)
            state = "double_string"
            i += 1
            continue
        if language == "rust":
            literal_end = rust_char_literal_end(i)
            if literal_end is not None:
                for k in range(i, literal_end):
                    put_space(source[k])
                i = literal_end
                continue
        if language == "go" and ch == "'":
            put_space(ch)
            state = "single_string"
            i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def go_file_has_build_constraints(source: str) -> bool:
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if line.startswith("package "):
            return False
        if line.startswith("//go:build") or line.startswith("// +build"):
            return True
    return False


def go_file_has_platform_suffix(path: Path) -> bool:
    stem = path.name.removesuffix("_test.go").removesuffix(".go")
    suffixes = stem.split("_")[1:]
    if not suffixes:
        return False
    last = suffixes[-1]
    if last in GO_KNOWN_GOARCH:
        return True
    if last in GO_KNOWN_GOOS:
        return True
    return len(suffixes) >= 2 and suffixes[-2] in GO_KNOWN_GOOS and suffixes[-1] in GO_KNOWN_GOARCH


def go_test_source_reachability_error(rel_path: Path) -> str | None:
    if rel_path.parts[:2] != ("clients", "go"):
        return f"{rel_path} is not under clients/go"
    if any(part == "testdata" or part.startswith(("_", ".")) for part in rel_path.parts):
        return f"{rel_path} is in a Go-ignored directory or file"
    if go_file_has_platform_suffix(rel_path):
        return f"{rel_path} has a platform-specific Go suffix"
    return None


def go_testing_import_names(source: str) -> set[str]:
    names: set[str] = set()
    block_comment = False
    in_import_block = False

    def strip_comments(line: str) -> str:
        nonlocal block_comment
        out: list[str] = []
        i = 0
        while i < len(line):
            if block_comment:
                end = line.find("*/", i)
                if end == -1:
                    return "".join(out)
                i = end + 2
                block_comment = False
                continue
            if line.startswith("//", i):
                break
            if line.startswith("/*", i):
                block_comment = True
                i += 2
                continue
            if line[i] == '"':
                out.append(line[i])
                i += 1
                while i < len(line):
                    out.append(line[i])
                    if line[i] == "\\" and i + 1 < len(line):
                        i += 1
                        out.append(line[i])
                    elif line[i] == '"':
                        i += 1
                        break
                    i += 1
                continue
            out.append(line[i])
            i += 1
        return "".join(out)

    def add_import_match(match: re.Match[str]) -> None:
        alias = match.group("alias")
        if alias and alias not in {".", "_"}:
            names.add(alias)
        elif alias is None:
            names.add("testing")

    for raw_line in source.splitlines():
        line = strip_comments(raw_line).strip()
        if not line:
            continue
        if in_import_block:
            if line == ")":
                in_import_block = False
                continue
            match = GO_IMPORT_SPEC_RE.match(line)
            if match:
                add_import_match(match)
            continue
        match = GO_SINGLE_IMPORT_RE.match(line)
        if match:
            add_import_match(match)
            continue
        if GO_IMPORT_BLOCK_RE.match(line):
            in_import_block = True
            continue
        if line.startswith("import "):
            continue
        if line.startswith("package "):
            continue
        break
    return names


def rust_logical_lines(source: str) -> list[str]:
    logical: list[str] = []
    pending_attr: list[str] = []
    bracket_depth = 0
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if pending_attr:
            pending_attr.append(line)
            bracket_depth += line.count("[") - line.count("]")
            if bracket_depth <= 0:
                logical.append(" ".join(pending_attr))
                pending_attr = []
                bracket_depth = 0
            continue
        if line.startswith("#["):
            pending_attr = [line]
            bracket_depth = line.count("[") - line.count("]")
            if bracket_depth <= 0:
                logical.append(line)
                pending_attr = []
                bracket_depth = 0
            continue
        logical.append(line)
    if pending_attr:
        logical.append(" ".join(pending_attr))
    return logical


def rust_attrs_have_disabled_cfg(attrs: list[str]) -> bool:
    return any(RUST_CFG_ATTR_RE.match(attr) and not RUST_CFG_TEST_ATTR_RE.match(attr) for attr in attrs)


def rust_attrs_disable_runtime_test(attrs: list[str]) -> bool:
    return rust_attrs_have_disabled_cfg(attrs) or any(
        RUST_IGNORE_ATTR_RE.match(attr) or RUST_CFG_ATTR_IGNORE_RE.match(attr) for attr in attrs
    )


def rust_brace_delta(line: str) -> int:
    return line.count("{") - line.count("}")


def rust_line_opens_scope(line: str) -> bool:
    return "{" in line and rust_brace_delta(line) > 0


def rust_scope_kind(line: str) -> str | None:
    if RUST_EXTERNAL_MOD_RE.match(line):
        return None
    if RUST_INLINE_MOD_RE.match(line):
        return "module"
    if RUST_NON_MODULE_SCOPE_RE.match(line):
        return "non_module"
    return None


def rust_declared_external_modules(source: str) -> set[str]:
    masked = mask_non_code(source, language="rust")
    modules: set[str] = set()
    attrs: list[str] = []
    brace_depth = 0
    for line in rust_logical_lines(masked):
        if brace_depth < 0:
            brace_depth = 0
        if not line:
            continue
        if RUST_ATTR_RE.match(line):
            attrs.append(line)
            continue
        match = RUST_EXTERNAL_MOD_RE.match(line)
        if match and brace_depth == 0 and not rust_attrs_have_disabled_cfg(attrs):
            modules.add(match.group(1))
        brace_depth += rust_brace_delta(line)
        attrs = []
    return modules


def rust_module_file_for(parent: Path, module_name: str) -> Path | None:
    flat = parent / f"{module_name}.rs"
    nested = parent / module_name / "mod.rs"
    if flat.exists():
        return flat
    if nested.exists():
        return nested
    return None


def rust_source_reachability_error(repo_root: Path, rel_path: Path) -> str | None:
    parts = rel_path.parts
    if len(parts) < 6 or parts[:3] != ("clients", "rust", "crates"):
        return f"{rel_path} is not under clients/rust/crates"
    crate_root = repo_root.joinpath(*parts[:4])
    src_root = crate_root / "src"
    try:
        source_rel = repo_root.joinpath(*parts).relative_to(src_root)
    except ValueError:
        return f"{rel_path} is not under a Rust crate src directory"
    if source_rel.name in {"lib.rs", "main.rs"}:
        return None
    lib_rs = src_root / "lib.rs"
    if not lib_rs.exists():
        return f"{rel_path} has no crate lib.rs reachability root"
    regular_error = safe_regular_file_error(repo_root, lib_rs)
    if regular_error is not None:
        return regular_error

    if source_rel.name == "mod.rs":
        module_parts = source_rel.parent.parts
    else:
        module_parts = (*source_rel.parent.parts, source_rel.stem)
    if not module_parts:
        return f"{rel_path} does not map to a Rust module path"

    current_file = lib_rs
    current_dir = src_root
    for index, module_name in enumerate(module_parts):
        regular_error = safe_regular_file_error(repo_root, current_file)
        if regular_error is not None:
            return regular_error
        try:
            current_source = current_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return f"could not read Rust module root {current_file}: {exc}"
        if module_name not in rust_declared_external_modules(current_source):
            return f"{rel_path} is not declared from {current_file.relative_to(repo_root)}"
        next_file = rust_module_file_for(current_dir, module_name)
        if next_file is None:
            return f"{rel_path} module {module_name} has no reachable Rust source file"
        regular_error = safe_regular_file_error(repo_root, next_file)
        if regular_error is not None:
            return regular_error
        if index == len(module_parts) - 1:
            if next_file.resolve() != repo_root.joinpath(*parts).resolve():
                return f"{rel_path} maps to {next_file.relative_to(repo_root)} instead"
            return None
        current_file = next_file
        current_dir = next_file.parent if next_file.name == "mod.rs" else next_file.with_suffix("")
    return None


def runtime_source_reachability_error(repo_root: Path, rel_path: Path) -> str | None:
    if rel_path.suffix == ".go":
        return go_test_source_reachability_error(rel_path)
    if rel_path.suffix == ".rs":
        return rust_source_reachability_error(repo_root, rel_path)
    return None


def rust_test_signature_is_executable(match: re.Match[str]) -> bool:
    if match.group("params").strip():
        return False
    tail = match.group("tail").strip()
    if tail.startswith("{"):
        return True
    if not tail.startswith("->"):
        return False
    return_type, _, after_return = tail[2:].partition("{")
    if not after_return:
        return False
    return_type = return_type.strip()
    if return_type == "()":
        return True
    result_match = re.fullmatch(r"(?:(?:std|core)::result::)?Result\s*<(?P<ok>[^,<>]+),\s*.+>", return_type)
    return bool(result_match and result_match.group("ok").strip() == "()")


def rust_test_names(source: str) -> set[str]:
    names: set[str] = set()
    attrs: list[str] = []
    disabled_cfg_depths: list[int] = []
    non_module_depths: list[int] = []
    pending_scope_kind: str | None = None
    pending_scope_disabled = False
    brace_depth = 0
    for line in rust_logical_lines(source):
        if disabled_cfg_depths:
            disabled_cfg_depths = [depth for depth in disabled_cfg_depths if brace_depth >= depth]
        if non_module_depths:
            non_module_depths = [depth for depth in non_module_depths if brace_depth >= depth]
        if not line:
            continue
        if RUST_ATTR_RE.match(line):
            attrs.append(line)
            continue
        if pending_scope_kind is not None and "{" in line:
            scope_depth = brace_depth + 1
            if pending_scope_disabled:
                disabled_cfg_depths.append(scope_depth)
            if pending_scope_kind == "non_module":
                non_module_depths.append(scope_depth)
            pending_scope_kind = None
            pending_scope_disabled = False

        current_disabled = bool(disabled_cfg_depths)
        current_non_module = bool(non_module_depths)
        attrs_have_disabled_cfg = rust_attrs_have_disabled_cfg(attrs)
        match = RUST_FN_RE.match(line)
        if match:
            has_direct_test_attr = any(RUST_TEST_ATTR_RE.match(attr) for attr in attrs)
            if (
                has_direct_test_attr
                and rust_test_signature_is_executable(match)
                and not current_disabled
                and not current_non_module
                and not rust_attrs_disable_runtime_test(attrs)
            ):
                names.add(match.group(1))
            if rust_line_opens_scope(line):
                scope_depth = brace_depth + 1
                if attrs_have_disabled_cfg:
                    disabled_cfg_depths.append(scope_depth)
                non_module_depths.append(scope_depth)
            elif "{" not in line and rust_scope_kind(line) == "non_module" and not line.rstrip().endswith(";"):
                pending_scope_kind = "non_module"
                pending_scope_disabled = attrs_have_disabled_cfg
            brace_depth += rust_brace_delta(line)
            attrs = []
            continue

        scope_kind = rust_scope_kind(line)
        if scope_kind is not None:
            if rust_line_opens_scope(line):
                scope_depth = brace_depth + 1
                if attrs_have_disabled_cfg:
                    disabled_cfg_depths.append(scope_depth)
                if scope_kind == "non_module":
                    non_module_depths.append(scope_depth)
            elif "{" not in line and not line.rstrip().endswith(";"):
                pending_scope_kind = scope_kind
                pending_scope_disabled = attrs_have_disabled_cfg

        brace_depth += rust_brace_delta(line)
        attrs = []
    return names


def source_test_names(path: Path) -> tuple[set[str], str | None]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return set(), f"could not read {path}: {exc}"
    if path.suffix == ".go":
        if not path.name.endswith("_test.go"):
            return set(), None
        if go_file_has_build_constraints(source):
            return set(), None
        masked = mask_non_code(source, language="go")
        testing_import_names = go_testing_import_names(source)
        return {
            name
            for name, import_name in GO_TEST_FUNC_RE.findall(masked)
            if is_go_test_name(name) and import_name in testing_import_names
        }, None
    if path.suffix == ".rs":
        return rust_test_names(mask_non_code(source, language="rust")), None
    return set(), f"unsupported runtime evidence source extension for {path}"


def is_go_test_name(name: str) -> bool:
    if not name.startswith("Test"):
        return False
    suffix = name[len("Test") :]
    if not suffix:
        return True
    return not suffix[0].islower()


def validate_runtime_evidence(repo_root: Path, domain_name: str, value: object) -> int:
    failures = 0
    if not isinstance(value, dict):
        print(f"ERROR: domain {domain_name}: runtime_evidence must be object", file=sys.stderr)
        return 1

    tests_by_file = value.get("tests_by_file")
    if not isinstance(tests_by_file, dict) or not tests_by_file:
        print(
            f"ERROR: domain {domain_name}: runtime_evidence.tests_by_file must be non-empty object",
            file=sys.stderr,
        )
        return 1

    for raw_path, raw_test_names in tests_by_file.items():
        rel_path, path_error = relative_source_path(
            raw_path,
            field_name=f"domain {domain_name} runtime_evidence.tests_by_file key",
        )
        if path_error is not None:
            print(f"ERROR: {path_error}", file=sys.stderr)
            failures += 1
            continue

        required_tests, tests_error = string_list(
            raw_test_names,
            field_name=f"domain {domain_name} runtime_evidence.tests_by_file[{raw_path}]",
            require_non_empty=True,
        )
        if tests_error is not None:
            print(f"ERROR: {tests_error}", file=sys.stderr)
            failures += 1
            continue

        source_path = repo_root / rel_path
        if not source_path.exists():
            print(f"FAIL: domain {domain_name}: missing runtime evidence source: {raw_path}", file=sys.stderr)
            failures += 1
            continue
        regular_error = safe_regular_file_error(repo_root, source_path)
        if regular_error is not None:
            print(
                f"FAIL: domain {domain_name}: invalid runtime evidence source {raw_path}: {regular_error}",
                file=sys.stderr,
            )
            failures += 1
            continue
        reachability_error = runtime_source_reachability_error(repo_root, rel_path)
        if reachability_error is not None:
            print(
                f"FAIL: domain {domain_name}: unreachable runtime evidence source {raw_path}: {reachability_error}",
                file=sys.stderr,
            )
            failures += 1
            continue

        present_tests, source_error = source_test_names(source_path)
        if source_error is not None:
            print(f"ERROR: domain {domain_name}: {source_error}", file=sys.stderr)
            failures += 1
            continue

        missing_tests = [test_name for test_name in required_tests if test_name not in present_tests]
        if missing_tests:
            print(
                f"FAIL: domain {domain_name}: {raw_path} missing runtime tests: {', '.join(missing_tests)}",
                file=sys.stderr,
            )
            failures += 1

    return failures


def main() -> int:
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
        runtime_evidence = domain.get("runtime_evidence")

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
        if runtime_evidence is not None:
            failures += validate_runtime_evidence(repo_root, name, runtime_evidence)

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
    raise SystemExit(main())

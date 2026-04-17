#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SHELL_EXECUTABLE_PATTERN = r"(?:/(?:usr/)?bin/)?(?:bash|dash|sh)"
COMMAND_PREFIX_PATTERN = r"command(?:\s+(?:--|-p))*\s+"
ENV_ASSIGNMENT_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*=\S+"
ENV_ASSIGNMENT_PREFIX_PATTERN = rf"(?:{ENV_ASSIGNMENT_PATTERN}\s+)+"
SUDO_COMMAND_PATTERN = r"(?:/(?:usr/)?bin/)?sudo"
ENV_COMMAND_PATTERN = r"(?:/(?:usr/)?bin/)?env"
SUDO_OPTION_PATTERN = r"(?:--|--?[A-Za-z][\w-]*(?:[= ]\S+)?)"
SUDO_PREFIX_PATTERN = rf"{SUDO_COMMAND_PATTERN}(?:\s+{SUDO_OPTION_PATTERN})*\s+"
ENV_ARGUMENT_PATTERN = rf"(?!{SHELL_EXECUTABLE_PATTERN}\b)\S+"
ENV_PREFIX_PATTERN = rf"{ENV_COMMAND_PATTERN}(?:\s+{ENV_ARGUMENT_PATTERN})*\s+"
SHELL_OPTION_PATTERN = r"(?:--[A-Za-z][\w-]*|-[A-Za-z]+)"
ENV_SPLIT_STRING_OPTION_PATTERN = r"(?:-S|--split-string)(?:=|\s+)"
ENV_SPLIT_STRING_PRE_ARGUMENT_PATTERN = rf"(?!-S(?:\s|$))(?!--split-string(?:=|\s|$)){ENV_ARGUMENT_PATTERN}"
ENV_SPLIT_STRING_VALUE_PATTERN = rf"(?:\"{SHELL_EXECUTABLE_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*\"|'{SHELL_EXECUTABLE_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*'|{SHELL_EXECUTABLE_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*)"
ENV_SPLIT_STRING_LAUNCHER_PATTERN = rf"{ENV_COMMAND_PATTERN}(?:\s+{ENV_SPLIT_STRING_PRE_ARGUMENT_PATTERN})*\s+{ENV_SPLIT_STRING_OPTION_PATTERN}{ENV_SPLIT_STRING_VALUE_PATTERN}"
SHELL_LAUNCHER_PATTERN = rf"(?:(?:{COMMAND_PREFIX_PATTERN}|{SUDO_PREFIX_PATTERN}|{ENV_PREFIX_PATTERN}|{ENV_ASSIGNMENT_PREFIX_PATTERN}))*?(?:{ENV_SPLIT_STRING_LAUNCHER_PATTERN}|{SHELL_EXECUTABLE_PATTERN})"
DOWNLOADER_EXECUTABLE_PATTERN = r"(?:/(?:usr/)?bin/)?(?:curl|wget)"
DOWNLOADER_WORD_PATTERN = rf"(?:{DOWNLOADER_EXECUTABLE_PATTERN}\b|\"{DOWNLOADER_EXECUTABLE_PATTERN}\"|'{DOWNLOADER_EXECUTABLE_PATTERN}')"
DOWNLOADER_PATTERN = rf"(?:(?:{COMMAND_PREFIX_PATTERN}|{SUDO_PREFIX_PATTERN}|{ENV_PREFIX_PATTERN}|{ENV_ASSIGNMENT_PREFIX_PATTERN}))*?{DOWNLOADER_WORD_PATTERN}"
SHELL_C_OPTION_PATTERN = r"(?:-c|-[A-Za-z]*c[A-Za-z]*|--command)"
INLINE_PIPE_COMMENT_RE = re.compile(r"\|&?\s*#")
STEPS_KEY_RE = re.compile(r'^\s*["\']?steps["\']?\s*:\s*(?:#.*)?$')
STEP_INLINE_RUN_RE = re.compile(r'^\s*-\s+["\']?run["\']?\s*:\s*(.*)$')
RUN_KEY_RE = re.compile(r'^\s*["\']?run["\']?\s*:\s*(.*)$')
BLOCK_SCALAR_RE = re.compile(r'^[>|][-+0-9]*(?:\s+#.*)?$')
STEP_FLOW_MAPPING_RE = re.compile(r"^\s*-\s*\{(.*)\}\s*$")
STEPS_FLOW_SEQUENCE_START_RE = re.compile(r'^\s*["\']?steps["\']?\s*:\s*\[(.*)$')
FLOW_STYLE_STEP_RUN_RE = re.compile(r'^\s*-\s*\{\s*["\']?run["\']?\s*:\s*(.*?)\s*\}\s*$')
ENV_SPLIT_STRING_FALLBACK_RE = re.compile(r"(?:^|[^\w])(?:/(?:usr/)?bin/)?env\s+-S(?:\s|$)|--split-string", re.IGNORECASE)

REMOTE_SHELL_PATTERNS = (
    (
        "remote shell pipe",
        re.compile(
            rf"(?:^|[^\w]){DOWNLOADER_PATTERN}.*\|&?\s*(?:\{{\s*|\(\s*)?{ENV_SPLIT_STRING_LAUNCHER_PATTERN}(?=\s|$|['\"])",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell pipe",
        re.compile(
            rf"(?:^|[^\w]){DOWNLOADER_PATTERN}.*\|&?\s*(?:\{{\s*|\(\s*)?(?<![\w./-]){SHELL_LAUNCHER_PATTERN}(?=\s|$|['\"]|\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell process substitution",
        re.compile(
            rf"(?:^|[^\w])(?:{SHELL_LAUNCHER_PATTERN}|source|\.)(?:\s+{SHELL_OPTION_PATTERN})*\s*(?:<\(|<\s*<\()\s*{DOWNLOADER_PATTERN}",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell here-string command substitution",
        re.compile(
            rf"(?:^|[^\w]){SHELL_LAUNCHER_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*\s*<<<\s*[\"']?(?:\$\(\s*{DOWNLOADER_PATTERN}|`[^`]*{DOWNLOADER_PATTERN})",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell here-doc command substitution",
        re.compile(
            rf"(?:^|[^\w]){SHELL_LAUNCHER_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*\s*<<-?\s*\S+.*(?:\$\(\s*{DOWNLOADER_PATTERN}|`[^`]*{DOWNLOADER_PATTERN})",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell -c command substitution",
        re.compile(
            rf"(?:^|[^\w]){SHELL_LAUNCHER_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*\s+{SHELL_C_OPTION_PATTERN}\s+[\"']?[^\n]*?(?:\$\(\s*{DOWNLOADER_PATTERN}|`[^`]*{DOWNLOADER_PATTERN})",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell eval command substitution",
        re.compile(rf"\beval\b\s+[\"']?[^\n]*?(?:\$\(\s*{DOWNLOADER_PATTERN}|`[^`]*{DOWNLOADER_PATTERN})", re.IGNORECASE),
    ),
)


def workflow_paths(repo_root: Path) -> list[Path]:
    workflow_dir = repo_root / ".github" / "workflows"
    return sorted(list(workflow_dir.glob("*.yml")) + list(workflow_dir.glob("*.yaml")))


def render_path(path: Path, repo_root: Path | None = None) -> str:
    if repo_root is None:
        return path.as_posix()
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError:
        return path.as_posix()


def command_windows(entries: list[tuple[int, str]], start: int) -> list[tuple[int, int, str]]:
    windows: list[tuple[int, int, str]] = []
    parts: list[str] = []
    join_without_space = False
    for idx in range(start, len(entries)):
        line_no, raw = entries[idx]
        stripped = raw.strip()
        if not stripped:
            if parts:
                if parts[-1].endswith("|") or parts[-1].endswith("|&"):
                    continue
                break
            continue
        if stripped.startswith("#"):
            if parts:
                continue
            continue
        normalized = stripped.rstrip("\\").strip()
        pipe_comment_match = INLINE_PIPE_COMMENT_RE.search(normalized)
        if pipe_comment_match:
            pipe_token = pipe_comment_match.group(0).split("#", 1)[0].rstrip()
            normalized = normalized[: pipe_comment_match.start()].rstrip() + f" {pipe_token}"
        else:
            normalized = strip_shell_comment(normalized)
        if parts and join_without_space:
            parts[-1] += normalized
        else:
            parts.append(normalized)
        join_without_space = raw.rstrip().endswith("\\")
        windows.append((idx, line_no, " ".join(parts)))
    return windows


def block_entries(entries: list[tuple[int, str]], start: int, run_indent: int) -> tuple[list[tuple[int, str]], int]:
    block: list[tuple[int, str]] = []
    idx = start
    while idx < len(entries):
        line_no, raw = entries[idx]
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if stripped and indent <= run_indent:
            break
        block.append((line_no, raw))
        idx += 1
    nonempty_indents = [len(raw) - len(raw.lstrip()) for _, raw in block if raw.strip()]
    base_indent = min(nonempty_indents) if nonempty_indents else run_indent + 1
    normalized = [
        (line_no, raw[base_indent:] if raw.strip() else "")
        for line_no, raw in block
    ]
    return normalized, idx


def inline_plain_scalar_entries(
    step_entries: list[tuple[int, str]],
    first_line_no: int,
    first_content: str,
    run_indent: int,
) -> list[tuple[int, str]]:
    entries: list[tuple[int, str]] = [(first_line_no, first_content)]
    base_indent: int | None = None
    for line_no, raw in step_entries[1:]:
        if not raw.strip():
            if base_indent is not None:
                entries.append((line_no, ""))
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent <= run_indent:
            break
        continuation_indent = run_indent + 1
        if base_indent is None:
            base_indent = continuation_indent
        entries.append((line_no, raw[continuation_indent:]))
    return entries


def strip_quoted_literals(text: str) -> str:
    parts: list[str] = []
    quote: str | None = None
    escape = False
    for ch in text:
        if quote is None:
            if ch in {"'", '"'}:
                quote = ch
                parts.append(ch)
            else:
                parts.append(ch)
            continue
        if quote == '"':
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
                parts.append(ch)
                continue
        elif ch == quote:
            quote = None
            parts.append(ch)
            continue
        parts.append(" ")
    return "".join(parts)


def strip_shell_comment(text: str) -> str:
    quote: str | None = None
    escape = False
    for idx, ch in enumerate(text):
        if quote is None:
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch in {"'", '"'}:
                quote = ch
                continue
            if ch == "#":
                return text[:idx].rstrip()
            continue
        if quote == '"':
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
        elif ch == quote:
            quote = None
    return text


def mask_pipe_window(text: str) -> str:
    parts: list[str] = []
    quote: str | None = None
    escape = False
    quoted: list[str] = []
    for ch in text:
        if quote is None:
            if ch in {"'", '"'}:
                quote = ch
                quoted = []
                parts.append(ch)
            else:
                parts.append(ch)
            continue
        if quote == '"':
            if escape:
                escape = False
                quoted.append(ch)
                continue
            if ch == "\\":
                escape = True
                quoted.append(ch)
                continue
        if ch == quote:
            quoted_text = "".join(quoted)
            if re.fullmatch(DOWNLOADER_EXECUTABLE_PATTERN, quoted_text):
                parts.extend(quoted_text)
            else:
                parts.extend(" " * len(quoted_text))
            parts.append(ch)
            quote = None
            quoted = []
            continue
        quoted.append(ch)
    if quote is not None and quoted:
        parts.extend(" " * len(quoted))
    return "".join(parts)


def extract_flow_mapping_run(mapping_text: str) -> str | None:
    entries: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escape = False
    depth = 0
    for ch in mapping_text:
        if quote is not None:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {"'", '"'}:
            quote = ch
            current.append(ch)
            continue
        if ch in "{[(":
            depth += 1
            current.append(ch)
            continue
        if ch in "}])":
            if depth > 0:
                depth -= 1
            current.append(ch)
            continue
        if ch == "," and depth == 0:
            entries.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if current:
        entries.append("".join(current).strip())

    for entry in entries:
        quote = None
        escape = False
        depth = 0
        for idx, ch in enumerate(entry):
            if quote is not None:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote:
                    quote = None
                continue
            if ch in {"'", '"'}:
                quote = ch
                continue
            if ch in "{[(":
                depth += 1
                continue
            if ch in "}])":
                if depth > 0:
                    depth -= 1
                continue
            if ch == ":" and depth == 0:
                key = entry[:idx].strip().strip("'\"")
                if key != "run":
                    break
                value = entry[idx + 1 :].strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                    value = value[1:-1]
                return value or None
    return None


def extract_flow_sequence_mappings(sequence_text: str, start_line_no: int) -> list[tuple[int, str]]:
    mappings: list[tuple[int, str]] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escape = False
    line_no = start_line_no
    mapping_line_no = start_line_no
    for ch in sequence_text:
        if quote is not None:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            if ch == "\n":
                line_no += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
            if depth > 0:
                current.append(ch)
            continue
        if ch == "{":
            depth += 1
            if depth == 1:
                current = []
                mapping_line_no = line_no
            else:
                current.append(ch)
            continue
        if ch == "}":
            if depth == 0:
                continue
            depth -= 1
            if depth == 0:
                mappings.append((mapping_line_no, "".join(current)))
                current = []
            else:
                current.append(ch)
            continue
        if depth > 0:
            current.append(ch)
        if ch == "\n":
            line_no += 1
    return mappings


def collect_flow_sequence(lines: list[str], start_idx: int, initial_text: str) -> tuple[str, int]:
    parts: list[str] = []
    depth = 1
    quote: str | None = None
    escape = False
    idx = start_idx
    text = initial_text
    while True:
        for pos, ch in enumerate(text):
            if quote is not None:
                parts.append(ch)
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote:
                    quote = None
                continue
            if ch in {"'", '"'}:
                quote = ch
                parts.append(ch)
                continue
            if ch == "[":
                depth += 1
                parts.append(ch)
                continue
            if ch == "]":
                depth -= 1
                if depth == 0:
                    return "".join(parts), idx + 1
                parts.append(ch)
                continue
            parts.append(ch)
        idx += 1
        if idx >= len(lines):
            return "".join(parts), idx
        text = "\n" + lines[idx]


def extract_step_run_entries(step_entries: list[tuple[int, str]]) -> list[list[tuple[int, str]]]:
    run_entries: list[list[tuple[int, str]]] = []
    first_line_no, first_raw = step_entries[0]
    flow_step_match = STEP_FLOW_MAPPING_RE.match(first_raw)
    if flow_step_match is not None:
        content = extract_flow_mapping_run(flow_step_match.group(1))
        if content:
            run_entries.append([(first_line_no, content)])
        return run_entries
    flow_style_match = FLOW_STYLE_STEP_RUN_RE.match(first_raw)
    if flow_style_match is not None:
        content = flow_style_match.group(1)
        if content:
            run_entries.append([(first_line_no, content)])
        return run_entries
    inline_match = STEP_INLINE_RUN_RE.match(first_raw)
    if inline_match is not None:
        content = inline_match.group(1)
        if content and BLOCK_SCALAR_RE.match(content.strip()):
            block, _ = block_entries(step_entries, 1, len(first_raw) - len(first_raw.lstrip()))
            run_entries.append(block)
        elif content:
            run_entries.append(
                inline_plain_scalar_entries(
                    step_entries,
                    first_line_no,
                    content,
                    len(first_raw) - len(first_raw.lstrip()) + 2,
                )
            )
        return run_entries

    child_indents = [
        len(raw) - len(raw.lstrip())
        for _, raw in step_entries[1:]
        if raw.strip()
    ]
    if not child_indents:
        return run_entries
    child_indent = min(child_indents)

    idx = 1
    while idx < len(step_entries):
        line_no, raw = step_entries[idx]
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if not stripped:
            idx += 1
            continue
        if indent != child_indent:
            idx += 1
            continue
        match = RUN_KEY_RE.match(raw)
        if match is None:
            idx += 1
            continue
        content = match.group(1)
        if content and BLOCK_SCALAR_RE.match(content.strip()):
            block, idx = block_entries(step_entries, idx + 1, indent)
            run_entries.append(block)
            continue
        if content:
            run_entries.append([(line_no, content)])
        idx += 1
    return run_entries


def iter_run_entries(lines: list[str]) -> list[list[tuple[int, str]]]:
    entries: list[list[tuple[int, str]]] = []
    idx = 0
    while idx < len(lines):
        raw = lines[idx]
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        flow_steps_match = STEPS_FLOW_SEQUENCE_START_RE.match(raw)
        if flow_steps_match is not None:
            start_line_no = idx + 1
            sequence_text, idx = collect_flow_sequence(lines, idx, flow_steps_match.group(1))
            for mapping_line_no, mapping_text in extract_flow_sequence_mappings(sequence_text, start_line_no):
                content = extract_flow_mapping_run(mapping_text)
                if content:
                    entries.append([(mapping_line_no, content)])
            continue
        if not STEPS_KEY_RE.match(raw):
            idx += 1
            continue
        steps_indent = indent
        idx += 1
        while idx < len(lines):
            raw = lines[idx]
            stripped = raw.strip()
            indent = len(raw) - len(raw.lstrip())
            if stripped and indent <= steps_indent:
                break
            if not stripped:
                idx += 1
                continue
            if indent > steps_indent and (stripped == "-" or stripped.startswith("- ")):
                step_indent = indent
                step_entries: list[tuple[int, str]] = [(idx + 1, raw)]
                idx += 1
                while idx < len(lines):
                    next_raw = lines[idx]
                    next_stripped = next_raw.strip()
                    next_indent = len(next_raw) - len(next_raw.lstrip())
                    if next_stripped and next_indent <= steps_indent:
                        break
                    if next_stripped and next_indent == step_indent and (next_stripped == "-" or next_stripped.startswith("- ")):
                        break
                    step_entries.append((idx + 1, next_raw))
                    idx += 1
                entries.extend(extract_step_run_entries(step_entries))
                continue
            idx += 1
    return entries


def infer_repo_root(path: Path) -> Path | None:
    for parent in path.parents:
        if parent.name == ".github" and parent.parent.name:
            return parent.parent
    return None


def find_violations(path: Path) -> list[str]:
    violations: list[str] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    rendered_path = render_path(path, infer_repo_root(path))
    for run_entries in iter_run_entries(lines):
        line_idx = 0
        while line_idx < len(run_entries):
            matched_end: int | None = None
            for end_idx, line_no, window in command_windows(run_entries, line_idx):
                for label, pattern in REMOTE_SHELL_PATTERNS:
                    candidate = mask_pipe_window(window) if label == "remote shell pipe" else window
                    matched = pattern.search(candidate)
                    if not matched and label == "remote shell pipe" and ENV_SPLIT_STRING_FALLBACK_RE.search(window):
                        matched = pattern.search(window)
                    if matched:
                        violations.append(f"{rendered_path}:{line_no}: {label}: {window}")
                        matched_end = end_idx
                        break
                else:
                    continue
                break
            if matched_end is not None:
                line_idx = matched_end + 1
                continue
            line_idx += 1
    return violations


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Reject remote shell bootstrap patterns in workflow YAML.")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository root containing .github/workflows",
    )
    args = parser.parse_args(argv[1:])

    repo_root = args.repo_root.resolve()
    bad: list[str] = []
    for workflow in workflow_paths(repo_root):
        bad.extend(find_violations(workflow))

    if bad:
        print("ERROR: remote shell bootstrap is not allowed in .github/workflows:", file=sys.stderr)
        for item in bad:
            print(f" - {item}", file=sys.stderr)
        print(file=sys.stderr)
        print("Fix: download pinned artifacts or use a repo-local helper instead of curl|bash/process substitution.", file=sys.stderr)
        return 1

    print("OK: no remote shell bootstrap patterns found in workflow surface.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

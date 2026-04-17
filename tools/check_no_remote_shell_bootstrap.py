#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
    from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
    from yaml.events import AliasEvent, MappingEndEvent, MappingStartEvent, ScalarEvent, SequenceEndEvent, SequenceStartEvent
except ImportError:  # pragma: no cover - optional dependency fallback
    yaml = None
    Node = object  # type: ignore[assignment]
    MappingNode = object  # type: ignore[assignment]
    ScalarNode = object  # type: ignore[assignment]
    SequenceNode = object  # type: ignore[assignment]
    AliasEvent = object  # type: ignore[assignment]
    MappingEndEvent = object  # type: ignore[assignment]
    MappingStartEvent = object  # type: ignore[assignment]
    ScalarEvent = object  # type: ignore[assignment]
    SequenceEndEvent = object  # type: ignore[assignment]
    SequenceStartEvent = object  # type: ignore[assignment]

MISSING_PYYAML_MESSAGE = "PyYAML is required for fail-closed workflow bootstrap scanning."

SHELL_EXECUTABLE_PATTERN = r"(?:(?:/(?:usr/)?(?:local/)?bin/|/opt/homebrew/bin/)?(?:bash|dash|sh|zsh|ksh|ash|mksh|yash|posh|fish))"
SHELL_WORD_PATTERN = rf"(?:{SHELL_EXECUTABLE_PATTERN}\b|\"{SHELL_EXECUTABLE_PATTERN}\"|'{SHELL_EXECUTABLE_PATTERN}')"
COMMAND_WORD_PATTERN = r"(?:command|\"command\"|'command')"
COMMAND_PREFIX_PATTERN = rf"{COMMAND_WORD_PATTERN}(?:\s+(?:--|-p))*\s+"
ENV_ASSIGNMENT_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*=\S+"
ENV_ASSIGNMENT_PREFIX_PATTERN = rf"(?:{ENV_ASSIGNMENT_PATTERN}\s+)+"
SUDO_COMMAND_PATTERN = r"(?:/(?:usr/)?bin/)?sudo"
ENV_COMMAND_PATTERN = r"(?:/(?:usr/)?bin/)?env"
ENV_COMMAND_WORD_PATTERN = rf"(?:{ENV_COMMAND_PATTERN}|\"{ENV_COMMAND_PATTERN}\"|'{ENV_COMMAND_PATTERN}')"
SUDO_OPTION_PATTERN = r"(?:--|--?[A-Za-z][\w-]*(?:[= ]\S+)?)"
SUDO_PREFIX_PATTERN = rf"{SUDO_COMMAND_PATTERN}(?:\s+{SUDO_OPTION_PATTERN})*\s+"
ENV_ARGUMENT_PATTERN = rf"(?!{SHELL_EXECUTABLE_PATTERN}\b)\S+"
ENV_PREFIX_PATTERN = rf"{ENV_COMMAND_WORD_PATTERN}(?:\s+{ENV_ARGUMENT_PATTERN})*\s+"
SHELL_OPTION_VALUE_PATTERN = r"(?:\"[^\"]+\"|'[^']+'|\S+)"
SHELL_OPTION_EQUALS_VALUE_PATTERN = r"(?:\"[^\"]*\"|'[^']*'|\S*)"
SHELL_OPTION_PATTERN = rf"(?:--(?:rcfile|init-file)(?:={SHELL_OPTION_EQUALS_VALUE_PATTERN}| {SHELL_OPTION_VALUE_PATTERN})|-o(?:={SHELL_OPTION_EQUALS_VALUE_PATTERN}| {SHELL_OPTION_VALUE_PATTERN})|--[A-Za-z][\w-]*|-[A-Za-z]+)"
ENV_SPLIT_STRING_OPTION_PATTERN = r"(?:-S|--split-string)(?:=|\s+)"
ENV_SPLIT_STRING_PRE_ARGUMENT_PATTERN = rf"(?!-S(?:\s|$))(?!--split-string(?:=|\s|$)){ENV_ARGUMENT_PATTERN}"
ENV_SPLIT_STRING_VALUE_PATTERN = rf"(?:\"{SHELL_EXECUTABLE_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*\"|'{SHELL_EXECUTABLE_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*'|{SHELL_EXECUTABLE_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*)"
ENV_SPLIT_STRING_LAUNCHER_PATTERN = rf"{ENV_COMMAND_WORD_PATTERN}(?:\s+{ENV_SPLIT_STRING_PRE_ARGUMENT_PATTERN})*\s+{ENV_SPLIT_STRING_OPTION_PATTERN}{ENV_SPLIT_STRING_VALUE_PATTERN}"
SHELL_LAUNCHER_PATTERN = rf"(?:(?:{COMMAND_PREFIX_PATTERN}|{SUDO_PREFIX_PATTERN}|{ENV_PREFIX_PATTERN}|{ENV_ASSIGNMENT_PREFIX_PATTERN}))*?(?:{ENV_SPLIT_STRING_LAUNCHER_PATTERN}|{SHELL_WORD_PATTERN})"
DOWNLOADER_EXECUTABLE_PATTERN = r"(?:/(?:usr/)?bin/)?(?:curl|wget)"
DOWNLOADER_WORD_PATTERN = rf"(?:{DOWNLOADER_EXECUTABLE_PATTERN}\b|\"{DOWNLOADER_EXECUTABLE_PATTERN}\"|'{DOWNLOADER_EXECUTABLE_PATTERN}')"
DOWNLOADER_PATTERN = rf"(?:(?:{COMMAND_PREFIX_PATTERN}|{SUDO_PREFIX_PATTERN}|{ENV_PREFIX_PATTERN}|{ENV_ASSIGNMENT_PREFIX_PATTERN}))*?{DOWNLOADER_WORD_PATTERN}"
SHELL_C_OPTION_PATTERN = r"(?:-c|-[A-Za-z]*c[A-Za-z]*|--command)"
INLINE_PIPE_COMMENT_RE = re.compile(r"\|&?\s*#")
YAML_NODE_METADATA_TOKEN_PATTERN = r"(?:!!?[^\s#]+|[&*][^\s#]+)"
YAML_VALUE_METADATA_PREFIX_PATTERN = r"^(?:(?:!!?[^\s#]+|&[^\s#]+)\s+)+"
STEPS_KEY_RE = re.compile(
    rf'^\s*["\']?steps["\']?\s*:\s*(?:{YAML_NODE_METADATA_TOKEN_PATTERN}\s*)*(?:#.*)?$'
)
STEP_INLINE_RUN_RE = re.compile(r'^\s*-\s+["\']?run["\']?\s*:\s*(.*)$')
RUN_KEY_RE = re.compile(r'^\s*["\']?run["\']?\s*:\s*(.*)$')
BLOCK_SCALAR_RE = re.compile(r'^[>|][-+0-9]*(?:\s+#.*)?$')
STEP_FLOW_MAPPING_RE = re.compile(r"^\s*-\s*\{(.*)\}\s*(?:#.*)?$")
STEPS_FLOW_SEQUENCE_START_RE = re.compile(
    rf'^\s*["\']?steps["\']?\s*:\s*(?:{YAML_NODE_METADATA_TOKEN_PATTERN}\s*)*\[(.*)$'
)
FLOW_STYLE_STEP_RUN_RE = re.compile(r'^\s*-\s*\{\s*["\']?run["\']?\s*:\s*(.*?)\s*\}\s*(?:#.*)?$')
ENV_SPLIT_STRING_FALLBACK_RE = re.compile(
    r"(?:^|[^\w])(?:/(?:usr/)?bin/)?env\s+(?:-S(?:\s|$)|--split-string(?:=|\s|$))",
    re.IGNORECASE,
)
WRAPPER_EXECUTABLE_PATTERN = rf"(?:{ENV_COMMAND_PATTERN}|command|source)"
SOURCE_WORD_PATTERN = r"(?:source|\"source\"|'source')"
STDIN_PATH_PATTERN = r"(?:/dev/stdin|\"/dev/stdin\"|'/dev/stdin'|/dev/fd/0|\"/dev/fd/0\"|'/dev/fd/0')"
SOURCE_STDIN_PATTERN = rf"(?:{SOURCE_WORD_PATTERN}|\.)\s+{STDIN_PATH_PATTERN}"

REMOTE_SHELL_PATTERNS = (
    (
        "remote shell pipe",
        re.compile(
            rf"(?:^|[^\w]){DOWNLOADER_PATTERN}[\s\S]*\|&?\s*(?:\{{\s*|\(\s*)?{ENV_SPLIT_STRING_LAUNCHER_PATTERN}(?=\s|$|['\"])",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell pipe",
        re.compile(
            rf"(?:^|[^\w]){DOWNLOADER_PATTERN}[\s\S]*\|&?\s*(?:\{{\s*|\(\s*)?{SOURCE_STDIN_PATTERN}(?=\s|$|['\"])",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell pipe",
        re.compile(
            rf"(?:^|[^\w]){DOWNLOADER_PATTERN}[\s\S]*\|&?\s*(?:\{{\s*|\(\s*)?(?<![\w./-]){SHELL_LAUNCHER_PATTERN}(?=\s|$|['\"]|\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell process substitution",
        re.compile(
            rf"(?:^|[^\w])(?:{SHELL_LAUNCHER_PATTERN}|{SOURCE_WORD_PATTERN}|\.)(?:\s+{SHELL_OPTION_PATTERN})*\s*(?:<\(|<\s*<\()\s*[\s\S]*?{DOWNLOADER_PATTERN}[\s\S]*?\)",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell here-string command substitution",
        re.compile(
            rf"(?:^|[^\w]){SHELL_LAUNCHER_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*\s*<<<\s*(?:(?:\$?[\"'])[\s\S]*?(?:\$\([\s\S]*?{DOWNLOADER_PATTERN}|`[^`]*{DOWNLOADER_PATTERN})[\s\S]*?[\"']|(?:\$\([^\n]*?{DOWNLOADER_PATTERN}|`[^`]*{DOWNLOADER_PATTERN}))",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell here-string direct bootstrap",
        re.compile(
            rf"(?:^|[^\w]){SHELL_LAUNCHER_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*\s*<<<\s*(?:\$?[\"'])[\s\S]*?{DOWNLOADER_PATTERN}[\s\S]*\|&?\s*(?:\{{\s*|\(\s*)?(?:{ENV_SPLIT_STRING_LAUNCHER_PATTERN}|{SOURCE_STDIN_PATTERN}|(?<![\w./-]){SHELL_LAUNCHER_PATTERN})(?=\s|$|['\"]|\b)[\s\S]*?[\"']",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell here-doc command substitution",
        re.compile(
            rf"(?:^|[^\w]){SHELL_LAUNCHER_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*\s*<<(?!<)-?\s*\S+[\s\S]*?(?:\$\([\s\S]*?{DOWNLOADER_PATTERN}|`[^`]*{DOWNLOADER_PATTERN})",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell -c command substitution",
        re.compile(
            rf"(?:^|[^\w]){SHELL_LAUNCHER_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*\s+{SHELL_C_OPTION_PATTERN}\s+(?:\$?[\"'])?[\s\S]*?(?:\$\([\s\S]*?{DOWNLOADER_PATTERN}|`[^`]*{DOWNLOADER_PATTERN})",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell -c command substitution",
        re.compile(
            rf"(?:^|[^\w]){SHELL_LAUNCHER_PATTERN}(?:\s+{SHELL_OPTION_PATTERN})*\s+{SHELL_C_OPTION_PATTERN}\s+(?:\$?[\"'])[\s\S]*?{DOWNLOADER_PATTERN}[\s\S]*\|&?\s*(?:\{{\s*|\(\s*)?(?:{ENV_SPLIT_STRING_LAUNCHER_PATTERN}|{SOURCE_STDIN_PATTERN}|(?<![\w./-]){SHELL_LAUNCHER_PATTERN})(?=\s|$|['\"]|\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "remote shell eval command substitution",
        re.compile(rf"\beval\b\s+(?:\$?[\"'])?[\s\S]*?(?:\$\([\s\S]*?{DOWNLOADER_PATTERN}|`[^`]*{DOWNLOADER_PATTERN})", re.IGNORECASE),
    ),
    (
        "remote shell eval command substitution",
        re.compile(
            rf"\beval\b\s+(?:\$?[\"'])[\s\S]*?{DOWNLOADER_PATTERN}[\s\S]*\|&?\s*(?:\{{\s*|\(\s*)?(?:{ENV_SPLIT_STRING_LAUNCHER_PATTERN}|{SOURCE_STDIN_PATTERN}|(?<![\w./-]){SHELL_LAUNCHER_PATTERN})(?=\s|$|['\"]|\b)",
            re.IGNORECASE,
        ),
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
    active_heredoc: tuple[str, bool] | None = None
    for idx in range(start, len(entries)):
        line_no, raw = entries[idx]
        stripped = raw.strip()
        if active_heredoc is not None:
            terminator, allow_tabs = active_heredoc
            parts.append(stripped if stripped else "")
            windows.append((idx, line_no, "\n".join(parts)))
            line_text = raw.rstrip("\r\n")
            compare_text = line_text.lstrip("\t") if allow_tabs else line_text
            if compare_text == terminator:
                active_heredoc = None
                break
            join_without_space = raw.rstrip().endswith("\\")
            continue
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
        heredoc_match = re.search(r"(?<!<)<<(?!<)(?P<tabs>-?)\s*(?P<terminator>\S+)$", normalized)
        if heredoc_match is not None:
            terminator = heredoc_match.group("terminator")
            if (
                len(terminator) >= 2
                and terminator[0] == terminator[-1]
                and terminator[0] in {"'", '"'}
            ):
                terminator = terminator[1:-1]
            active_heredoc = (terminator, heredoc_match.group("tabs") == "-")
        windows.append((idx, line_no, "\n".join(parts)))
    return windows


def heredoc_body_indices(entries: list[tuple[int, str]]) -> set[int]:
    body_indices: set[int] = set()
    active_heredoc: tuple[str, bool] | None = None
    for idx, (_, raw) in enumerate(entries):
        stripped = raw.strip()
        if active_heredoc is not None:
            body_indices.add(idx)
            terminator, allow_tabs = active_heredoc
            line_text = raw.rstrip("\r\n")
            compare_text = line_text.lstrip("\t") if allow_tabs else line_text
            if compare_text == terminator:
                active_heredoc = None
            continue
        if not stripped or stripped.startswith("#"):
            continue
        normalized = strip_shell_comment(stripped.rstrip("\\").strip())
        heredoc_match = re.search(r"(?<!<)<<(?!<)(?P<tabs>-?)\s*(?P<terminator>\S+)$", normalized)
        if heredoc_match is None:
            continue
        terminator = heredoc_match.group("terminator")
        if len(terminator) >= 2 and terminator[0] == terminator[-1] and terminator[0] in {"'", '"'}:
            terminator = terminator[1:-1]
        active_heredoc = (terminator, heredoc_match.group("tabs") == "-")
    return body_indices


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


def strip_yaml_scalar_quotes(text: str) -> str:
    trimmed = text.strip()
    if len(trimmed) >= 2 and trimmed[0] == trimmed[-1] and trimmed[0] in {"'", '"'}:
        trimmed = trimmed[1:-1]
    trimmed = re.sub(YAML_VALUE_METADATA_PREFIX_PATTERN, "", trimmed)
    if text != trimmed:
        return trimmed
    return text


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
            prefix_parts = parts[:-1] if parts and parts[-1] in {"'", '"'} else parts
            prefix_text = "".join(prefix_parts).rstrip()
            preserve_shell_word = (
                not prefix_text
                or prefix_text.endswith(("|", "|&", ";", "&", "&&", "||", "("))
                or bool(
                    re.search(
                        rf"(?:^|\s)(?:{COMMAND_PREFIX_PATTERN}|{SUDO_PREFIX_PATTERN}|{ENV_PREFIX_PATTERN}|{ENV_ASSIGNMENT_PREFIX_PATTERN})$",
                        prefix_text,
                    )
                )
            )
            preserve_stdin_path = bool(
                re.fullmatch(r"/dev/(?:stdin|fd/0)", quoted_text)
                and re.search(rf"(?:^|\s)(?:{SOURCE_WORD_PATTERN}|\.)$", prefix_text)
            )
            preserve_shell_option_value = bool(
                re.search(r"(?:^|\s)(?:-o|--rcfile|--init-file)$", prefix_text)
            )
            if (
                re.fullmatch(DOWNLOADER_EXECUTABLE_PATTERN, quoted_text)
                or re.fullmatch(SHELL_EXECUTABLE_PATTERN, quoted_text)
                or re.fullmatch(WRAPPER_EXECUTABLE_PATTERN, quoted_text)
            ) and preserve_shell_word:
                parts.extend(quoted_text)
            elif preserve_stdin_path:
                parts.extend(quoted_text)
            elif preserve_shell_option_value:
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


def split_shell_segments(text: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escape = False
    depth = 0
    idx = 0
    length = len(text)
    while idx < length:
        ch = text[idx]
        if quote is None:
            if escape:
                current.append(ch)
                escape = False
                idx += 1
                continue
            if ch == "\\":
                current.append(ch)
                escape = True
                idx += 1
                continue
            if ch in {"'", '"'}:
                quote = ch
                current.append(ch)
                idx += 1
                continue
            if ch in "({[":
                depth += 1
                current.append(ch)
                idx += 1
                continue
            if ch in ")}]":
                if depth > 0:
                    depth -= 1
                current.append(ch)
                idx += 1
                continue
            if ch == ";" and depth == 0:
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                idx += 1
                continue
            if ch == "&" and depth == 0 and not text.startswith("&&", idx) and (idx == 0 or text[idx - 1] != "|"):
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                idx += 1
                continue
            if depth == 0 and (text.startswith("&&", idx) or text.startswith("||", idx)):
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                idx += 2
                continue
            current.append(ch)
            idx += 1
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
        current.append(ch)
        idx += 1
    segment = "".join(current).strip()
    if segment:
        segments.append(segment)
    return segments


def split_shell_commands(text: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escape = False
    depth = 0
    idx = 0
    length = len(text)
    while idx < length:
        ch = text[idx]
        if quote is None:
            if escape:
                current.append(ch)
                escape = False
                idx += 1
                continue
            if ch == "\\":
                current.append(ch)
                escape = True
                idx += 1
                continue
            if ch in {"'", '"'}:
                quote = ch
                current.append(ch)
                idx += 1
                continue
            if ch in "({[":
                depth += 1
                current.append(ch)
                idx += 1
                continue
            if ch in ")}]":
                if depth > 0:
                    depth -= 1
                current.append(ch)
                idx += 1
                continue
            if ch == ";" and depth == 0:
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                idx += 1
                continue
            if ch == "&" and depth == 0 and not text.startswith("&&", idx) and (idx == 0 or text[idx - 1] != "|"):
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                idx += 1
                continue
            if depth == 0 and (text.startswith("&&", idx) or text.startswith("||", idx)):
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                idx += 2
                continue
            if ch == "\n" and depth == 0:
                segment = "".join(current).strip()
                if segment:
                    segments.append(segment)
                current = []
                idx += 1
                continue
            current.append(ch)
            idx += 1
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
        current.append(ch)
        idx += 1
    segment = "".join(current).strip()
    if segment:
        segments.append(segment)
    return segments


def split_pipe_detection_segments(text: str) -> list[str]:
    groups: list[str] = []
    current_lines: list[str] = []
    pipeline_open = False
    for line in text.split("\n"):
        stripped = line.strip()
        if not current_lines:
            current_lines = [line]
            pipeline_open = stripped.endswith("|") or stripped.endswith("|&")
            continue
        if pipeline_open:
            current_lines.append(line)
            if stripped and not stripped.startswith("#"):
                pipeline_open = stripped.endswith("|") or stripped.endswith("|&")
            if not pipeline_open and stripped and not stripped.startswith("#"):
                group = "\n".join(current_lines).strip()
                if group:
                    groups.append(group)
                current_lines = []
            continue
        if stripped.startswith("|&") or stripped.startswith("|"):
            current_lines.append(line)
            pipeline_open = stripped.endswith("|") or stripped.endswith("|&")
            if not pipeline_open:
                group = "\n".join(current_lines).strip()
                if group:
                    groups.append(group)
                current_lines = []
            continue
        group = "\n".join(current_lines).strip()
        if group:
            groups.append(group)
        current_lines = [line]
        pipeline_open = stripped.endswith("|") or stripped.endswith("|&")
    if current_lines:
        group = "\n".join(current_lines).strip()
        if group:
            groups.append(group)

    segments: list[str] = []
    for group in groups:
        segments.extend(split_shell_segments(group))
    return segments


def strip_non_shell_heredoc_body(text: str) -> str:
    match = re.search(r"(?<!<)<<(?!<)-?\s*\S+", text)
    if match is None:
        return text
    prefix = text[: match.start()]
    masked_prefix = mask_pipe_window(prefix)
    if re.search(rf"(?:^|[^\w])(?:{SHELL_LAUNCHER_PATTERN}|{SOURCE_WORD_PATTERN}|\.)(?:\s+{SHELL_OPTION_PATTERN})*\s*$", masked_prefix):
        return text
    return prefix + text[match.start() : match.end()]


def is_command_position_prefix(text: str) -> bool:
    prefix_text = text.rstrip()
    return (
        not prefix_text
        or prefix_text.endswith(("|", "|&", ";", "&", "&&", "||", "("))
        or bool(
            re.search(
                rf"(?:^|\s)(?:{COMMAND_PREFIX_PATTERN}|{SUDO_PREFIX_PATTERN}|{ENV_PREFIX_PATTERN}|{ENV_ASSIGNMENT_PREFIX_PATTERN})$",
                prefix_text,
            )
        )
    )


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
            elif quote == '"' and ch == "\\":
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


def has_unmasked_env_split_fallback(text: str) -> bool:
    masked = mask_pipe_window(text)
    return bool(ENV_SPLIT_STRING_FALLBACK_RE.search(masked))


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
            elif quote == '"' and ch == "\\":
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
    comment = False
    idx = start_idx
    text = initial_text
    while True:
        for pos, ch in enumerate(text):
            if comment:
                parts.append(ch)
                if ch == "\n":
                    comment = False
                continue
            if quote is not None:
                parts.append(ch)
                if escape:
                    escape = False
                elif quote == '"' and ch == "\\":
                    escape = True
                elif ch == quote:
                    quote = None
                continue
            if ch in {"'", '"'}:
                quote = ch
                parts.append(ch)
                continue
            if ch == "#":
                comment = True
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


def collect_step_flow_mapping_text(step_entries: list[tuple[int, str]]) -> str | None:
    first_raw = step_entries[0][1]
    match = re.match(r"^\s*-\s*\{(.*)$", first_raw)
    if match is None:
        return None

    depth = 1
    quote: str | None = None
    escape = False
    comment = False
    parts: list[str] = []
    segments = [match.group(1)] + [f"\n{raw.strip()}" for _, raw in step_entries[1:]]
    for segment in segments:
        for ch in segment:
            if comment:
                parts.append(ch)
                if ch == "\n":
                    comment = False
                continue
            if quote is not None:
                parts.append(ch)
                if escape:
                    escape = False
                elif quote == '"' and ch == "\\":
                    escape = True
                elif ch == quote:
                    quote = None
                continue
            if ch in {"'", '"'}:
                quote = ch
                parts.append(ch)
                continue
            if ch == "#":
                comment = True
                parts.append(ch)
                continue
            if ch == "{":
                depth += 1
                parts.append(ch)
                continue
            if ch == "}":
                depth -= 1
                if depth == 0:
                    return "".join(parts)
                parts.append(ch)
                continue
            parts.append(ch)
    return None


def search_unquoted(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    quote: str | None = None
    escape = False
    quoted_ranges: list[tuple[int, int]] = []
    start_idx = -1
    for idx, ch in enumerate(text):
        if quote is None:
            if ch in {"'", '"'}:
                quote = ch
                start_idx = idx
            continue
        if quote == '"':
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
        if ch == quote:
            quoted_ranges.append((start_idx, idx))
            quote = None
            start_idx = -1
    for match in pattern.finditer(text):
        start = match.start()
        blocked = False
        for lo, hi in quoted_ranges:
            if not (lo <= start <= hi):
                continue
            quoted_text = text[lo + 1 : hi]
            if (
                start == lo
                and re.fullmatch(SHELL_EXECUTABLE_PATTERN, quoted_text)
                and is_command_position_prefix(text[:lo])
            ):
                blocked = False
                break
            blocked = True
            break
        if blocked:
            continue
        return match
    return None


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
    flow_mapping_text = collect_step_flow_mapping_text(step_entries)
    if flow_mapping_text is not None:
        content = extract_flow_mapping_run(flow_mapping_text)
        if content:
            run_entries.append([(first_line_no, content)])
        return run_entries
    inline_match = STEP_INLINE_RUN_RE.match(first_raw)
    if inline_match is not None:
        content = strip_yaml_scalar_quotes(inline_match.group(1))
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
        content = strip_yaml_scalar_quotes(match.group(1))
        if content and BLOCK_SCALAR_RE.match(content.strip()):
            block, idx = block_entries(step_entries, idx + 1, indent)
            run_entries.append(block)
            continue
        if content:
            entries = inline_plain_scalar_entries(step_entries[idx:], line_no, content, indent)
            run_entries.append(entries)
            idx += len(entries)
            continue
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


def yaml_run_entries(content: str) -> list[list[tuple[int, str]]]:
    if yaml is None:
        raise RuntimeError(MISSING_PYYAML_MESSAGE)
    try:
        root = yaml.compose(content)
    except yaml.YAMLError as exc:
        if iter_run_entries(content.splitlines()):
            return []
        raise RuntimeError(f"PyYAML parse failed: {exc}") from exc
    if root is None:
        return []

    entries: list[list[tuple[int, str]]] = []

    def emit_run(key_node: ScalarNode, value_node: ScalarNode) -> None:
        value = value_node.value or ""
        if not value:
            return
        line_no = key_node.start_mark.line + 1
        if getattr(value_node, "style", None) in {"|", ">"}:
            line_no += 1
        lines = value.splitlines()
        if not lines:
            entries.append([(line_no, value)])
            return
        entries.append([(line_no + offset, line) for offset, line in enumerate(lines)])

    def walk(node: Node) -> None:
        if isinstance(node, MappingNode):
            for key_node, value_node in node.value:
                if isinstance(key_node, ScalarNode) and key_node.value == "steps" and isinstance(value_node, SequenceNode):
                    for item in value_node.value:
                        if isinstance(item, MappingNode):
                            for step_key, step_value in item.value:
                                if (
                                    isinstance(step_key, ScalarNode)
                                    and step_key.value == "run"
                                    and isinstance(step_value, ScalarNode)
                                ):
                                    emit_run(step_key, step_value)
                        walk(item)
                    continue
                walk(value_node)
            return
        if isinstance(node, SequenceNode):
            for item in node.value:
                walk(item)

    walk(root)
    return entries


def yaml_alias_run_entries(content: str) -> list[list[tuple[int, str]]]:
    if yaml is None:
        raise RuntimeError(MISSING_PYYAML_MESSAGE)
    try:
        events = list(yaml.parse(content))
    except yaml.YAMLError as exc:
        if iter_run_entries(content.splitlines()):
            return []
        raise RuntimeError(f"PyYAML parse failed: {exc}") from exc

    alias_entries: list[list[tuple[int, str]]] = []
    anchor_runs: dict[str, list[str]] = {}
    stack: list[dict[str, object]] = []

    def record_run(value: str, scalar_anchor: str | None) -> None:
        if scalar_anchor:
            anchor_runs.setdefault(scalar_anchor, [])
            if value not in anchor_runs[scalar_anchor]:
                anchor_runs[scalar_anchor].append(value)
        for ctx in stack:
            anchor = ctx.get("anchor")
            if not isinstance(anchor, str) or not anchor:
                continue
            anchor_runs.setdefault(anchor, [])
            if value not in anchor_runs[anchor]:
                anchor_runs[anchor].append(value)

    for event in events:
        if isinstance(event, MappingStartEvent):
            stack.append({"kind": "map", "anchor": event.anchor, "expecting_key": True, "current_key": None})
            continue
        if isinstance(event, SequenceStartEvent):
            stack.append({"kind": "seq", "anchor": event.anchor})
            continue
        if isinstance(event, (MappingEndEvent, SequenceEndEvent)):
            if stack:
                stack.pop()
            continue
        if not stack:
            continue
        top = stack[-1]
        if isinstance(event, ScalarEvent):
            if top.get("kind") != "map":
                continue
            if bool(top.get("expecting_key")):
                top["current_key"] = event.value
                top["expecting_key"] = False
                continue
            if top.get("current_key") == "run" and isinstance(event.value, str) and event.value:
                record_run(event.value, event.anchor)
            top["current_key"] = None
            top["expecting_key"] = True
            continue
        if isinstance(event, AliasEvent):
            anchor = event.anchor
            if anchor and anchor in anchor_runs:
                line_no = event.start_mark.line + 1
                for run_text in anchor_runs[anchor]:
                    alias_entries.append([(line_no, run_text)])
            if top.get("kind") == "map" and not bool(top.get("expecting_key")):
                top["current_key"] = None
                top["expecting_key"] = True

    return alias_entries


def normalize_run_entries(entries: list[tuple[int, str]]) -> tuple[int, str]:
    return (entries[0][0], normalize_run_entries_text(entries))


def normalize_run_entries_text(entries: list[tuple[int, str]]) -> str:
    return " ".join("\n".join(text for _, text in entries).split())


def infer_repo_root(path: Path) -> Path | None:
    for parent in path.parents:
        if parent.name == ".github" and parent.parent.name:
            return parent.parent
    return None


def find_violations(path: Path) -> list[str]:
    violations: list[str] = []
    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()
    rendered_path = render_path(path, infer_repo_root(path))
    run_entries_sets = iter_run_entries(lines)
    text_entry_keys = {normalize_run_entries(entries) for entries in run_entries_sets}
    text_entry_texts = {key[1] for key in text_entry_keys}
    seen_violations: set[tuple[str, int, str]] = set()
    for entries in yaml_run_entries(content):
        key = normalize_run_entries(entries)
        if key[1] in text_entry_texts:
            continue
        run_entries_sets.append(entries)
    for entries in yaml_alias_run_entries(content):
        key = normalize_run_entries(entries)
        if key in text_entry_keys:
            continue
        run_entries_sets.append(entries)
        text_entry_keys.add(key)
        text_entry_texts.add(key[1])
    for run_entries in run_entries_sets:
        skipped_body_indices = heredoc_body_indices(run_entries)
        line_idx = 0
        while line_idx < len(run_entries):
            if line_idx in skipped_body_indices:
                line_idx += 1
                continue
            matched_end: int | None = None
            for end_idx, line_no, window in command_windows(run_entries, line_idx):
                def trim_match(source_text: str, base_line_no: int, start_idx: int) -> tuple[int, str]:
                    raw_window = source_text[start_idx:]
                    leading = raw_window[: len(raw_window) - len(raw_window.lstrip())]
                    adjusted_line = base_line_no + leading.count("\n")
                    return adjusted_line, raw_window.lstrip()

                def here_string_payload_anchor(label: str, source_text: str, base_line_no: int) -> int:
                    if label not in {"remote shell here-string command substitution", "remote shell here-string direct bootstrap"}:
                        return base_line_no
                    payload_start = source_text.find("<<<")
                    if payload_start == -1:
                        return base_line_no
                    payload_text = source_text[payload_start + 3 :]
                    if label == "remote shell here-string command substitution":
                        match = re.search(r"\$\(|`", payload_text)
                    else:
                        match = re.search(DOWNLOADER_PATTERN, payload_text, re.IGNORECASE)
                    if match is None:
                        return base_line_no
                    return base_line_no + payload_text[: match.start()].count("\n")

                for label, pattern in REMOTE_SHELL_PATTERNS:
                    pipe_window = strip_non_shell_heredoc_body(window)
                    candidate = mask_pipe_window(pipe_window) if label in {"remote shell pipe", "remote shell process substitution"} else window
                    if label in {"remote shell here-string command substitution", "remote shell here-string direct bootstrap"}:
                        candidate = candidate.replace('\\"', '"').replace("\\'", "'")
                    matched = None
                    matched_line_no = line_no
                    if label == "remote shell pipe":
                        masked_segments = split_pipe_detection_segments(candidate)
                        original_segments = split_pipe_detection_segments(pipe_window)
                        for seg_idx, segment in enumerate(masked_segments):
                            matched = pattern.search(segment)
                            if matched:
                                source_segment = original_segments[seg_idx] if seg_idx < len(original_segments) else segment
                                base_line_no = line_no - source_segment.count("\n") + source_segment[: matched.start()].count("\n")
                                matched_line_no, window = trim_match(source_segment, base_line_no, matched.start())
                                break
                        if not matched and has_unmasked_env_split_fallback(pipe_window):
                            for segment in original_segments:
                                matched = pattern.search(segment)
                                if matched:
                                    base_line_no = line_no - segment.count("\n") + segment[: matched.start()].count("\n")
                                    matched_line_no, window = trim_match(segment, base_line_no, matched.start())
                                    break
                    else:
                        if label == "remote shell here-doc command substitution":
                            matched = pattern.search(candidate)
                            if matched:
                                source_segment = window
                                base_line_no = line_no - source_segment.count("\n") + source_segment[: matched.start()].count("\n")
                                matched_line_no, window = trim_match(source_segment, base_line_no, matched.start())
                        else:
                            command_segments = split_shell_commands(candidate)
                            original_segments = split_shell_commands(window)
                            for seg_idx, segment in enumerate(command_segments):
                                if label in {"remote shell -c command substitution", "remote shell eval command substitution"}:
                                    matched = search_unquoted(pattern, segment)
                                else:
                                    matched = pattern.search(segment)
                                if matched:
                                    source_segment = original_segments[seg_idx] if seg_idx < len(original_segments) else segment
                                    base_line_no = line_no - source_segment.count("\n") + source_segment[: matched.start()].count("\n")
                                    matched_line_no, window = trim_match(source_segment, base_line_no, matched.start())
                                    matched_line_no = here_string_payload_anchor(label, source_segment, matched_line_no)
                                    break
                    if matched:
                        violation_key = (label, matched_line_no, " ".join(window.split()))
                        if violation_key not in seen_violations:
                            seen_violations.add(violation_key)
                            violations.append(f"{rendered_path}:{matched_line_no}: {label}: {window}")
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

    if yaml is None:
        print(f"ERROR: {MISSING_PYYAML_MESSAGE}", file=sys.stderr)
        return 1

    repo_root = args.repo_root.resolve()
    workflows = workflow_paths(repo_root)
    if not workflows:
        print(f"ERROR: no workflow files found under {repo_root}/.github/workflows", file=sys.stderr)
        return 1

    bad: list[str] = []
    for workflow in workflows:
        try:
            bad.extend(find_violations(workflow))
        except RuntimeError as exc:
            print(f"ERROR: {render_path(workflow, repo_root)}: {exc}", file=sys.stderr)
            return 1

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

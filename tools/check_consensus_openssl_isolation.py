#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


GO_VERIFY_FILE = "clients/go/consensus/verify_sig_openssl.go"
RUST_VERIFY_FILE = "clients/rust/crates/rubin-consensus/src/verify_sig_openssl.rs"


def extract_function_body(text: str, signature: str) -> str | None:
    start = text.find(signature)
    if start < 0:
        return None
    brace = text.find("{", start)
    if brace < 0:
        return None

    depth = 0
    for idx in range(brace, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[brace + 1 : idx]
    return None


def strip_line_comments(text: str, line_comment: str) -> str:
    lines = []
    for line in text.splitlines():
        idx = line.find(line_comment)
        if idx >= 0:
            line = line[:idx]
        lines.append(line)
    return "\n".join(lines)


def strip_c_block_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def strip_double_quoted_strings(text: str) -> str:
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


def sanitize_go_or_c(text: str) -> str:
    text = strip_c_block_comments(text)
    text = strip_line_comments(text, "//")
    text = strip_double_quoted_strings(text)
    return text


def sanitize_rust(text: str) -> str:
    text = strip_line_comments(text, "//")
    text = strip_double_quoted_strings(text)
    return text


def contains_call(body: str, name: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\s*\(", body) is not None


def check_go_verify(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    sanitized_text = sanitize_go_or_c(text)
    c_text = strip_double_quoted_strings(strip_line_comments(text, "//"))
    body = extract_function_body(sanitized_text, "func verifySig(")
    if body is None:
        return [f"{path}: missing func verifySig("]

    if not contains_call(body, "ensureOpenSSLConsensusInit"):
        errors.append(
            f"{path}: verifySig must use ensureOpenSSLConsensusInit() instead of operator-configured bootstrap"
        )
    if contains_call(body, "ensureOpenSSLBootstrap"):
        errors.append(
            f"{path}: verifySig must not call ensureOpenSSLBootstrap() in consensus path"
        )

    consensus_body = extract_function_body(sanitized_text, "func ensureOpenSSLConsensusInit()")
    if consensus_body is not None:
        if contains_call(consensus_body, "ensureOpenSSLBootstrap"):
            errors.append(
                f"{path}: ensureOpenSSLConsensusInit must not delegate to ensureOpenSSLBootstrap()"
            )
        if contains_call(consensus_body, "opensslBootstrap") or contains_call(
            consensus_body, "opensslBootstrapFn"
        ):
            errors.append(
                f"{path}: ensureOpenSSLConsensusInit must not delegate to opensslBootstrap* because that shares config-loading bootstrap"
            )

    consensus_wrapper = extract_function_body(sanitized_text, "func opensslConsensusInit()")
    if consensus_wrapper is None:
        errors.append(f"{path}: missing func opensslConsensusInit()")
    else:
        if contains_call(consensus_wrapper, "rubin_openssl_bootstrap"):
            errors.append(
                f"{path}: opensslConsensusInit must not call rubin_openssl_bootstrap()"
            )

    c_consensus_body = extract_function_body(c_text, "static int rubin_openssl_consensus_init")
    if c_consensus_body is None:
        errors.append(f"{path}: missing static int rubin_openssl_consensus_init")
    else:
        if "OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG" in c_consensus_body:
            errors.append(
                f"{path}: rubin_openssl_consensus_init must not use OPENSSL_INIT_LOAD_CONFIG"
            )
        if (
            contains_call(c_consensus_body, "rubin_set_env_if_empty")
            or contains_call(c_consensus_body, "setenv")
            or contains_call(c_consensus_body, "getenv")
            or "OPENSSL_CONF" in c_consensus_body
            or "OPENSSL_MODULES" in c_consensus_body
        ):
            errors.append(
                f"{path}: rubin_openssl_consensus_init must not read or mutate OPENSSL_CONF/OPENSSL_MODULES"
            )
    return errors


def check_rust_verify(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    sanitized_text = sanitize_rust(text)
    body = extract_function_body(sanitized_text, "pub fn verify_sig(")
    if body is None:
        return [f"{path}: missing pub fn verify_sig("]

    if not contains_call(body, "ensure_openssl_consensus_init"):
        errors.append(
            f"{path}: verify_sig must use ensure_openssl_consensus_init() instead of operator bootstrap"
        )
    if contains_call(body, "ensure_openssl_bootstrap"):
        errors.append(
            f"{path}: verify_sig must not call ensure_openssl_bootstrap() in consensus path"
        )

    consensus_body = extract_function_body(
        sanitized_text, "fn openssl_consensus_bootstrap() -> Result<(), TxError>"
    )
    if consensus_body is None:
        errors.append(f"{path}: missing fn openssl_consensus_bootstrap() -> Result<(), TxError>")
    else:
        if "OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG" in consensus_body:
            errors.append(
                f"{path}: openssl_consensus_bootstrap must not use OPENSSL_INIT_LOAD_CONFIG because inherited OPENSSL_CONF/OPENSSL_MODULES can affect consensus"
            )
        if "set_env_if_empty" in consensus_body or "RUBIN_OPENSSL_" in consensus_body:
            errors.append(
                f"{path}: openssl_consensus_bootstrap must not read or propagate operator-configured OpenSSL env"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail on consensus OpenSSL patterns that allow env/config drift."
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Repository-relative files to inspect.",
    )
    args = parser.parse_args()

    repo_root = Path(".").resolve()
    errors: list[str] = []

    for rel in args.files:
        rel_norm = Path(rel).as_posix()
        path = repo_root / rel_norm
        if not path.exists():
            errors.append(f"{rel_norm}: file does not exist")
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        if rel_norm == GO_VERIFY_FILE:
            errors.extend(check_go_verify(Path(rel_norm), text))
        elif rel_norm == RUST_VERIFY_FILE:
            errors.extend(check_rust_verify(Path(rel_norm), text))

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    print("OK: consensus OpenSSL isolation source policy is satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

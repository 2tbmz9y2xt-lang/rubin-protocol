#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


SCAN_SUFFIXES = {
    ".md",
    ".txt",
    ".py",
    ".mjs",
    ".js",
    ".ts",
    ".go",
    ".rs",
    ".toml",
    ".json",
    ".yml",
    ".yaml",
    ".sh",
    ".c",
    ".h",
}

ALLOWED_MENTION_FILES = {
    "tools/check_crypto_backend_policy.py",
}

FORBIDDEN_BACKEND_RE = re.compile(
    r"(?i)\b(wolfssl|wolfcrypt|liboqs)\b|oqs/|OQS_[A-Z0-9_]+"
)

FORBIDDEN_CLAIM_PATTERNS = [
    re.compile(r"production\s+fips\s+compliance\s+by\s+default", re.IGNORECASE),
    re.compile(r"already\s+certified\s+for\s+production\s+pq", re.IGNORECASE),
    re.compile(r"already\s+fips-validated\s+in\s+production\s+scope", re.IGNORECASE),
]

DOC_PROFILE_REQUIRED_PHRASES = [
    "OpenSSL 3.5+",
    "MUST use",
    "non-OpenSSL PQ backend binding is forbidden",
    'allowed: "NIST/FIPS-aligned PQ implementation profile"',
]

DOC_OPS_REQUIRED_PHRASES = [
    "best-effort runtime gating",
    "not automatic production FIPS compliance",
]

GO_VERIFY_GO_REQUIRED_SNIPPET_GROUPS = [
    ["func verifySig("],
    ["case SUITE_ID_ML_DSA_87:"],
    [
        "func opensslVerifySigOneShot(",
        "func opensslVerifySigDigestOneShot(",
        "func opensslVerifySigMessage(",
    ],
]

GO_VERIFY_CGO_REQUIRED_SNIPPET_GROUPS = [
    ["EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL)"],
    ["EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len)"],
]

GO_VERIFY_ML_DSA_DIRECT_DISPATCH_SNIPPETS = [
    'return opensslVerifySigOneShot("ML-DSA-87", pubkey, signature, digest32[:])',
    'return opensslVerifySigMessage("ML-DSA-87", pubkey, signature, digest32[:])',
    'return verifyWithMapping("ML-DSA-87")',
]

GO_VERIFY_ML_DSA_BINDING_RESOLUTION_SNIPPET = (
    'binding, err := resolveSuiteVerifierBinding("ML-DSA-87", '
    "ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)"
)

GO_VERIFY_ML_DSA_BINDING_HANDOFF_SNIPPET = (
    "return verifySigWithBinding(binding, pubkey, signature, digest32)"
)

GO_VERIFY_ML_DSA_DIRECT_DISPATCH_PATTERNS = [
    re.compile(
        r'return\s+opensslVerifySigOneShot\s*\(\s*,\s*pubkey\s*,\s*signature\s*,\s*digest32\[:\]\s*,?\s*\)'
    ),
    re.compile(
        r'return\s+opensslVerifySigMessage\s*\(\s*,\s*pubkey\s*,\s*signature\s*,\s*digest32\[:\]\s*,?\s*\)'
    ),
    re.compile(r'return\s+verifyWithMapping\s*\(\s*\)'),
]

GO_VERIFY_ML_DSA_DIRECT_DISPATCH_EXACT_PATTERNS = [
    re.compile(
        r'(^|[^`"\\])return\s+opensslVerifySigOneShot\s*\(\s*"ML-DSA-87"\s*,\s*pubkey\s*,\s*signature\s*,\s*digest32\[:\]\s*,?\s*\)'
    ),
    re.compile(
        r'(^|[^`"\\])return\s+opensslVerifySigMessage\s*\(\s*"ML-DSA-87"\s*,\s*pubkey\s*,\s*signature\s*,\s*digest32\[:\]\s*,?\s*\)'
    ),
    re.compile(
        r'(^|[^`"\\])return\s+verifyWithMapping\s*\(\s*"ML-DSA-87"\s*,?\s*\)'
    ),
]

GO_VERIFY_ML_DSA_BINDING_RESOLUTION_PATTERN = re.compile(
    r'binding\s*,\s*err\s*:=\s*resolveSuiteVerifierBinding\s*\(\s*,\s*ML_DSA_87_PUBKEY_BYTES\s*,\s*ML_DSA_87_SIG_BYTES\s*,?\s*\)'
)

GO_VERIFY_ML_DSA_BINDING_RESOLUTION_EXACT_PATTERN = re.compile(
    r'(^|[^`"\\])binding\s*,\s*err\s*:=\s*resolveSuiteVerifierBinding\s*\(\s*"ML-DSA-87"\s*,\s*ML_DSA_87_PUBKEY_BYTES\s*,\s*ML_DSA_87_SIG_BYTES\s*,?\s*\)'
)

GO_VERIFY_ML_DSA_BINDING_HANDOFF_PATTERN = re.compile(
    r'return\s+verifySigWithBinding\s*\(\s*binding\s*,\s*pubkey\s*,\s*signature\s*,\s*digest32\s*,?\s*\)'
)

RUST_VERIFY_REQUIRED_SNIPPETS = [
    "pub fn verify_sig(",
    'SUITE_ID_ML_DSA_87 => Ok(c"ML-DSA-87")',
    "fn parse_openssl_fips_mode(",
    "fn ensure_openssl_bootstrap()",
    "OPENSSL_init_crypto(",
    "OSSL_PROVIDER_load(",
    "EVP_set_default_properties(",
    "fn openssl_verify_sig_digest_oneshot(",
    "EVP_DigestVerifyInit_ex(",
    "core::ptr::null()",
    "EVP_DigestVerify(",
]


def run_git(root: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout


def git_tracked_files(root: Path, prefixes: list[str] | None = None) -> list[str]:
    cmd = ["ls-files"]
    if prefixes:
        cmd.extend(prefixes)
    out = run_git(root, cmd)
    return [line.strip() for line in out.splitlines() if line.strip()]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def should_ignore_claim_line(line: str) -> bool:
    lowered = line.lower()
    return (
        "forbidden" in lowered
        or "must not" in lowered
        or "not automatic" in lowered
        or "do not" in lowered
        or "запрещ" in lowered
    )


def check_forbidden_claims(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if should_ignore_claim_line(line):
            continue
        for pat in FORBIDDEN_CLAIM_PATTERNS:
            if pat.search(line):
                errors.append(
                    f"{path}:{idx}: forbidden compliance claim phrase matched: {pat.pattern!r}"
                )
    return errors


def check_forbidden_backend_refs(
    root: Path, rel_paths: list[str], context: str
) -> list[str]:
    errors: list[str] = []
    for rel in rel_paths:
        path = root / rel
        if path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        if rel in ALLOWED_MENTION_FILES:
            continue
        text = read_text(path)
        match = FORBIDDEN_BACKEND_RE.search(text)
        if match:
            errors.append(
                f"{context}: forbidden backend reference in {rel}: {match.group(0)!r}"
            )
    return errors


def check_required_snippets(path: Path, text: str, snippets: list[str]) -> list[str]:
    errors: list[str] = []
    for snippet in snippets:
        if snippet not in text:
            errors.append(f"{path}: missing required snippet: {snippet!r}")
    return errors


def check_required_snippet_groups(
    path: Path, text: str, snippet_groups: list[list[str]]
) -> list[str]:
    errors: list[str] = []
    for group in snippet_groups:
        if not any(snippet in text for snippet in group):
            errors.append(
                f"{path}: missing required snippet group (any-of): {group!r}"
            )
    return errors


def normalize_for_match(text: str) -> str:
    return " ".join(text.split())


def check_required_snippet_groups_normalized(
    path: Path, text: str, snippet_groups: list[list[str]]
) -> list[str]:
    errors: list[str] = []
    normalized_text = normalize_for_match(text)
    for group in snippet_groups:
        if not any(normalize_for_match(snippet) in normalized_text for snippet in group):
            errors.append(
                f"{path}: missing required snippet group (any-of): {group!r}"
            )
    return errors


def sanitize_go_source(text: str, *, strip_strings: bool) -> str:
    out: list[str] = []
    i = 0
    state = "normal"
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if state == "normal":
            if ch == "/" and nxt == "/":
                out.extend("  ")
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                out.extend("  ")
                i += 2
                state = "block_comment"
                continue
            if ch == '"':
                out.append(" " if strip_strings else ch)
                i += 1
                state = "string"
                continue
            if ch == "`":
                out.append(" " if strip_strings else ch)
                i += 1
                state = "raw_string"
                continue
            if ch == "'":
                out.append(" " if strip_strings else ch)
                i += 1
                state = "rune"
                continue
            out.append(ch)
            i += 1
            continue

        if state == "line_comment":
            if ch == "\n":
                out.append("\n")
                i += 1
                state = "normal"
            else:
                out.append(" ")
                i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                out.extend("  ")
                i += 2
                state = "normal"
            elif ch == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" ")
                i += 1
            continue

        if state == "string":
            if ch == "\\":
                out.append(" " if strip_strings else ch)
                i += 1
                if i < len(text):
                    if strip_strings:
                        out.append("\n" if text[i] == "\n" else " ")
                    else:
                        out.append(text[i])
                    i += 1
                continue
            if ch == '"':
                out.append(" " if strip_strings else ch)
                i += 1
                state = "normal"
            elif ch == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" " if strip_strings else ch)
                i += 1
            continue

        if state == "raw_string":
            if ch == "`":
                out.append(" " if strip_strings else ch)
                i += 1
                state = "normal"
            elif ch == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" " if strip_strings else ch)
                i += 1
            continue

        if state == "rune":
            if ch == "\\":
                out.append(" " if strip_strings else ch)
                i += 1
                if i < len(text):
                    if strip_strings:
                        out.append("\n" if text[i] == "\n" else " ")
                    else:
                        out.append(text[i])
                    i += 1
                continue
            if ch == "'":
                out.append(" " if strip_strings else ch)
                i += 1
                state = "normal"
            elif ch == "\n":
                out.append("\n")
                i += 1
            else:
                out.append(" " if strip_strings else ch)
                i += 1
            continue

    return "".join(out)


def extract_go_verify_mldsa_case(path: Path, text: str) -> tuple[str | None, list[str]]:
    errors: list[str] = []
    lines = text.splitlines()
    in_verify_sig = False
    verify_sig_depth = 0
    switch_depth: int | None = None
    collecting_case = False
    collected_lines: list[str] = []

    for line in lines:
        current_depth = verify_sig_depth
        next_depth = current_depth + line.count("{") - line.count("}")
        stripped = line.lstrip()

        if not in_verify_sig:
            if "func verifySig(" in line:
                in_verify_sig = True
                verify_sig_depth = next_depth
            continue

        if switch_depth is None:
            if re.match(r"^\s*switch\s+suiteID\s*\{", line):
                switch_depth = next_depth
            verify_sig_depth = next_depth
            if verify_sig_depth <= 0:
                break
            continue

        if collecting_case:
            if current_depth < switch_depth:
                return "\n".join(collected_lines), errors
            if current_depth == switch_depth and re.match(r"^\s*(case |default:)", stripped):
                return "\n".join(collected_lines), errors
            collected_lines.append(line)
            verify_sig_depth = next_depth
            if verify_sig_depth <= 0:
                break
            continue

        if current_depth == switch_depth and stripped.startswith("case SUITE_ID_ML_DSA_87:"):
            collecting_case = True
            _, _, same_line_tail = line.partition("case SUITE_ID_ML_DSA_87:")
            if same_line_tail.strip():
                collected_lines.append(same_line_tail)
            verify_sig_depth = next_depth
            continue

        verify_sig_depth = next_depth
        if verify_sig_depth <= 0:
            break

    if collecting_case:
        return "\n".join(collected_lines), errors

    errors.append(f"{path}: missing verifySig ML-DSA-87 case body for policy checks")
    return None, errors


def check_go_verify_required_snippets(path: Path, text: str) -> list[str]:
    structure_text = sanitize_go_source(text, strip_strings=True)
    comment_stripped_text = sanitize_go_source(text, strip_strings=False)
    errors = check_required_snippet_groups_normalized(
        path, structure_text, GO_VERIFY_GO_REQUIRED_SNIPPET_GROUPS
    )
    errors.extend(
        check_required_snippet_groups_normalized(
            path, text, GO_VERIFY_CGO_REQUIRED_SNIPPET_GROUPS
        )
    )
    case_body, case_errors = extract_go_verify_mldsa_case(path, structure_text)
    errors.extend(case_errors)
    if case_body is None:
        return errors
    comment_case_body, comment_case_errors = extract_go_verify_mldsa_case(
        path, comment_stripped_text
    )
    if comment_case_body is None:
        errors.extend(comment_case_errors)
        return errors
    normalized_case_body = normalize_for_match(case_body)
    normalized_comment_case_body = normalize_for_match(comment_case_body)
    has_direct_dispatch = any(
        pattern.search(normalized_case_body)
        for pattern in GO_VERIFY_ML_DSA_DIRECT_DISPATCH_PATTERNS
    ) and any(
        pattern.search(normalized_comment_case_body)
        for pattern in GO_VERIFY_ML_DSA_DIRECT_DISPATCH_EXACT_PATTERNS
    )
    has_binding_resolution = GO_VERIFY_ML_DSA_BINDING_RESOLUTION_PATTERN.search(
        normalized_case_body
    ) is not None and GO_VERIFY_ML_DSA_BINDING_RESOLUTION_EXACT_PATTERN.search(
        normalized_comment_case_body
    ) is not None
    has_binding_handoff = GO_VERIFY_ML_DSA_BINDING_HANDOFF_PATTERN.search(
        normalized_case_body
    ) is not None

    if not (has_direct_dispatch or has_binding_resolution or has_binding_handoff):
        errors.append(
            f"{path}: verifySig ML-DSA-87 case missing required dispatch group (any-of): "
            f"{GO_VERIFY_ML_DSA_DIRECT_DISPATCH_SNIPPETS + [GO_VERIFY_ML_DSA_BINDING_RESOLUTION_SNIPPET]!r}"
        )

    if has_binding_resolution and not has_binding_handoff:
        errors.append(
            f"{path}: verifySig ML-DSA-87 case missing required binding handoff snippet: "
            f"{GO_VERIFY_ML_DSA_BINDING_HANDOFF_SNIPPET!r}"
        )
    if has_binding_handoff and not has_binding_resolution:
        errors.append(
            f"{path}: verifySig ML-DSA-87 case missing required binding resolution snippet: "
            f"{GO_VERIFY_ML_DSA_BINDING_RESOLUTION_SNIPPET!r}"
        )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Crypto backend policy lint (docs + OpenSSL binding invariants)."
    )
    parser.add_argument(
        "--context-root",
        default=".",
        help="Path to spec context repository root (expects spec/* docs).",
    )
    parser.add_argument(
        "--code-root",
        default=".",
        help="Path to code repository root (expects clients/* and tools/*).",
    )
    parser.add_argument(
        "--skip-doc-policy",
        action="store_true",
        help="Skip spec/doc-policy checks.",
    )
    parser.add_argument(
        "--skip-binding-policy",
        action="store_true",
        help="Skip Go/Rust OpenSSL binding invariants checks.",
    )
    args = parser.parse_args()

    context_root = Path(args.context_root).resolve()
    code_root = Path(args.code_root).resolve()

    errors: list[str] = []

    if not args.skip_doc_policy:
        profile = context_root / "spec" / "RUBIN_CRYPTO_BACKEND_PROFILE.md"
        ops = context_root / "spec" / "RUBIN_CRYPTO_BACKEND_OPS.md"
        readme = context_root / "spec" / "README.md"
        required_files = [profile, ops, readme]
        for path in required_files:
            if not path.exists():
                errors.append(f"doc-policy: missing required file: {path}")

        if not errors:
            profile_text = read_text(profile)
            ops_text = read_text(ops)
            readme_text = read_text(readme)

            for phrase in DOC_PROFILE_REQUIRED_PHRASES:
                if phrase not in profile_text:
                    errors.append(
                        "doc-policy: RUBIN_CRYPTO_BACKEND_PROFILE.md missing phrase: "
                        f"{phrase!r}"
                    )
            for phrase in DOC_OPS_REQUIRED_PHRASES:
                if phrase not in ops_text:
                    errors.append(
                        "doc-policy: RUBIN_CRYPTO_BACKEND_OPS.md missing phrase: "
                        f"{phrase!r}"
                    )

            if "./RUBIN_CRYPTO_BACKEND_PROFILE.md" not in readme_text:
                errors.append(
                    "doc-policy: spec/README.md must reference RUBIN_CRYPTO_BACKEND_PROFILE.md"
                )

            errors.extend(check_forbidden_claims(profile, profile_text))
            errors.extend(check_forbidden_claims(ops, ops_text))

            doc_rel_paths = [
                "spec/RUBIN_CRYPTO_BACKEND_PROFILE.md",
                "spec/RUBIN_CRYPTO_BACKEND_OPS.md",
                "spec/README.md",
            ]
            errors.extend(
                check_forbidden_backend_refs(
                    context_root, doc_rel_paths, context="doc-policy"
                )
            )

    if not args.skip_binding_policy:
        go_verify = code_root / "clients" / "go" / "consensus" / "verify_sig_openssl.go"
        rust_verify = (
            code_root
            / "clients"
            / "rust"
            / "crates"
            / "rubin-consensus"
            / "src"
            / "verify_sig_openssl.rs"
        )

        if not go_verify.exists():
            errors.append(f"binding-policy: missing file: {go_verify}")
        if not rust_verify.exists():
            errors.append(f"binding-policy: missing file: {rust_verify}")

        if go_verify.exists():
            go_text = read_text(go_verify)
            errors.extend(check_go_verify_required_snippets(go_verify, go_text))
        if rust_verify.exists():
            rust_text = read_text(rust_verify)
            errors.extend(
                check_required_snippets(rust_verify, rust_text, RUST_VERIFY_REQUIRED_SNIPPETS)
            )

        forbidden_glob = "scripts/crypto/wolfssl/**"
        forbidden_tracked = run_git(code_root, ["ls-files", forbidden_glob]).strip()
        if forbidden_tracked:
            errors.append(
                "binding-policy: tracked files under scripts/crypto/wolfssl are forbidden"
            )

        tracked = git_tracked_files(
            code_root,
            prefixes=[
                "clients/",
                "scripts/",
                "tools/",
                ".github/workflows/",
            ],
        )
        errors.extend(
            check_forbidden_backend_refs(
                code_root, tracked, context="binding-policy"
            )
        )

    if errors:
        for item in errors:
            print(f"ERROR: {item}", file=sys.stderr)
        return 1

    print("OK: crypto backend doc-policy + binding-policy checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

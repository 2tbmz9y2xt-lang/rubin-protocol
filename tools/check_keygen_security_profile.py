#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path


DOC_REQUIRED_PHRASES = [
    "OS-provided CSPRNG",
    "MUST NOT be printed to logs",
    "OpenSSL bootstrap/config/provider initialization MUST run before keygen/sign",
    "Invalid `RUBIN_OPENSSL_FIPS_MODE` MUST fail fast",
    "ML-DSA-87",
    "SLH-DSA-SHAKE-256f",
]

GO_SIGNER_SNIPPETS = [
    "func newOpenSSLRawKeypair(",
    "if err := ensureOpenSSLBootstrap(); err != nil {",
    'newOpenSSLRawKeypair("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES)',
    'newOpenSSLRawKeypair("SLH-DSA-SHAKE-256f", SLH_DSA_SHAKE_256F_PUBKEY_BYTES)',
]

GO_TEST_SNIPPETS = [
    "TestNewOpenSSLRawKeypair_InvalidFIPSModeRejected",
    "TestNewMLDSA87Keypair_InvalidFIPSModeRejected",
    "TestNewSLHDSASHAKE256fKeypair_InvalidFIPSModeRejected",
]

RUST_TEST_SNIPPETS = [
    "EVP_PKEY_keygen_init(ctx) > 0",
    "EVP_PKEY_keygen(ctx, &mut pkey) > 0",
    "EVP_PKEY_get_raw_public_key(pkey, pubkey.as_mut_ptr(), &mut pubkey_len) > 0",
]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def require_snippets(path: Path, text: str, snippets: list[str], errors: list[str]) -> None:
    for snippet in snippets:
        if snippet not in text:
            errors.append(f"{path}: missing required snippet: {snippet!r}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check key-generation security profile docs + runtime guard bindings."
    )
    parser.add_argument(
        "--context-root",
        default=".",
        help="Path to spec repository root (expects spec/*).",
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
        help="Skip Go/Rust runtime-guard binding checks.",
    )
    args = parser.parse_args()

    context_root = Path(args.context_root).resolve()
    code_root = Path(args.code_root).resolve()

    errors: list[str] = []

    profile = context_root / "spec" / "RUBIN_KEY_GENERATION_PROFILE.md"
    readme = context_root / "spec" / "README.md"
    go_signer = code_root / "clients" / "go" / "consensus" / "openssl_signer.go"
    go_tests = code_root / "clients" / "go" / "consensus" / "openssl_signer_additional_test.go"
    rust_tests = (
        code_root
        / "clients"
        / "rust"
        / "crates"
        / "rubin-consensus"
        / "src"
        / "tests.rs"
    )

    required_paths: list[Path] = []
    if not args.skip_doc_policy:
        required_paths.extend([profile, readme])
    if not args.skip_binding_policy:
        required_paths.extend([go_signer, go_tests, rust_tests])

    for path in required_paths:
        if not path.exists():
            errors.append(f"missing required file: {path}")

    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if not args.skip_doc_policy:
        profile_text = read_text(profile)
        readme_text = read_text(readme)
        for phrase in DOC_REQUIRED_PHRASES:
            if phrase not in profile_text:
                errors.append(
                    f"doc-policy: RUBIN_KEY_GENERATION_PROFILE.md missing phrase: {phrase!r}"
                )
        if "./RUBIN_KEY_GENERATION_PROFILE.md" not in readme_text:
            errors.append(
                "doc-policy: spec/README.md must reference RUBIN_KEY_GENERATION_PROFILE.md"
            )

    if not args.skip_binding_policy:
        go_signer_text = read_text(go_signer)
        go_tests_text = read_text(go_tests)
        rust_tests_text = read_text(rust_tests)
        require_snippets(go_signer, go_signer_text, GO_SIGNER_SNIPPETS, errors)
        require_snippets(go_tests, go_tests_text, GO_TEST_SNIPPETS, errors)
        require_snippets(rust_tests, rust_tests_text, RUST_TEST_SNIPPETS, errors)

    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print("OK: key-generation profile docs + runtime guard bindings checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

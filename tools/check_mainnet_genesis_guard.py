#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path


DEVNET_ALL_FF = "f" * 64
HEX_32_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def detect_strict_mode() -> bool:
    forced = os.getenv("RUBIN_RELEASE_NETWORK", "").strip().lower()
    if forced == "mainnet":
        return True
    ref = os.getenv("GITHUB_REF", "")
    return ref.startswith("refs/tags/mainnet-") or ref.startswith("refs/heads/release/mainnet")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def check_code_guards(code_root: Path) -> list[str]:
    errors: list[str] = []
    go_sync = code_root / "clients" / "go" / "node" / "sync.go"
    rust_sync = code_root / "clients" / "rust" / "crates" / "rubin-node" / "src" / "sync.rs"
    go_needles = [
        "mainnet requires explicit expected_target",
        "mainnet expected_target must not equal devnet POW_LIMIT (all-ff)",
    ]
    rust_needles = [
        "mainnet requires explicit expected_target",
        "mainnet expected_target must not equal devnet POW_LIMIT (all-ff)",
    ]

    for path, needles in ((go_sync, go_needles), (rust_sync, rust_needles)):
        if not path.exists():
            errors.append(f"missing file: {path}")
            continue
        text = read_text(path)
        for needle in needles:
            if needle not in text:
                errors.append(f"missing guard marker in {path}: {needle}")
    return errors


def parse_pow_limit_mainnet(network_params_text: str) -> str | None:
    m = re.search(r"`POW_LIMIT_MAINNET`[^\\n]*", network_params_text)
    if not m:
        return None
    hex_match = re.search(r"([0-9a-fA-F]{64})", m.group(0))
    if hex_match:
        return hex_match.group(1).lower()
    return ""


def check_mainnet_artifacts(context_root: Path) -> list[str]:
    errors: list[str] = []
    spec_dir = context_root / "spec"
    network_params = spec_dir / "RUBIN_NETWORK_PARAMS.md"
    publish_doc = spec_dir / "MAINNET_GENESIS_PUBLISH.md"
    required = [
        spec_dir / "MAINNET_GENESIS_BYTES.json",
        spec_dir / "MAINNET_CHAIN_ID.txt",
        spec_dir / "MAINNET_GENESIS_HASH.txt",
    ]

    if not spec_dir.exists():
        return errors
    if not network_params.exists():
        errors.append(f"missing file: {network_params}")
        return errors
    if not publish_doc.exists():
        errors.append(f"missing file: {publish_doc}")

    params_text = read_text(network_params)
    pow_limit_mainnet = parse_pow_limit_mainnet(params_text)
    if pow_limit_mainnet is None:
        errors.append("RUBIN_NETWORK_PARAMS.md must define `POW_LIMIT_MAINNET`")
    elif pow_limit_mainnet == "":
        errors.append("`POW_LIMIT_MAINNET` must contain a concrete 32-byte hex value")
    elif not HEX_32_RE.fullmatch(pow_limit_mainnet):
        errors.append("`POW_LIMIT_MAINNET` must be exactly 32-byte hex")
    elif pow_limit_mainnet == DEVNET_ALL_FF:
        errors.append("`POW_LIMIT_MAINNET` must not equal all-FF devnet POW limit")

    for path in required:
        if not path.exists():
            errors.append(f"missing file: {path}")
            continue
        raw = read_text(path).strip()
        if not raw:
            errors.append(f"empty artifact: {path}")
            continue
        lowered = raw.lower()
        if any(token in lowered for token in ("tbd", "unset", "not_published", "placeholder")):
            errors.append(f"artifact still contains placeholder token: {path}")
        if path.name.endswith(".txt") and not HEX_32_RE.fullmatch(raw):
            errors.append(f"artifact must be 32-byte hex: {path}")
        if path.name.endswith(".json"):
            try:
                parsed = json.loads(raw)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"invalid json in {path}: {exc}")
                continue
            for key in ("genesis_header_bytes_hex", "genesis_tx_bytes_hex", "pow_limit_mainnet_hex"):
                value = parsed.get(key, "")
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"{path}: missing or empty `{key}`")
                elif "tbd" in value.lower() or "unset" in value.lower():
                    errors.append(f"{path}: placeholder value in `{key}`")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate anti-devnet mainnet release guards (spec + code)."
    )
    parser.add_argument(
        "--context-root",
        default=".",
        help="Path to context repo (contains spec/ in spec-private).",
    )
    parser.add_argument(
        "--code-root",
        default=".",
        help="Path to code repo (rubin-protocol).",
    )
    parser.add_argument(
        "--strict-mainnet",
        action="store_true",
        help="Force strict mainnet artifact checks regardless of branch/tag env.",
    )
    args = parser.parse_args()

    context_root = Path(args.context_root).resolve()
    code_root = Path(args.code_root).resolve()

    errors: list[str] = []
    errors.extend(check_code_guards(code_root))

    strict = args.strict_mainnet or detect_strict_mode()
    if strict:
        errors.extend(check_mainnet_artifacts(context_root))
    else:
        spec_dir = context_root / "spec"
        if spec_dir.exists():
            # Lightweight non-strict safety: forbid explicit all-FF mainnet value if declared.
            network_params = spec_dir / "RUBIN_NETWORK_PARAMS.md"
            if network_params.exists():
                pow_limit_mainnet = parse_pow_limit_mainnet(read_text(network_params))
                if pow_limit_mainnet and pow_limit_mainnet == DEVNET_ALL_FF:
                    errors.append("non-strict check: `POW_LIMIT_MAINNET` must not equal all-FF devnet value")

    if errors:
        print("MAINNET_GENESIS_GUARD: FAIL")
        for err in errors:
            print(f"- {err}")
        return 1

    mode = "strict" if strict else "non-strict"
    print(f"MAINNET_GENESIS_GUARD: PASS ({mode})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

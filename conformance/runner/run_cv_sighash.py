#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import os.path
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ClientCmd:
    name: str
    cwd: Path
    argv_prefix: list[str]


def run(client: ClientCmd, argv: list[str]) -> str:
    timeout_s = int(os.environ.get("RUBIN_CONFORMANCE_TIMEOUT_S", "60"))
    p = subprocess.run(
        client.argv_prefix + argv,
        cwd=str(client.cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout_s,
    )
    if p.returncode != 0:
        raise RuntimeError(
            f"{client.name} failed (exit={p.returncode})\n"
            f"cmd: {' '.join(client.argv_prefix + argv)}\n"
            f"cwd: {client.cwd}\n"
            f"stderr:\n{p.stderr.strip()}\n"
        )
    return p.stdout.strip()

def relpath(from_dir: Path, to_path: Path) -> str:
    return os.path.relpath(str(to_path), start=str(from_dir))


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        obj = yaml.safe_load(f)
    if not isinstance(obj, dict):
        raise ValueError(f"fixture root must be a mapping: {path}")
    return obj


def main() -> int:
    parser = argparse.ArgumentParser(description="Run CV-SIGHASH conformance vectors against Rust + Go clients.")
    parser.add_argument(
        "--fixture",
        default=None,
        help="Path to CV-SIGHASH.yml (default: repo/conformance/fixtures/CV-SIGHASH.yml)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Chain instance profile Markdown (fallback if a test lacks chain_id_hex)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    fixture_path = Path(args.fixture).resolve() if args.fixture else repo_root / "conformance" / "fixtures" / "CV-SIGHASH.yml"
    profile_path = (
        Path(args.profile).resolve()
        if args.profile
        else repo_root / "spec" / "RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md"
    )

    fixture = load_yaml(fixture_path)
    if fixture.get("gate") != "CV-SIGHASH":
        raise ValueError(f"unexpected gate in fixture: {fixture_path}")
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        raise ValueError(f"fixture has no tests: {fixture_path}")

    rust_prefix: list[str] = [
        "cargo",
        "run",
        "-q",
        "--manifest-path",
        "clients/rust/Cargo.toml",
    ]
    if os.environ.get("RUBIN_CONFORMANCE_RUST_NO_DEFAULT", "").strip() not in ("", "0", "false", "False"):
        rust_prefix.append("--no-default-features")
    rust_features = os.environ.get("RUBIN_CONFORMANCE_RUST_FEATURES", "").strip()
    if rust_features:
        rust_prefix.extend(["--features", rust_features])
    rust_prefix.extend(["-p", "rubin-node", "--"])

    rust = ClientCmd(
        name="rust",
        cwd=repo_root,
        argv_prefix=rust_prefix,
    )

    go_prefix: list[str] = ["go", "-C", "clients/go", "run"]
    go_tags = os.environ.get("RUBIN_CONFORMANCE_GO_TAGS", "").strip()
    if go_tags:
        go_prefix.extend(["-tags", go_tags])
    go_prefix.append("./node")

    go = ClientCmd(
        name="go",
        cwd=repo_root,
        argv_prefix=go_prefix,
    )

    failures: list[str] = []
    executed = 0

    for t in tests:
        if not isinstance(t, dict):
            failures.append("invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"{test_id}: missing/invalid context")
            continue

        tx_hex = ctx.get("tx_hex")
        if not isinstance(tx_hex, str) or tx_hex == "":
            failures.append(f"{test_id}: missing tx_hex")
            continue

        expected_txid = t.get("expected_txid_sha3_256_hex")
        expected_sighash = t.get("expected_sighash_v1_hex")

        try:
            if isinstance(expected_txid, str) and expected_txid:
                out_r = run(rust, ["txid", "--tx-hex", tx_hex])
                out_g = run(go, ["txid", "--tx-hex", tx_hex])
                executed += 1
                if out_r != expected_txid:
                    failures.append(f"{test_id}: rust txid mismatch: got={out_r} expected={expected_txid}")
                if out_g != expected_txid:
                    failures.append(f"{test_id}: go txid mismatch: got={out_g} expected={expected_txid}")
                if out_r != out_g:
                    failures.append(f"{test_id}: cross-client txid mismatch: rust={out_r} go={out_g}")

            if isinstance(expected_sighash, str) and expected_sighash:
                input_index = ctx.get("input_index")
                input_value = ctx.get("input_value")
                chain_id_hex = ctx.get("chain_id_hex")
                if not isinstance(input_index, int) or input_index < 0:
                    failures.append(f"{test_id}: invalid input_index")
                    continue
                if not isinstance(input_value, int) or input_value < 0:
                    failures.append(f"{test_id}: invalid input_value")
                    continue

                rust_chain_args: list[str]
                go_chain_args: list[str]
                if isinstance(chain_id_hex, str) and chain_id_hex:
                    rust_chain_args = ["--chain-id-hex", chain_id_hex]
                    go_chain_args = ["--chain-id-hex", chain_id_hex]
                else:
                    rust_chain_args = ["--profile", relpath(rust.cwd, profile_path)]
                    go_chain_args = ["--profile", relpath(go.cwd, profile_path)]

                out_r = run(
                    rust,
                    [
                        "sighash",
                        "--tx-hex",
                        tx_hex,
                        "--input-index",
                        str(input_index),
                        "--input-value",
                        str(input_value),
                        *rust_chain_args,
                    ],
                )
                out_g = run(
                    go,
                    [
                        "sighash",
                        "--tx-hex",
                        tx_hex,
                        "--input-index",
                        str(input_index),
                        "--input-value",
                        str(input_value),
                        *go_chain_args,
                    ],
                )
                executed += 1
                if out_r != expected_sighash:
                    failures.append(f"{test_id}: rust sighash mismatch: got={out_r} expected={expected_sighash}")
                if out_g != expected_sighash:
                    failures.append(f"{test_id}: go sighash mismatch: got={out_g} expected={expected_sighash}")
                if out_r != out_g:
                    failures.append(f"{test_id}: cross-client sighash mismatch: rust={out_r} go={out_g}")

        except Exception as e:  # noqa: BLE001
            failures.append(f"{test_id}: runner error: {e}")

    if failures:
        sys.stderr.write("CV-SIGHASH: FAIL\n")
        for f in failures:
            sys.stderr.write(f"- {f}\n")
        return 1

    sys.stdout.write(f"CV-SIGHASH: PASS ({executed} checks)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

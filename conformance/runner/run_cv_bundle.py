#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import os.path
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from run_cv_common import make_parse_tx_bytes, parse_int, parse_hex


@dataclass(frozen=True)
class ClientCmd:
    name: str
    cwd: Path
    argv_prefix: list[str]


def run_result(client: ClientCmd, argv: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if client.name == "go" and not env.get("GOCACHE", "").strip():
        fallback_cache = Path(tempfile.gettempdir()) / "rubin-conformance-go-cache"
        fallback_cache.mkdir(parents=True, exist_ok=True)
        env["GOCACHE"] = str(fallback_cache)

    return subprocess.run(
        client.argv_prefix + argv,
        cwd=str(client.cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def run_success(client: ClientCmd, argv: list[str]) -> str:
    p = run_result(client, argv)
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


def run_compactsize(gate: str, fixture: dict[str, Any], rust: ClientCmd, go: ClientCmd, failures: list[str]) -> int:
    vectors = fixture.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        failures.append(f"{gate}: fixture has no vectors")
        return 0

    executed = 0
    for t in vectors:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid vector entry")
            continue
        name = str(t.get("name", t.get("id", "<missing name>")))
        value = t.get("value")
        encoding = t.get("encoding_hex")
        if not isinstance(encoding, str) or encoding == "":
            failures.append(f"{gate}::{name}: missing encoding_hex")
            continue
        if not isinstance(value, int):
            failures.append(f"{gate}::{name}: missing value")
            continue

        expected = str(value)
        try:
            out_r = run_success(rust, ["compactsize", "--encoded-hex", encoding])
            out_g = run_success(go, ["compactsize", "--encoded-hex", encoding])
            executed += 1
            if out_r != expected:
                failures.append(f"{gate}::{name}: rust compactsize mismatch: got={out_r} expected={expected}")
            if out_g != expected:
                failures.append(f"{gate}::{name}: go compactsize mismatch: got={out_g} expected={expected}")
            if out_r != out_g:
                failures.append(f"{gate}::{name}: cross-client compactsize mismatch: rust={out_r} go={out_g}")
        except Exception as e:
            failures.append(f"{gate}::{name}: runner error: {e}")

    return executed


def run_parse(
    gate: str,
    fixture: dict[str, Any],
    rust: ClientCmd,
    go: ClientCmd,
    failures: list[str],
    skip_reasons: list[str],
) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append(f"{gate}: fixture has no tests")
        return 0

    executed = 0
    runnable = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append(f"{gate}: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"{gate}:{test_id}: missing context")
            continue

        tx_hex_ctx = ctx.get("tx_hex")
        if isinstance(tx_hex_ctx, str) and tx_hex_ctx:
            tx_hex = tx_hex_ctx
        else:
            try:
                tx_hex = make_parse_tx_bytes(ctx)
            except Exception as e:
                skip_reasons.append(f"{gate}:{test_id}: no parse fixture data: {e}")
                continue

        expected_code = str(t.get("expected_code", "")).upper() if t.get("expected_code") else ""
        expected_error = str(t.get("expected_error", "")).upper() if t.get("expected_error") else ""
        if not expected_code and not expected_error:
            failures.append(f"{gate}:{test_id}: neither expected_code nor expected_error")
            continue

        max_witness = ctx.get("witness_size_bytes")
        max_witness_bytes = ""
        if isinstance(max_witness, int) and max_witness >= 0:
            max_witness_bytes = str(max_witness)

        for side in ("rust", "go"):
            client = rust if side == "rust" else go
            argv = ["parse", "--tx-hex", tx_hex]
            if max_witness_bytes:
                argv.extend(["--max-witness-bytes", max_witness_bytes])
            p = run_result(client, argv)
            if expected_code:
                if p.returncode != 0:
                    failures.append(f"{gate}:{test_id}: {side} expected pass, exit={p.returncode} stderr={p.stderr.strip()}")
                else:
                    out = p.stdout.strip()
                    if out != "OK":
                        failures.append(f"{gate}:{test_id}: {side} expected OK, got={out}")
                continue

            if expected_error:
                code = expected_error
                if p.returncode == 0:
                    failures.append(f"{gate}:{test_id}: {side} expected {code} but parse succeeded")
                else:
                    got = p.stderr.strip()
                    if code not in got:
                        failures.append(f"{gate}:{test_id}: {side} expected {code}, got={got}")

        runnable += 1
        if expected_code:
            executed += 2
        if expected_error:
            executed += 2

    if runnable == 0:
        skip_reasons.append(f"{gate}: no runnable tx_hex vectors in fixture")

    return executed


def run_sighash(fixture: dict[str, Any], rust: ClientCmd, go: ClientCmd, failures: list[str], profile_path: Path) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append("CV-SIGHASH: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append("CV-SIGHASH: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"CV-SIGHASH:{test_id}: missing/invalid context")
            continue

        tx_hex = ctx.get("tx_hex")
        if not isinstance(tx_hex, str) or tx_hex == "":
            failures.append(f"CV-SIGHASH:{test_id}: missing tx_hex")
            continue

        expected_txid = t.get("expected_txid_sha3_256_hex")
        expected_sighash = t.get("expected_sighash_v1_hex")
        try:
            if isinstance(expected_txid, str) and expected_txid:
                out_r = run_success(rust, ["txid", "--tx-hex", tx_hex])
                out_g = run_success(go, ["txid", "--tx-hex", tx_hex])
                executed += 1
                if out_r != expected_txid:
                    failures.append(f"CV-SIGHASH:{test_id}: rust txid mismatch: got={out_r} expected={expected_txid}")
                if out_g != expected_txid:
                    failures.append(f"CV-SIGHASH:{test_id}: go txid mismatch: got={out_g} expected={expected_txid}")
                if out_r != out_g:
                    failures.append(f"CV-SIGHASH:{test_id}: cross-client txid mismatch: rust={out_r} go={out_g}")

            if isinstance(expected_sighash, str) and expected_sighash:
                input_index = ctx.get("input_index")
                input_value = ctx.get("input_value")
                chain_id_hex = ctx.get("chain_id_hex")
                if not isinstance(input_index, int) or input_index < 0:
                    failures.append(f"CV-SIGHASH:{test_id}: invalid input_index")
                    continue
                if not isinstance(input_value, int) or input_value < 0:
                    failures.append(f"CV-SIGHASH:{test_id}: invalid input_value")
                    continue

                if isinstance(chain_id_hex, str) and chain_id_hex:
                    rust_chain_args = ["--chain-id-hex", chain_id_hex]
                    go_chain_args = ["--chain-id-hex", chain_id_hex]
                else:
                    rust_chain_args = ["--profile", relpath(rust.cwd, profile_path)]
                    go_chain_args = ["--profile", relpath(go.cwd, profile_path)]

                out_r = run_success(
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
                out_g = run_success(
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
                    failures.append(f"CV-SIGHASH:{test_id}: rust sighash mismatch: got={out_r} expected={expected_sighash}")
                if out_g != expected_sighash:
                    failures.append(f"CV-SIGHASH:{test_id}: go sighash mismatch: got={out_g} expected={expected_sighash}")
                if out_r != out_g:
                    failures.append(f"CV-SIGHASH:{test_id}: cross-client sighash mismatch: rust={out_r} go={out_g}")

        except Exception as e:  # noqa: BLE001
            failures.append(f"CV-SIGHASH:{test_id}: runner error: {e}")

    return executed


def run_sigcheck(
    fixture: dict[str, Any],
    rust: ClientCmd,
    go: ClientCmd,
    failures: list[str],
    profile_path: Path,
) -> int:
    tests = fixture.get("tests")
    if not isinstance(tests, list) or not tests:
        failures.append("CV-SIGCHECK: fixture has no tests")
        return 0

    executed = 0
    for t in tests:
        if not isinstance(t, dict):
            failures.append("CV-SIGCHECK: invalid test entry (not a mapping)")
            continue
        test_id = str(t.get("id", "<missing id>"))
        ctx = t.get("context")
        if not isinstance(ctx, dict):
            failures.append(f"CV-SIGCHECK:{test_id}: missing context")
            continue

        tx_hex_ctx = ctx.get("tx_hex")
        if isinstance(tx_hex_ctx, str) and tx_hex_ctx:
            tx_hex = tx_hex_ctx
        else:
            try:
                tx_hex = make_parse_tx_bytes(ctx)
            except Exception as e:
                failures.append(f"CV-SIGCHECK:{test_id}: no parse fixture data: {e}")
                continue

        expected_code = str(t.get("expected_code", "")).upper() if t.get("expected_code") else ""
        expected_error = str(t.get("expected_error", "")).upper() if t.get("expected_error") else ""
        if not expected_code and not expected_error:
            failures.append(f"CV-SIGCHECK:{test_id}: neither expected_code nor expected_error")
            continue

        prevout_covenant_type = ctx.get("prevout_covenant_type")
        prevout_covenant_data_hex = ctx.get("prevout_covenant_data_hex")
        if not isinstance(prevout_covenant_data_hex, str) or prevout_covenant_data_hex == "":
            failures.append(f"CV-SIGCHECK:{test_id}: missing prevout_covenant_data_hex")
            continue
        try:
            _ = parse_hex(prevout_covenant_data_hex)
        except Exception as e:
            failures.append(f"CV-SIGCHECK:{test_id}: invalid prevout_covenant_data_hex: {e}")
            continue

        input_index = ctx.get("input_index")
        input_value = ctx.get("input_value")
        if input_index is None:
            failures.append(f"CV-SIGCHECK:{test_id}: missing input_index")
            continue
        if input_value is None:
            failures.append(f"CV-SIGCHECK:{test_id}: missing input_value")
            continue
        if prevout_covenant_type is None:
            failures.append(f"CV-SIGCHECK:{test_id}: missing prevout_covenant_type")
            continue

        try:
            input_index = parse_int(input_index)
            if input_index < 0:
                raise ValueError("input_index must be >= 0")
            input_value = parse_int(input_value)
            if input_value < 0:
                raise ValueError("input_value must be >= 0")
            prevout_type = parse_int(prevout_covenant_type)
            if prevout_type < 0:
                raise ValueError("prevout_covenant_type must be >= 0")
        except (TypeError, ValueError, OverflowError) as e:
            failures.append(f"CV-SIGCHECK:{test_id}: invalid integer field: {e}")
            continue

        chain_height = ctx.get("chain_height")
        chain_timestamp = ctx.get("chain_timestamp")
        chain_id_hex = ctx.get("chain_id_hex")

        chain_args = []
        if isinstance(chain_id_hex, str) and chain_id_hex:
            chain_args = ["--chain-id-hex", chain_id_hex]
        else:
            chain_args = ["--profile", relpath(rust.cwd, profile_path)]

        if chain_height is not None:
            try:
                chain_args.extend(["--chain-height", str(parse_int(chain_height))])
            except (TypeError, ValueError, OverflowError) as e:
                failures.append(f"CV-SIGCHECK:{test_id}: invalid chain-height: {e}")
                continue

        if chain_timestamp is not None:
            try:
                chain_args.extend(["--chain-timestamp", str(parse_int(chain_timestamp))])
            except (TypeError, ValueError, OverflowError) as e:
                failures.append(f"CV-SIGCHECK:{test_id}: invalid chain-timestamp: {e}")
                continue

        if ctx.get("suite_id_02_active"):
            chain_args.append("--suite-id-02-active")

        cmd = [
            "verify",
            "--tx-hex",
            tx_hex,
            "--input-index",
            str(input_index),
            "--input-value",
            str(input_value),
            "--prevout-covenant-type",
            str(prevout_type),
            "--prevout-covenant-data-hex",
            prevout_covenant_data_hex,
            *chain_args,
        ]

        pr = run_result(rust, cmd)
        pg = run_result(go, cmd)

        out_r = pr.stdout.strip()
        err_r = pr.stderr.strip()
        rc_r = pr.returncode

        out_g = pg.stdout.strip()
        err_g = pg.stderr.strip()
        rc_g = pg.returncode

        executed += 1

        if expected_code:
            if rc_r != 0:
                failures.append(f"CV-SIGCHECK:{test_id}: rust expected {expected_code} but failed: {err_r}")
            elif out_r != "OK":
                failures.append(f"CV-SIGCHECK:{test_id}: rust output mismatch: got={out_r}")
            if rc_g != 0:
                failures.append(f"CV-SIGCHECK:{test_id}: go expected {expected_code} but failed: {err_g}")
            elif out_g != "OK":
                failures.append(f"CV-SIGCHECK:{test_id}: go output mismatch: got={out_g}")
            if out_r != out_g:
                failures.append(f"CV-SIGCHECK:{test_id}: cross-client pass output mismatch: rust={out_r} go={out_g}")
            if rc_r != rc_g:
                failures.append(f"CV-SIGCHECK:{test_id}: cross-client exit mismatch: rust={rc_r} go={rc_g}")
            continue

        if expected_error:
            code = expected_error
            if rc_r == 0:
                failures.append(f"CV-SIGCHECK:{test_id}: rust expected {code} but succeeded: {out_r}")
            elif code not in err_r:
                failures.append(f"CV-SIGCHECK:{test_id}: rust expected {code}, got={err_r}")

            if rc_g == 0:
                failures.append(f"CV-SIGCHECK:{test_id}: go expected {code} but succeeded: {out_g}")
            elif code not in err_g:
                failures.append(f"CV-SIGCHECK:{test_id}: go expected {code}, got={err_g}")

            continue

    return executed


def main() -> int:
    parser = argparse.ArgumentParser(description="Run all supported conformance gates against Rust + Go clients.")
    parser.add_argument(
        "--bundle",
        default=None,
        help="Path to RUBIN_L1_CONFORMANCE_BUNDLE_v1.1.yaml",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Chain instance profile Markdown (fallback if test lacks chain_id_hex)",
    )
    parser.add_argument(
        "--fixture-dir",
        default="conformance/fixtures",
        help="Fixture directory under repo root",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    bundle_path = Path(args.bundle).resolve() if args.bundle else repo_root / "conformance/fixtures/RUBIN_L1_CONFORMANCE_BUNDLE_v1.1.yaml"
    fixture_dir = Path(args.fixture_dir)
    if not fixture_dir.is_absolute():
        fixture_dir = (repo_root / fixture_dir).resolve()

    profile_path = (
        Path(args.profile).resolve()
        if args.profile
        else repo_root / "spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md"
    )

    bundle = load_yaml(bundle_path)
    gate_map = {}
    for entry in bundle.get("mandatory_gates", []) if isinstance(bundle.get("mandatory_gates"), list) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name", ""))
        file = entry.get("file")
        if not file:
            continue
        gate_map[name] = Path(file)

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

    go_prefix: list[str] = ["go", "-C", "clients/go", "run"]
    go_tags = os.environ.get("RUBIN_CONFORMANCE_GO_TAGS", "").strip()
    if go_tags:
        go_prefix.extend(["-tags", go_tags])
    go_prefix.append("./node")

    rust = ClientCmd(name="rust", cwd=repo_root, argv_prefix=rust_prefix)
    go = ClientCmd(name="go", cwd=repo_root, argv_prefix=go_prefix)

    failures: list[str] = []
    skips: list[str] = []
    checks = 0
    skipped = []

    for gate, rel in gate_map.items():
        rel_path = Path(rel)
        if rel_path.is_absolute():
            fixture_path = rel_path
        else:
            manifest_path = (repo_root / rel_path).resolve()
            if manifest_path.exists():
                fixture_path = manifest_path
            else:
                fixture_path = (fixture_dir / rel_path).resolve()
        if not fixture_path.exists():
            failures.append(f"{gate}: fixture not found at {fixture_path}")
            continue
        fixture = load_yaml(fixture_path)

        if gate == "CV-COMPACTSIZE":
            checks += run_compactsize(gate, fixture, rust, go, failures)
            continue
        if gate == "CV-SIGHASH":
            checks += run_sighash(fixture, rust, go, failures, profile_path)
            continue
        if gate == "CV-SIGCHECK":
            checks += run_sigcheck(fixture, rust, go, failures, profile_path)
            continue
        if gate == "CV-PARSE":
            checks += run_parse(gate, fixture, rust, go, failures, skips)
            continue

        skipped.append(gate)

    if skips:
        for note in skips:
            sys.stdout.write(f"CONFORMANCE-BUNDLE: SKIP {note}\n")
    if skipped:
        for gate in skipped:
            sys.stdout.write(f"CONFORMANCE-BUNDLE: SKIP {gate}: no runner support in unified execution yet\n")

    if failures:
        sys.stderr.write("CONFORMANCE-BUNDLE: FAIL\n")
        for f in failures:
            sys.stderr.write(f"- {f}\n")
        if checks > 0:
            sys.stderr.write(f"Executed checks: {checks}\n")
        return 1

    sys.stdout.write(f"CONFORMANCE-BUNDLE: PASS ({checks} checks)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

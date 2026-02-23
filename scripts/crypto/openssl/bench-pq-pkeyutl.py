#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import tempfile
import time
from pathlib import Path


ALGORITHMS = [
    ("ML-DSA-87", 300),
    ("SLH-DSA-SHAKE-256f", 40),
]


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def timed_loop(cmd: list[str], iterations: int) -> list[float]:
    durations_ms: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.perf_counter()
        durations_ms.append((end - start) * 1000.0)
    return durations_ms


def summarize(samples_ms: list[float]) -> dict[str, float]:
    mean_ms = statistics.fmean(samples_ms)
    median_ms = statistics.median(samples_ms)
    sorted_samples = sorted(samples_ms)
    p95_ms = sorted_samples[min(len(sorted_samples) - 1, int(len(sorted_samples) * 0.95))]
    p99_ms = sorted_samples[min(len(sorted_samples) - 1, int(len(sorted_samples) * 0.99))]
    return {
        "iterations": len(samples_ms),
        "mean_ms": mean_ms,
        "median_ms": median_ms,
        "p95_ms": p95_ms,
        "p99_ms": p99_ms,
        "ops_per_sec": 1000.0 / mean_ms if mean_ms > 0 else 0.0,
    }


def file_size(path: Path) -> int:
    return path.stat().st_size


def benchmark_algorithm(openssl_bin: Path, algorithm: str, iterations: int, msg_path: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="rubin-openssl-bench-") as td:
        tmp = Path(td)
        key = tmp / "key.pem"
        pub = tmp / "pub.pem"
        sig = tmp / "sig.bin"

        run([str(openssl_bin), "genpkey", "-algorithm", algorithm, "-out", str(key)])
        run([str(openssl_bin), "pkey", "-in", str(key), "-pubout", "-out", str(pub)])
        run([str(openssl_bin), "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(msg_path), "-out", str(sig)])
        run(
            [
                str(openssl_bin),
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(pub),
                "-rawin",
                "-in",
                str(msg_path),
                "-sigfile",
                str(sig),
            ]
        )

        sign_cmd = [
            str(openssl_bin),
            "pkeyutl",
            "-sign",
            "-inkey",
            str(key),
            "-rawin",
            "-in",
            str(msg_path),
            "-out",
            str(sig),
        ]
        verify_cmd = [
            str(openssl_bin),
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(pub),
            "-rawin",
            "-in",
            str(msg_path),
            "-sigfile",
            str(sig),
        ]

        sign_samples = timed_loop(sign_cmd, iterations)
        run(sign_cmd)
        verify_samples = timed_loop(verify_cmd, iterations)

        return {
            "algorithm": algorithm,
            "iterations": iterations,
            "public_key_bytes": file_size(pub),
            "signature_bytes": file_size(sig),
            "sign": summarize(sign_samples),
            "verify": summarize(verify_samples),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark PQ signature ops via OpenSSL pkeyutl")
    parser.add_argument(
        "--openssl-bin",
        default=str(Path.home() / ".cache" / "rubin-openssl" / "bundle-3.5.5" / "bin" / "openssl"),
    )
    parser.add_argument(
        "--output-json",
        default="",
        help="Optional path to write full JSON results",
    )
    parser.add_argument(
        "--msg-bytes",
        type=int,
        default=32,
        help="Message size in bytes",
    )
    args = parser.parse_args()

    openssl_bin = Path(args.openssl_bin)
    if not openssl_bin.exists():
        raise SystemExit(f"openssl binary not found: {openssl_bin}")

    version = subprocess.check_output([str(openssl_bin), "version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="rubin-openssl-msg-") as td:
        msg_path = Path(td) / "msg.bin"
        msg_path.write_bytes(os.urandom(args.msg_bytes))

        results = {
            "openssl_bin": str(openssl_bin),
            "openssl_version": version,
            "message_bytes": args.msg_bytes,
            "benchmarks": [],
        }
        for algorithm, iterations in ALGORITHMS:
            bench = benchmark_algorithm(openssl_bin, algorithm, iterations, msg_path)
            results["benchmarks"].append(bench)

    if args.output_json:
        out_path = Path(args.output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

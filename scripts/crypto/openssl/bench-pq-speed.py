#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


ROW_RE = re.compile(
    r"^\s*(?P<alg>ML-DSA-87|SLH-DSA-SHAKE-256f)\s+"
    r"(?P<keygen_sec>[0-9.]+)s\s+"
    r"(?P<sign_sec>[0-9.]+)s\s+"
    r"(?P<verify_sec>[0-9.]+)s\s+"
    r"(?P<keygens_s>[0-9.]+)\s+"
    r"(?P<sign_s>[0-9.]+)\s+"
    r"(?P<verify_s>[0-9.]+)\s*$"
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run OpenSSL speed benchmark for PQ signature algorithms")
    parser.add_argument(
        "--openssl-bin",
        default=str(Path.home() / ".cache" / "rubin-openssl" / "bundle-3.5.5" / "bin" / "openssl"),
    )
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--output-json", default="")
    args = parser.parse_args()

    openssl_bin = Path(args.openssl_bin)
    if not openssl_bin.exists():
        raise SystemExit(f"openssl binary not found: {openssl_bin}")

    cmd = [
        str(openssl_bin),
        "speed",
        "-elapsed",
        "-signature-algorithms",
        "-seconds",
        str(args.seconds),
        "ML-DSA-87",
        "SLH-DSA-SHAKE-256f",
    ]
    out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)

    rows = []
    for line in out.splitlines():
        match = ROW_RE.match(line)
        if not match:
            continue
        record = {"algorithm": match.group("alg")}
        for key in ["keygen_sec", "sign_sec", "verify_sec", "keygens_s", "sign_s", "verify_s"]:
            record[key] = float(match.group(key))
        rows.append(record)

    if len(rows) != 2:
        raise SystemExit(f"failed to parse speed output\n{out}")

    rows = sorted(rows, key=lambda row: row["algorithm"])
    mldsa = next(row for row in rows if row["algorithm"] == "ML-DSA-87")
    slh = next(row for row in rows if row["algorithm"] == "SLH-DSA-SHAKE-256f")

    result = {
        "openssl_bin": str(openssl_bin),
        "seconds": args.seconds,
        "raw_output": out,
        "benchmarks": rows,
        "ratios": {
            "verify_latency_slh_over_mldsa": slh["verify_sec"] / mldsa["verify_sec"],
            "sign_latency_slh_over_mldsa": slh["sign_sec"] / mldsa["sign_sec"],
            "verify_throughput_mldsa_over_slh": mldsa["verify_s"] / slh["verify_s"],
            "sign_throughput_mldsa_over_slh": mldsa["sign_s"] / slh["sign_s"],
        },
    }

    if args.output_json:
        output_path = Path(args.output_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

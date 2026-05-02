#!/usr/bin/env python3
from __future__ import annotations

import json
# Tests execute repo-local Python CLIs through argv lists only.
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPARE = REPO_ROOT / "scripts" / "runtime_perf" / "compare_runtime_perf.py"
PARSE_COMBINED = REPO_ROOT / "scripts" / "benchmarks" / "parse_go_bench.py"
SLO = REPO_ROOT / "scripts" / "benchmarks" / "combined_load_slo.json"


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class RuntimePerfAdvisoryTests(unittest.TestCase):
    def run_compare(self, base: Path, head: Path, out: Path) -> dict:
        summary = out / "summary.md"
        delta = out / "delta.json"
        # The command is a repo-local script through sys.executable with temp file arguments only.
        proc = subprocess.run(  # nosec B603
            [
                sys.executable,
                str(COMPARE),
                "--base-dir",
                str(base),
                "--head-dir",
                str(head),
                "--summary",
                str(summary),
                "--output",
                str(delta),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(summary.exists())
        self.assertTrue(delta.exists())
        return json.loads(delta.read_text(encoding="utf-8"))

    def test_all_selected_low_noise_metrics_pass_when_within_thresholds(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            write_json(
                base / "go_metrics.json",
                {
                    "suite": "go",
                    "metrics": {
                        "BenchmarkMempoolAddTx": {"iterations": 1, "ns_per_op": 100.0, "b_per_op": 10.0, "allocs_per_op": 1.0},
                        "BenchmarkMempoolRelayMetadata": {"iterations": 1, "ns_per_op": 100.0, "b_per_op": 10.0, "allocs_per_op": 1.0},
                        "BenchmarkCloneChainState": {"iterations": 1, "ns_per_op": 100.0, "b_per_op": 10.0, "allocs_per_op": 1.0},
                    },
                },
            )
            write_json(
                head / "go_metrics.json",
                {
                    "suite": "go",
                    "metrics": {
                        "BenchmarkMempoolAddTx": {"iterations": 1, "ns_per_op": 110.0, "b_per_op": 10.0, "allocs_per_op": 1.0},
                        "BenchmarkMempoolRelayMetadata": {"iterations": 1, "ns_per_op": 110.0, "b_per_op": 10.0, "allocs_per_op": 1.0},
                        "BenchmarkCloneChainState": {"iterations": 1, "ns_per_op": 110.0, "b_per_op": 10.0, "allocs_per_op": 1.0},
                    },
                },
            )
            write_json(
                base / "rust_metrics.json",
                {
                    "suite": "rust",
                    "metrics": {
                        "rubin_node_txpool/admit": {"ns_per_op": 100.0},
                        "rubin_node_txpool/relay_metadata": {"ns_per_op": 100.0},
                        "rubin_node_chainstate_clone": {"ns_per_op": 100.0},
                    },
                },
            )
            write_json(
                head / "rust_metrics.json",
                {
                    "suite": "rust",
                    "metrics": {
                        "rubin_node_txpool/admit": {"ns_per_op": 110.0},
                        "rubin_node_txpool/relay_metadata": {"ns_per_op": 110.0},
                        "rubin_node_chainstate_clone": {"ns_per_op": 110.0},
                    },
                },
            )

            doc = self.run_compare(base, head, root / "out")
            summary_text = (root / "out" / "summary.md").read_text(encoding="utf-8")

        self.assertEqual(doc["input_issues"], [])
        self.assertEqual(doc["advisory_status"], "pass")
        self.assertTrue(all(item["status"] == "pass" for item in doc["advisory"]))
        self.assertIn("Overall advisory status: `pass`", summary_text)

    def test_selected_low_noise_regression_warns_without_failing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            write_json(
                base / "go_metrics.json",
                {
                    "suite": "go",
                    "metrics": {
                        "BenchmarkMempoolAddTx": {
                            "iterations": 1,
                            "ns_per_op": 100.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        },
                        "BenchmarkMempoolRelayMetadata": {
                            "iterations": 1,
                            "ns_per_op": 100.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        },
                        "BenchmarkCloneChainState": {
                            "iterations": 1,
                            "ns_per_op": 100.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        },
                        "BenchmarkMinerBuildContext": {
                            "iterations": 1,
                            "ns_per_op": 100.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        },
                    },
                },
            )
            write_json(
                head / "go_metrics.json",
                {
                    "suite": "go",
                    "metrics": {
                        "BenchmarkMempoolAddTx": {
                            "iterations": 1,
                            "ns_per_op": 130.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        },
                        "BenchmarkMempoolRelayMetadata": {
                            "iterations": 1,
                            "ns_per_op": 100.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        },
                        "BenchmarkCloneChainState": {
                            "iterations": 1,
                            "ns_per_op": 100.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        },
                        "BenchmarkMinerBuildContext": {
                            "iterations": 1,
                            "ns_per_op": 1000.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        },
                    },
                },
            )
            write_json(
                base / "rust_metrics.json",
                {
                    "suite": "rust",
                    "metrics": {
                        "rubin_node_txpool/admit": {"ns_per_op": 100.0},
                        "rubin_node_txpool/relay_metadata": {"ns_per_op": 100.0},
                        "rubin_node_chainstate_clone": {"ns_per_op": 100.0},
                    },
                },
            )
            write_json(
                head / "rust_metrics.json",
                {
                    "suite": "rust",
                    "metrics": {
                        "rubin_node_txpool/admit": {"ns_per_op": 100.0},
                        "rubin_node_txpool/relay_metadata": {"ns_per_op": 100.0},
                        "rubin_node_chainstate_clone": {"ns_per_op": 100.0},
                    },
                },
            )

            doc = self.run_compare(base, head, root / "out")
            summary_text = (root / "out" / "summary.md").read_text(encoding="utf-8")

        self.assertEqual(doc["input_issues"], [])
        self.assertEqual(doc["advisory_status"], "warn")
        self.assertIn("Overall advisory status: `warn`", summary_text)
        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "warn")
        self.assertEqual(add_tx["baseline"], 100.0)
        self.assertEqual(add_tx["observed"], 130.0)
        self.assertEqual(add_tx["threshold_pct"], 20.0)
        miner = next(row for row in doc["go"] if row["name"] == "BenchmarkMinerBuildContext")
        self.assertEqual(miner["advisory"]["ns_per_op"]["status"], "unselected")

    def test_missing_or_malformed_metrics_are_no_data_not_regression(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            base.mkdir()
            head.mkdir()
            (base / "go_metrics.json").write_text("{not-json\n", encoding="utf-8")
            write_json(
                head / "go_metrics.json",
                {
                    "suite": "go",
                    "metrics": {
                        "BenchmarkMempoolAddTx": {
                            "iterations": 1,
                            "ns_per_op": 130.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        }
                    },
                },
            )

            doc = self.run_compare(base, head, root / "out")

        self.assertIn("malformed JSON", "\n".join(doc["input_issues"]))
        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "no_data")
        self.assertNotEqual(add_tx["status"], "warn")

    def test_combined_load_slo_breach_is_advisory_warn_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = root / "bench.txt"
            out = root / "combined.json"
            summary = root / "summary.md"
            raw.write_text(
                "setup banner from wrapper\n"
                "BenchmarkValidateBlockBasicCombinedLoad-8 1 4000000000 ns/op 900000000 B/op 4000000 allocs/op\n",
                encoding="utf-8",
            )
            # The command is a repo-local script through sys.executable with temp file arguments only.
            proc = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    str(PARSE_COMBINED),
                    "--input",
                    str(raw),
                    "--slo",
                    str(SLO),
                    "--output",
                    str(out),
                    "--summary",
                    str(summary),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads(out.read_text(encoding="utf-8"))
            summary_text = summary.read_text(encoding="utf-8")

        self.assertEqual(doc["status"], "warn")
        self.assertTrue(doc["advisory"])
        self.assertIn("workflow remains non-blocking", doc["reason"])
        self.assertIn("Status: `warn`", summary_text)

    def test_missing_combined_load_line_is_no_data_not_regression(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = root / "bench.txt"
            out = root / "combined.json"
            raw.write_text("dev-env banner\nok no benchmark here\n", encoding="utf-8")
            # The command is a repo-local script through sys.executable with temp file arguments only.
            proc = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    str(PARSE_COMBINED),
                    "--input",
                    str(raw),
                    "--slo",
                    str(SLO),
                    "--output",
                    str(out),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(doc["status"], "no_data")
        self.assertEqual(doc["violations"], [])
        self.assertIn("not found", doc["reason"])


if __name__ == "__main__":
    unittest.main()

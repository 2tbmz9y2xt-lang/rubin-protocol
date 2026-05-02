#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
# Tests execute repo-local Python CLIs through argv lists only.
import subprocess  # nosec B404
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPARE = REPO_ROOT / "scripts" / "runtime_perf" / "compare_runtime_perf.py"
PARSE_COMBINED = REPO_ROOT / "scripts" / "benchmarks" / "parse_go_bench.py"
RUN_COMBINED = REPO_ROOT / "scripts" / "benchmarks" / "run_combined_load_benchmark.sh"
SLO = REPO_ROOT / "scripts" / "benchmarks" / "combined_load_slo.json"
TREND = REPO_ROOT / "scripts" / "runtime_perf" / "build_runtime_perf_trend.py"


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        self.assertIn("malformed JSON", add_tx["reason"])
        self.assertNotEqual(add_tx["status"], "warn")
        go_row = next(row for row in doc["go"] if row["name"] == "BenchmarkMempoolAddTx")
        self.assertIn("malformed JSON", go_row["advisory"]["ns_per_op"]["reason"])
        self.assertEqual(doc["rust"], [])

    def test_non_object_metric_entry_is_no_data_not_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            write_json(
                base / "go_metrics.json",
                {
                    "suite": "go",
                    "metrics": {
                        "BenchmarkMempoolAddTx": [],
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
                        }
                    },
                },
            )

            doc = self.run_compare(base, head, root / "out")

        self.assertIn("metrics entry for BenchmarkMempoolAddTx is list", "\n".join(doc["input_issues"]))
        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "no_data")
        self.assertIn("expected object", add_tx["reason"])

    def test_malformed_unselected_entry_does_not_mask_selected_warning(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            for side, add_tx_ns in [(base, 100.0), (head, 130.0)]:
                write_json(
                    side / "go_metrics.json",
                    {
                        "suite": "go",
                        "metrics": {
                            "BenchmarkMempoolAddTx": {
                                "iterations": 1,
                                "ns_per_op": add_tx_ns,
                                "b_per_op": 10.0,
                                "allocs_per_op": 1.0,
                            },
                            "BenchmarkMinerBuildContext": [],
                        },
                    },
                )

            doc = self.run_compare(base, head, root / "out")

        self.assertIn("metrics entry for BenchmarkMinerBuildContext is list", "\n".join(doc["input_issues"]))
        self.assertEqual(doc["advisory_status"], "warn")
        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "warn")
        self.assertEqual(add_tx["baseline"], 100.0)
        self.assertEqual(add_tx["observed"], 130.0)
        miner = next(row for row in doc["go"] if row["name"] == "BenchmarkMinerBuildContext")
        self.assertEqual(miner["advisory"]["ns_per_op"]["status"], "unselected")

    def test_malformed_missing_list_does_not_mask_selected_warning(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            for side, add_tx_ns in [(base, 100.0), (head, 130.0)]:
                write_json(
                    side / "go_metrics.json",
                    {
                        "suite": "go",
                        "metrics": {
                            "BenchmarkMempoolAddTx": {
                                "iterations": 1,
                                "ns_per_op": add_tx_ns,
                                "b_per_op": 10.0,
                                "allocs_per_op": 1.0,
                            },
                        },
                        "missing": "not-a-list",
                    },
                )

            doc = self.run_compare(base, head, root / "out")

        self.assertIn("field 'missing' is str, expected list", "\n".join(doc["input_issues"]))
        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "warn")

    def test_missing_unselected_row_summary_matches_json_status(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            write_json(
                base / "go_metrics.json",
                {
                    "suite": "go",
                    "metrics": {
                        "BenchmarkMinerBuildContext": {
                            "iterations": 1,
                            "ns_per_op": 100.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        },
                    },
                },
            )
            write_json(head / "go_metrics.json", {"suite": "go", "metrics": {}})

            doc = self.run_compare(base, head, root / "out")
            summary_text = (root / "out" / "summary.md").read_text(encoding="utf-8")

        miner = next(row for row in doc["go"] if row["name"] == "BenchmarkMinerBuildContext")
        self.assertEqual(miner["advisory"]["ns_per_op"]["status"], "unselected")
        self.assertIn("| `BenchmarkMinerBuildContext` | 100 | missing | n/a | unselected |", summary_text)

    def test_malformed_exit_code_records_input_issue_without_masking_warning(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            for side, add_tx_ns in [(base, 100.0), (head, 130.0)]:
                write_json(
                    side / "go_metrics.json",
                    {
                        "suite": "go",
                        "metrics": {
                            "BenchmarkMempoolAddTx": {
                                "iterations": 1,
                                "ns_per_op": add_tx_ns,
                                "b_per_op": 10.0,
                                "allocs_per_op": 1.0,
                            },
                        },
                    },
                )
            (base / "exit_code.txt").write_text("not-an-int\n", encoding="utf-8")
            (head / "exit_code.txt").write_text("0\n", encoding="utf-8")

            doc = self.run_compare(base, head, root / "out")

        self.assertIsNone(doc["base_exit_code"])
        self.assertEqual(doc["head_exit_code"], 0)
        self.assertIn("malformed exit code", "\n".join(doc["input_issues"]))
        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "warn")

    def test_invalid_utf8_metric_artifact_is_no_data_not_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            base.mkdir(parents=True)
            (base / "go_metrics.json").write_bytes(b"\xff\xfe")
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

        self.assertIn("invalid UTF-8", "\n".join(doc["input_issues"]))
        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "no_data")

    def test_invalid_utf8_exit_code_records_input_issue_without_masking_warning(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            for side, add_tx_ns in [(base, 100.0), (head, 130.0)]:
                write_json(
                    side / "go_metrics.json",
                    {
                        "suite": "go",
                        "metrics": {
                            "BenchmarkMempoolAddTx": {
                                "iterations": 1,
                                "ns_per_op": add_tx_ns,
                                "b_per_op": 10.0,
                                "allocs_per_op": 1.0,
                            },
                        },
                    },
                )
            (base / "exit_code.txt").write_bytes(b"\xff\xfe")

            doc = self.run_compare(base, head, root / "out")

        self.assertIsNone(doc["base_exit_code"])
        self.assertIn("invalid UTF-8", "\n".join(doc["input_issues"]))
        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "warn")

    def test_non_finite_selected_metric_is_no_data_not_pass(self):
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
                        }
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
                            "ns_per_op": float("nan"),
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        }
                    },
                },
            )

            doc = self.run_compare(base, head, root / "out")

        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "no_data")
        self.assertIn("non-finite", add_tx["reason"])
        self.assertIsNone(add_tx["delta_pct"])

    def test_negative_selected_metric_is_no_data_not_pass(self):
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
                        }
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
                            "ns_per_op": -1.0,
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        }
                    },
                },
            )

            doc = self.run_compare(base, head, root / "out")

        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "no_data")
        self.assertIn("negative metric value", add_tx["reason"])
        self.assertIsNone(add_tx["delta_pct"])

    def test_rust_missing_list_surfaces_rows_and_no_data(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            base = root / "base"
            head = root / "head"
            for side in [base, head]:
                write_json(
                    side / "rust_metrics.json",
                    {
                        "suite": "rust",
                        "metrics": {
                            "rubin_node_txpool/admit": {"ns_per_op": 100.0},
                        },
                        "missing": ["rubin_node_txpool/relay_metadata"],
                    },
                )

            doc = self.run_compare(base, head, root / "out")
            summary_text = (root / "out" / "summary.md").read_text(encoding="utf-8")

        self.assertEqual(doc["missing"]["rust"]["base"], ["rubin_node_txpool/relay_metadata"])
        self.assertEqual(doc["missing"]["rust"]["head"], ["rubin_node_txpool/relay_metadata"])
        missing_row = next(row for row in doc["rust"] if row["name"] == "rubin_node_txpool/relay_metadata")
        self.assertIsNone(missing_row["base"])
        self.assertIsNone(missing_row["head"])
        self.assertEqual(missing_row["advisory"]["ns_per_op"]["status"], "no_data")
        self.assertIn("rubin_node_txpool/relay_metadata", summary_text)

    def test_combined_load_slo_breach_is_advisory_warn_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = root / "bench.txt"
            out = root / "combined.json"
            summary = root / "summary.md"
            raw.write_text(
                "setup banner from wrapper\n"
                "BenchmarkValidateBlockBasicCombinedLoad-8 1 4000000000 ns/op "
                "12 custom/op 900000000 B/op 4000000 allocs/op 99 verifies/op\n",
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

    def test_missing_combined_load_input_file_writes_no_data_summary(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out = root / "combined.json"
            summary = root / "summary.md"
            # The command is a repo-local script through sys.executable with temp file arguments only.
            proc = subprocess.run(  # nosec B603
                [
                    sys.executable,
                    str(PARSE_COMBINED),
                    "--input",
                    str(root / "missing-benchmark.txt"),
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

        self.assertEqual(doc["status"], "no_data")
        self.assertIn("benchmark output not found", doc["reason"])
        self.assertIn("Status: `no_data`", summary_text)

    def test_combined_load_wrapper_emits_no_data_when_benchmark_command_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out_dir = root / "combined"
            env = os.environ.copy()
            env["RUBIN_OPENSSL_PREFIX"] = str(root / "missing-openssl")
            # The command is a repo-local shell wrapper with temp artifact output only.
            proc = subprocess.run(  # nosec B603
                [str(RUN_COMBINED), str(out_dir)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads((out_dir / "combined_load_metrics.json").read_text(encoding="utf-8"))
            summary_text = (out_dir / "combined_load_summary.md").read_text(encoding="utf-8")
            raw_exists = (out_dir / "combined_load_benchmark.txt").exists()

        self.assertEqual(doc["status"], "no_data")
        self.assertIn("benchmark line for BenchmarkValidateBlockBasicCombinedLoad not found", doc["reason"])
        self.assertIn("Status: `no_data`", summary_text)
        self.assertTrue(raw_exists)
        self.assertIn("RUBIN_OPENSSL_PREFIX", proc.stderr)
        self.assertIn("benchmark command failed", proc.stderr)

    def test_malformed_combined_load_metric_has_distinct_no_data_reason(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = root / "bench.txt"
            out = root / "combined.json"
            raw.write_text(
                "BenchmarkValidateBlockBasicCombinedLoad-8 1 4000000000 ns/op 4000000 allocs/op\n",
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
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            doc = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(doc["status"], "no_data")
        self.assertIn("missing required metric", doc["reason"])
        self.assertNotIn("not found", doc["reason"])

    def test_malformed_combined_load_numeric_token_is_no_data_not_traceback(self):
        for token in ["400..0", "NaN", "-400"]:
            with self.subTest(token=token), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                raw = root / "bench.txt"
                out = root / "combined.json"
                raw.write_text(
                    f"BenchmarkValidateBlockBasicCombinedLoad-8 1 {token} ns/op "
                    "900000000 B/op 4000000 allocs/op\n",
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
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                doc = json.loads(out.read_text(encoding="utf-8"))

            self.assertEqual(doc["status"], "no_data")
            self.assertIn("malformed ns_per_op", doc["reason"])
            self.assertNotIn("Traceback", proc.stderr)

    def test_invalid_utf8_combined_load_input_writes_no_data_summary(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            raw = root / "bench.txt"
            out = root / "combined.json"
            summary = root / "summary.md"
            raw.write_bytes(b"\xff\xfe")
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

        self.assertEqual(doc["status"], "no_data")
        self.assertIn("benchmark output unreadable", doc["reason"])
        self.assertIn("Status: `no_data`", summary_text)
        self.assertNotIn("Traceback", proc.stderr)

    def test_invalid_combined_load_slo_threshold_fails_closed(self):
        for limit_key in ["max_ns_per_op", "max_b_per_op", "max_allocs_per_op"]:
            for value in [float("nan"), float("inf"), -1.0, 0.0]:
                with self.subTest(limit_key=limit_key, value=str(value)), tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    raw = root / "bench.txt"
                    slo = root / "slo.json"
                    out = root / "combined.json"
                    raw.write_text(
                        "BenchmarkValidateBlockBasicCombinedLoad-8 1 4000000000 ns/op "
                        "900000000 B/op 4000000 allocs/op\n",
                        encoding="utf-8",
                    )
                    payload = json.loads(SLO.read_text(encoding="utf-8"))
                    payload[limit_key] = value
                    write_json(slo, payload)
                    # The command is a repo-local script through sys.executable with temp file arguments only.
                    proc = subprocess.run(  # nosec B603
                        [
                            sys.executable,
                            str(PARSE_COMBINED),
                            "--input",
                            str(raw),
                            "--slo",
                            str(slo),
                            "--output",
                            str(out),
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                    )

                self.assertNotEqual(proc.returncode, 0)
                self.assertFalse(out.exists())
                self.assertIn(f"SLO {limit_key}", proc.stderr)
                self.assertNotIn("Traceback", proc.stderr)

    def test_invalid_combined_load_slo_benchmark_fails_closed(self):
        for value in [None, "", "   ", " BenchmarkValidateBlockBasicCombinedLoad ", 123]:
            with self.subTest(value=repr(value)), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                raw = root / "bench.txt"
                slo = root / "slo.json"
                out = root / "combined.json"
                raw.write_text(
                    "BenchmarkValidateBlockBasicCombinedLoad-8 1 4000000000 ns/op "
                    "900000000 B/op 4000000 allocs/op\n",
                    encoding="utf-8",
                )
                payload = json.loads(SLO.read_text(encoding="utf-8"))
                payload["benchmark"] = value
                write_json(slo, payload)
                # The command is a repo-local script through sys.executable with temp file arguments only.
                proc = subprocess.run(  # nosec B603
                    [
                        sys.executable,
                        str(PARSE_COMBINED),
                        "--input",
                        str(raw),
                        "--slo",
                        str(slo),
                        "--output",
                        str(out),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(out.exists())
            self.assertIn("SLO benchmark must", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)

    def test_non_numeric_selected_metric_is_no_data_not_traceback(self):
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
                            "ns_per_op": "n/a",
                            "b_per_op": 10.0,
                            "allocs_per_op": 1.0,
                        }
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
                        }
                    },
                },
            )

            doc = self.run_compare(base, head, root / "out")

        add_tx = next(item for item in doc["advisory"] if item["benchmark"] == "BenchmarkMempoolAddTx")
        self.assertEqual(add_tx["status"], "no_data")
        self.assertIn("non-numeric", add_tx["reason"])

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

    def test_advisory_threshold_registry_matches_trend_low_noise_candidates(self):
        compare = load_module(COMPARE, "compare_runtime_perf_for_test")
        trend = load_module(TREND, "build_runtime_perf_trend_for_test")

        threshold_keys = {
            (item["suite"], item["benchmark"], item["metric"])
            for item in compare.ADVISORY_THRESHOLDS
        }
        trend_keys = {
            (item["suite"], item["benchmark"], item["metric"])
            for item in trend.LOW_NOISE_CANDIDATES
            if item["suite"] in {"go", "rust"}
        }

        self.assertEqual(threshold_keys, trend_keys)


if __name__ == "__main__":
    unittest.main()

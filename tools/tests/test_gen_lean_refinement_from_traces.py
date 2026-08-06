from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.formal.gen_lean_refinement_from_traces import (
    Header,
    _emit_go_trace_v1,
    _lean_opt_nat,
    _load_fixture_vector_ids,
    _require_exact_trace_ids,
)


class GoTraceV1GeneratorTests(unittest.TestCase):
    def test_simplicity_exec_trace_ids_must_match_fixture_ids(self) -> None:
        _require_exact_trace_ids(
            [("CV-SE-001", "{ row }"), ("CV-SE-002", "{ row }")],
            ["CV-SE-001", "CV-SE-002"],
            "CV-SIMPLICITY-EXEC",
        )

    def test_simplicity_exec_trace_ids_reject_missing_duplicate_and_extra(self) -> None:
        with self.assertRaises(SystemExit) as ctx:
            _require_exact_trace_ids(
                [
                    ("CV-SE-001", "{ row }"),
                    ("CV-SE-001", "{ row }"),
                    ("CV-SE-EXTRA", "{ row }"),
                ],
                ["CV-SE-001", "CV-SE-MISSING"],
                "CV-SIMPLICITY-EXEC",
            )

        message = str(ctx.exception)
        self.assertIn("CV-SIMPLICITY-EXEC trace ID coverage mismatch", message)
        self.assertIn("missing CV-SE-MISSING", message)
        self.assertIn("duplicate CV-SE-001", message)
        self.assertIn("extra CV-SE-EXTRA", message)

    def test_fixture_vector_ids_reject_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "CV-SIMPLICITY-EXEC.json"
            fixture.write_text(
                json.dumps(
                    {
                        "gate": "CV-SIMPLICITY-EXEC",
                        "vectors": [
                            {"id": "CV-SE-001"},
                            {"id": "CV-SE-001"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(SystemExit) as ctx:
                _load_fixture_vector_ids(fixture, "CV-SIMPLICITY-EXEC")

        self.assertIn("duplicate vector id CV-SE-001", str(ctx.exception))

    def test_core_ext_utxo_negative_trace_rows_are_emitted(self) -> None:
        text = _emit_go_trace_v1(
            Header(
                repo_commit="test",
                fixtures_digest_sha3_256="00",
            ),
            [
                {
                    "type": "entry",
                    "gate": "CV-UTXO-BASIC",
                    "vector_id": "CV-U-EXT-NEG",
                    "op": "utxo_apply_basic",
                    "ok": False,
                    "err": "TX_ERR_COVENANT_TYPE_INVALID",
                    "outputs": {},
                },
                {
                    "type": "entry",
                    "gate": "CV-UTXO-BASIC",
                    "vector_id": "CV-U-NEG",
                    "op": "utxo_apply_basic",
                    "ok": False,
                    "err": "TX_ERR_PARSE",
                    "outputs": {},
                },
                {
                    "type": "entry",
                    "gate": "CV-PARSE",
                    "vector_id": "CV-PARSE-NEG",
                    "op": "parse_tx",
                    "ok": False,
                    "err": "TX_ERR_PARSE",
                    "outputs": {},
                },
            ],
        )

        self.assertIn('{ id := "CV-U-EXT-NEG", ok := false', text)
        self.assertNotIn("CV-U-NEG", text)
        self.assertNotIn("CV-PARSE-NEG", text)


class CanonicalDecimalFeeTests(unittest.TestCase):
    """The widened `fee` trace output is a canonical decimal STRING."""

    def test_accepts_canonical_decimal_string_above_u64(self) -> None:
        self.assertEqual(_lean_opt_nat("18446744073709551616"), "some 18446744073709551616")
        self.assertEqual(
            _lean_opt_nat("340282366920938463463374607431768211455"),
            "some 340282366920938463463374607431768211455",
        )

    def test_accepts_zero_and_legacy_numeric_token(self) -> None:
        self.assertEqual(_lean_opt_nat("0"), "some 0")
        self.assertEqual(_lean_opt_nat(10), "some 10")
        self.assertEqual(_lean_opt_nat(18446744073709551615), "some 18446744073709551615")
        self.assertEqual(_lean_opt_nat(None), "none")

    def test_rejects_legacy_numeric_token_above_u64(self) -> None:
        # The widened domain is reachable only through the string form, so a
        # bare JSON integer stays bounded to u64 here exactly as it is in both
        # clients' readers and in the conformance runner's `exact_uint`.
        for bad in [18446744073709551616, 1 << 128]:
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    _lean_opt_nat(bad)

    def test_rejects_non_canonical_strings(self) -> None:
        for bad in ["", "00", "01", "+1", "-1", " 1", "1 ", "1.0", "1e3", "0x10", "abc"]:
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    _lean_opt_nat(bad)

    def test_rejects_trailing_newline(self) -> None:
        # Python's `$` also matches just before a single trailing newline, so
        # an anchored `^...$` canonicality regex silently accepted "123\n".
        # The reader is anchored with `\Z`, which has no such exemption.
        for bad in ["123\n", "0\n", "\n"]:
            with self.subTest(bad=bad):
                with self.assertRaises(SystemExit):
                    _lean_opt_nat(bad)

    def test_rejects_negative_and_bool(self) -> None:
        with self.assertRaises(SystemExit):
            _lean_opt_nat(-1)
        with self.assertRaises(SystemExit):
            _lean_opt_nat(True)

    def test_emits_string_fee_row_as_unbounded_nat(self) -> None:
        text = _emit_go_trace_v1(
            Header(repo_commit="c0ffee", fixtures_digest_sha3_256="d1"),
            [
                {
                    "gate": "CV-UTXO-BASIC",
                    "vector_id": "CV-U-WIDE",
                    "op": "utxo_apply_basic",
                    "ok": True,
                    "err": "",
                    "outputs": {"fee": "18446744073709551616", "utxo_count": 0},
                },
            ],
        )
        self.assertIn("fee := some 18446744073709551616", text)


if __name__ == "__main__":
    unittest.main()

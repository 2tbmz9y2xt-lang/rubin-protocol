import unittest
from pathlib import Path
from unittest import mock

if __package__:
    from .run_cv_bundle import (
        RETIRED_GATES,
        is_retired_gate,
        normalize_validation_result,
        normalized_vector_op,
        validate_vector,
    )
else:
    from run_cv_bundle import (
        RETIRED_GATES,
        is_retired_gate,
        normalize_validation_result,
        normalized_vector_op,
        validate_vector,
    )


class RunCvBundleOpNormalizationTests(unittest.TestCase):
    def test_core_ext_gates_are_retired(self):
        self.assertEqual(RETIRED_GATES, frozenset({"CV-EXT", "CV-TXCTX"}))
        self.assertTrue(is_retired_gate("CV-EXT"))
        self.assertTrue(is_retired_gate("CV-TXCTX"))
        self.assertFalse(is_retired_gate("CV-UTXO-BASIC"))

    def test_non_txctx_whitespace_op_is_missing(self):
        op = normalized_vector_op("CV-OTHER", {"id": "X", "op": "   "})
        self.assertEqual(op, "   ")

    def test_noncanonical_whitespace_is_not_silently_normalized(self):
        op = normalized_vector_op("CV-UTXO-BASIC", {"id": "CV-U-01", "op": " parse_tx "})
        self.assertEqual(op, " parse_tx ")

    def test_invalid_nonstring_op_returns_validation_error_instead_of_crashing(self):
        problems, skipped = normalize_validation_result(
            validate_vector("CV-OTHER", {"id": "X", "op": 0}, None, None, {})
        )
        self.assertEqual(problems, ["CV-OTHER/X: missing op"])
        self.assertFalse(skipped)

    def test_rotation_ops_forward_network_into_cli_request(self):
        cases = [
            (
                {
                    "id": "ROT-CREATE",
                    "op": "rotation_create_suite_check",
                    "network": "mainnet",
                    "height": 15,
                    "suite_id": 1,
                    "rotation_descriptor": {
                        "name": "r1",
                        "old_suite_id": 1,
                        "new_suite_id": 2,
                        "create_height": 10,
                        "spend_height": 20,
                        "sunset_height": 100,
                    },
                    "suite_registry": [],
                    "expect_ok": True,
                },
                "rotation_create_suite_check",
            ),
            (
                {
                    "id": "ROT-NATIVE-CREATE",
                    "op": "rotation_native_create_suites",
                    "network": "testnet",
                    "height": 15,
                    "rotation_descriptor": {
                        "name": "r1",
                        "old_suite_id": 1,
                        "new_suite_id": 2,
                        "create_height": 10,
                        "spend_height": 20,
                        "sunset_height": 100,
                    },
                    "suite_registry": [],
                    "expect_ok": True,
                },
                "rotation_native_create_suites",
            ),
            (
                {
                    "id": "ROT-SPEND",
                    "op": "rotation_spend_suite_check",
                    "network": "mainnet",
                    "height": 15,
                    "suite_id": 2,
                    "covenant_type": 0,
                    "rotation_descriptor": {
                        "name": "r1",
                        "old_suite_id": 1,
                        "new_suite_id": 2,
                        "create_height": 10,
                        "spend_height": 20,
                        "sunset_height": 100,
                    },
                    "suite_registry": [],
                    "expect_ok": True,
                },
                "rotation_spend_suite_check",
            ),
            (
                {
                    "id": "ROT-DESC",
                    "op": "rotation_descriptor_check",
                    "network": "devnet",
                    "rotation_descriptors": [
                        {
                            "name": "r1",
                            "old_suite_id": 1,
                            "new_suite_id": 2,
                            "create_height": 10,
                            "spend_height": 20,
                            "sunset_height": 100,
                        },
                        {
                            "name": "r2",
                            "old_suite_id": 2,
                            "new_suite_id": 3,
                            "create_height": 100,
                            "spend_height": 110,
                            "sunset_height": 200,
                        },
                    ],
                    "suite_registry": [],
                    "expect_ok": True,
                },
                "rotation_descriptor_check",
            ),
        ]

        for vector, expected_op in cases:
            seen = []

            def fake_call_tool(_tool_path, req):
                seen.append(req.copy())
                return {"ok": True}

            with self.subTest(op=expected_op):
                with mock.patch(
                    f"{validate_vector.__module__}.call_tool", side_effect=fake_call_tool
                ):
                    problems, skipped = normalize_validation_result(
                        validate_vector(
                            "CV-NATIVE-ROTATION-DESCRIPTOR",
                            vector,
                            Path("go-cli"),
                            Path("rust-cli"),
                            {},
                        )
                    )
                self.assertEqual(problems, [])
                self.assertFalse(skipped)
                self.assertEqual(len(seen), 2)
                for req in seen:
                    self.assertEqual(req["op"], expected_op)
                    self.assertEqual(req["network"], vector["network"])

    def test_rotation_native_create_suites_normalizes_go_base64_response(self):
        vector = {
            "id": "ROT-NATIVE-CREATE-SETS",
            "op": "rotation_native_create_suites",
            "height": 15,
            "rotation_descriptor": {
                "name": "r1",
                "old_suite_id": 1,
                "new_suite_id": 2,
                "create_height": 10,
                "spend_height": 20,
                "sunset_height": 100,
            },
            "suite_registry": [],
            "expect_ok": True,
            "expect_suite_ids": [1, 2],
        }
        responses = iter(
            [
                {"ok": True, "suite_ids": "AQI="},
                {"ok": True, "suite_ids": [1, 2]},
            ]
        )

        with mock.patch(
            f"{validate_vector.__module__}.call_tool",
            side_effect=lambda _tool_path, _req: next(responses),
        ):
            problems, skipped = normalize_validation_result(
                validate_vector(
                    "CV-NATIVE-ROTATION-CREATE",
                    vector,
                    Path("go-cli"),
                    Path("rust-cli"),
                    {},
                )
            )

        self.assertEqual(problems, [])
        self.assertFalse(skipped)

    def test_simplicity_exec_vector_forwards_fields(self):
        vector = {
            "id": "CV-SE-UNIT",
            "op": "simplicity_exec_vector",
            "program_hex": "60",
            "witness_hex": "00",
            "covenant_cmr_hex": "11" * 32,
            "semantics_version": 1,
            "jet_accepted": True,
            "jet_cost": 7,
            "expect_ok": True,
            "expect_accepted": True,
            "expect_final_counter": 7,
        }
        seen = []

        def fake_call_tool(_tool_path, req):
            seen.append(req.copy())
            return {"ok": True, "accepted": True, "final_counter": 7}

        with mock.patch(f"{validate_vector.__module__}.call_tool", side_effect=fake_call_tool):
            problems, skipped = normalize_validation_result(
                validate_vector(
                    "CV-SIMPLICITY-EXEC",
                    vector,
                    Path("go-cli"),
                    Path("rust-cli"),
                    {},
                )
            )
        self.assertEqual(problems, [])
        self.assertFalse(skipped)
        self.assertEqual(len(seen), 2)
        self.assertEqual(
            seen[0],
            {
                "op": "simplicity_exec_vector",
                "program_hex": "60",
                "witness_hex": "00",
                "covenant_cmr_hex": "11" * 32,
                "semantics_version": 1,
                "jet_accepted": True,
                "jet_cost": 7,
            },
        )

    def test_simplicity_exec_vector_reports_final_counter_mismatch(self):
        vector = {
            "id": "CV-SE-COUNTER",
            "op": "simplicity_exec_vector",
            "program_hex": "60",
            "jet_accepted": True,
            "jet_cost": 400001,
            "expect_ok": False,
            "expect_err": "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED",
            "expect_accepted": True,
            "expect_final_counter": 400000,
        }

        def fake_call_tool(_tool_path, _req):
            return {
                "ok": False,
                "err": "TX_ERR_SIMPLICITY_BUDGET_EXCEEDED",
                "accepted": True,
                "final_counter": 2,
            }

        with mock.patch(f"{validate_vector.__module__}.call_tool", side_effect=fake_call_tool):
            problems, skipped = normalize_validation_result(
                validate_vector(
                    "CV-SIMPLICITY-EXEC",
                    vector,
                    Path("go-cli"),
                    Path("rust-cli"),
                    {},
                )
            )
        self.assertEqual(problems, ["CV-SIMPLICITY-EXEC/CV-SE-COUNTER: expect_final_counter mismatch"])
        self.assertFalse(skipped)

    def test_simplicity_exec_vector_requires_trace_outputs(self):
        vector = {
            "id": "CV-SE-MISSING",
            "op": "simplicity_exec_vector",
            "program_hex": "60",
            "expect_ok": True,
            "expect_accepted": True,
            "expect_final_counter": 1,
        }

        def fake_call_tool(_tool_path, _req):
            return {"ok": True}

        with mock.patch(f"{validate_vector.__module__}.call_tool", side_effect=fake_call_tool):
            problems, skipped = normalize_validation_result(
                validate_vector(
                    "CV-SIMPLICITY-EXEC",
                    vector,
                    Path("go-cli"),
                    Path("rust-cli"),
                    {},
                )
            )
        self.assertEqual(
            problems,
            [
                "CV-SIMPLICITY-EXEC/CV-SE-MISSING: missing accepted output go_has=False rust_has=False",
                "CV-SIMPLICITY-EXEC/CV-SE-MISSING: missing final_counter output go_has=False rust_has=False",
            ],
        )
        self.assertFalse(skipped)

    def test_simplicity_exec_vector_rejects_unexpected_trace_outputs(self):
        vector = {
            "id": "CV-SE-UNEXPECTED",
            "op": "simplicity_exec_vector",
            "program_hex": "25",
            "expect_ok": False,
            "expect_err": "TX_ERR_SIMPLICITY_DECODE",
        }

        responses = [
            {"ok": False, "err": "TX_ERR_SIMPLICITY_DECODE", "accepted": False},
            {
                "ok": False,
                "err": "TX_ERR_SIMPLICITY_DECODE",
                "accepted": False,
                "final_counter": 0,
            },
        ]

        def fake_call_tool(_tool_path, _req):
            return responses.pop(0)

        with mock.patch(f"{validate_vector.__module__}.call_tool", side_effect=fake_call_tool):
            problems, skipped = normalize_validation_result(
                validate_vector(
                    "CV-SIMPLICITY-EXEC",
                    vector,
                    Path("go-cli"),
                    Path("rust-cli"),
                    {},
                )
            )
        self.assertEqual(
            problems,
            [
                "CV-SIMPLICITY-EXEC/CV-SE-UNEXPECTED: unexpected accepted output go_has=True rust_has=True",
                "CV-SIMPLICITY-EXEC/CV-SE-UNEXPECTED: unexpected final_counter output go_has=False rust_has=True",
            ],
        )
        self.assertFalse(skipped)


if __name__ == "__main__":
    unittest.main()

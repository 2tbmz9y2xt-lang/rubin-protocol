import io
import sys
import unittest
from pathlib import Path
from unittest import mock

if __package__:
    from .run_cv_bundle import (
        MAX_U128,
        MAX_U64,
        RETIRED_GATES,
        is_retired_gate,
        known_gate_names,
        main,
        normalize_validation_result,
        normalized_vector_op,
        select_requested_fixtures,
        validate_vector,
    )
else:
    from run_cv_bundle import (
        MAX_U128,
        MAX_U64,
        RETIRED_GATES,
        is_retired_gate,
        known_gate_names,
        main,
        normalize_validation_result,
        normalized_vector_op,
        select_requested_fixtures,
        validate_vector,
    )


class RunCvBundleOpNormalizationTests(unittest.TestCase):
    def test_core_ext_gates_are_retired(self):
        self.assertEqual(RETIRED_GATES, frozenset({"CV-EXT", "CV-TXCTX"}))
        self.assertTrue(is_retired_gate("CV-EXT"))
        self.assertTrue(is_retired_gate("CV-TXCTX"))
        self.assertFalse(is_retired_gate("CV-UTXO-BASIC"))

    def test_deleted_retired_gates_are_known_for_requested_runs(self):
        fixtures = [{"gate": "CV-UTXO-BASIC", "vectors": []}]

        self.assertEqual(
            known_gate_names(fixtures),
            {"CV-UTXO-BASIC", "CV-EXT", "CV-TXCTX"},
        )
        selected, retired, unknown = select_requested_fixtures(fixtures, ["CV-TXCTX"])
        self.assertEqual(selected, [])
        self.assertEqual(retired, {"CV-TXCTX"})
        self.assertEqual(unknown, [])

    def test_unknown_requested_gate_is_reported(self):
        fixtures = [{"gate": "CV-UTXO-BASIC", "vectors": []}]

        selected, retired, unknown = select_requested_fixtures(
            fixtures,
            ["CV-NOT-A-GATE", "CV-EXT"],
        )
        self.assertEqual(selected, [])
        self.assertEqual(retired, {"CV-EXT"})
        self.assertEqual(unknown, ["CV-NOT-A-GATE"])

    def test_only_deleted_retired_gate_prints_retired_summary(self):
        fixtures = [{"gate": "CV-UTXO-BASIC", "vectors": []}]
        argv = ["run_cv_bundle.py", "--only-gates", "CV-TXCTX"]

        with mock.patch.object(sys, "argv", argv):
            with mock.patch(f"{main.__module__}.load_fixtures", return_value=fixtures):
                with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
                    rc = main()

        self.assertEqual(rc, 0)
        self.assertIn(
            "retired gates skipped: CV-TXCTX (0 vectors)",
            stdout.getvalue(),
        )

    def test_active_utxo_apply_basic_rejects_core_ext_profiles(self):
        vector = {"id": "CV-U-EXT-ACTIVE", "op": "utxo_apply_basic", "tx_hex": "00", "utxos": [],
                  "height": 1, "block_timestamp": 1, "core_ext_profiles": [{"ext_id": 1}]}
        with mock.patch(f"{validate_vector.__module__}.call_tool") as call_tool:
            problems, skipped = normalize_validation_result(
                validate_vector("CV-UTXO-BASIC", vector, Path("go-cli"), Path("rust-cli"), {})
            )

        self.assertEqual((problems, skipped), ([
            "CV-UTXO-BASIC/CV-U-EXT-ACTIVE: core_ext_profiles retired from active utxo_apply_basic gates"
        ], False))
        call_tool.assert_not_called()

    def test_whitespace_only_op_is_preserved_for_validation_error(self):
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


class RunCvBundleSupplyTests(unittest.TestCase):
    @staticmethod
    def _connect_vector(
        already_generated,
        expected_n1=None,
    ):
        if expected_n1 is None:
            expected_n1 = already_generated
        return {
            "id": "CV-SUPPLY-UNIT",
            "op": "connect_block_basic",
            "block_hex": "00",
            "height": 1,
            "already_generated": already_generated,
            "utxos": [],
            "expect_ok": True,
            "expect_already_generated": already_generated,
            "expect_already_generated_n1": expected_n1,
        }

    @staticmethod
    def _run_with_responses(vector, responses):
        seen = []
        response_iter = iter(responses)

        def fake_call_tool(_tool_path, req):
            seen.append(req.copy())
            return next(response_iter)

        with mock.patch(
            f"{validate_vector.__module__}.call_tool",
            side_effect=fake_call_tool,
        ):
            problems, skipped = normalize_validation_result(
                validate_vector(
                    "CV-SUB",
                    vector,
                    Path("go-cli"),
                    Path("rust-cli"),
                    {},
                )
            )
        return problems, skipped, seen

    def test_supply_input_is_validated_and_forwarded_without_reencoding(self):
        for op in ("block_basic_check_with_fees", "connect_block_basic"):
            for token in (0, MAX_U64, str(MAX_U64 + 1)):
                vector = {
                    "id": "CV-SUPPLY-FORWARD",
                    "op": op,
                    "block_hex": "00",
                    "height": 1,
                    "already_generated": token,
                    "expect_ok": True,
                }
                if op == "block_basic_check_with_fees":
                    vector["sum_fees"] = 0
                    responses = [{"ok": True}, {"ok": True}]
                else:
                    vector["utxos"] = []
                    vector["expect_already_generated"] = token
                    vector["expect_already_generated_n1"] = token
                    responses = [
                        {
                            "ok": True,
                            "already_generated": str(token),
                            "already_generated_n1": str(token),
                        },
                        {
                            "ok": True,
                            "already_generated": str(token),
                            "already_generated_n1": str(token),
                        },
                    ]

                with self.subTest(op=op, token=token):
                    problems, skipped, seen = self._run_with_responses(vector, responses)
                    self.assertEqual(problems, [])
                    self.assertFalse(skipped)
                    self.assertEqual(len(seen), 2)
                    for req in seen:
                        self.assertEqual(req["already_generated"], token)
                        self.assertIs(type(req["already_generated"]), type(token))

    def test_supply_input_preserves_existing_omitted_default_zero(self):
        for op in ("block_basic_check_with_fees", "connect_block_basic"):
            vector = {
                "id": "CV-SUPPLY-DEFAULT",
                "op": op,
                "block_hex": "00",
                "height": 1,
                "expect_ok": True,
            }
            if op == "block_basic_check_with_fees":
                vector["sum_fees"] = 0
                responses = [{"ok": True}, {"ok": True}]
            else:
                vector["utxos"] = []
                responses = [
                    {
                        "ok": True,
                        "already_generated": "0",
                        "already_generated_n1": "0",
                    },
                    {
                        "ok": True,
                        "already_generated": "0",
                        "already_generated_n1": "0",
                    },
                ]

            with self.subTest(op=op):
                problems, skipped, seen = self._run_with_responses(vector, responses)
                self.assertEqual(problems, [])
                self.assertFalse(skipped)
                self.assertEqual([req["already_generated"] for req in seen], [0, 0])

    def test_malformed_supply_input_fails_before_client_dispatch(self):
        malformed = [
            ("float", 1.5),
            ("exponent", 1e1),
            ("bool", True),
            ("negative", -1),
            ("null", None),
            ("numeric-above-u64", MAX_U64 + 1),
            ("empty", ""),
            ("leading-zero", "01"),
            ("plus", "+1"),
            ("signed", "-1"),
            ("leading-whitespace", " 1"),
            ("trailing-whitespace", "1 "),
            ("string-exponent", "1e1"),
            ("string-above-u128", str(MAX_U128 + 1)),
        ]
        for op in ("block_basic_check_with_fees", "connect_block_basic"):
            for label, token in malformed:
                vector = {
                    "id": "CV-SUPPLY-REJECT",
                    "op": op,
                    "block_hex": "00",
                    "height": 1,
                    "already_generated": token,
                }
                if op == "block_basic_check_with_fees":
                    vector["sum_fees"] = 0
                else:
                    vector["utxos"] = []

                with self.subTest(op=op, token=label):
                    with mock.patch(
                        f"{validate_vector.__module__}.call_tool"
                    ) as call_tool:
                        problems, skipped = normalize_validation_result(
                            validate_vector(
                                "CV-SUB",
                                vector,
                                Path("go-cli"),
                                Path("rust-cli"),
                                {},
                            )
                        )
                    self.assertTrue(problems)
                    self.assertFalse(skipped)
                    call_tool.assert_not_called()

    def test_connect_compares_exact_crossing_values(self):
        crossing = "18446744073699181041"
        crossing_n1 = "18446744073718206916"
        vector = self._connect_vector(crossing, crossing_n1)
        response = {
            "ok": True,
            "already_generated": crossing,
            "already_generated_n1": crossing_n1,
        }

        problems, skipped, _seen = self._run_with_responses(
            vector,
            [response, response],
        )

        self.assertEqual(problems, [])
        self.assertFalse(skipped)

    def test_connect_rejects_each_clients_noncanonical_supply_output(self):
        omitted = object()
        malformed = [
            ("omitted", omitted),
            ("null", None),
            ("numeric", 7),
            ("bool", True),
            ("empty", ""),
            ("leading-zero", "07"),
            ("signed", "-7"),
            ("whitespace", " 7"),
            ("exponent", "7e0"),
            ("unreadable", []),
            ("above-u128", str(MAX_U128 + 1)),
        ]
        for side_index, side in enumerate(("go", "rust")):
            for field in ("already_generated", "already_generated_n1"):
                for label, token in malformed:
                    good = {
                        "ok": True,
                        "already_generated": "7",
                        "already_generated_n1": "8",
                    }
                    bad = dict(good)
                    if token is omitted:
                        bad.pop(field)
                    else:
                        bad[field] = token
                    responses = [good, good]
                    responses[side_index] = bad

                    with self.subTest(side=side, field=field, token=label):
                        problems, skipped, _seen = self._run_with_responses(
                            self._connect_vector(7, 8),
                            responses,
                        )
                        self.assertFalse(skipped)
                        self.assertTrue(
                            any(f"{side}.{field}:" in problem for problem in problems),
                            problems,
                        )

    def test_connect_same_wrong_canonical_values_cannot_false_pass(self):
        crossing = "18446744073699181041"
        crossing_n1 = "18446744073718206916"
        vector = self._connect_vector(crossing, crossing_n1)
        wrong = {
            "ok": True,
            "already_generated": str(MAX_U64),
            "already_generated_n1": str(MAX_U64),
        }

        problems, skipped, _seen = self._run_with_responses(vector, [wrong, wrong])

        self.assertFalse(skipped)
        self.assertIn("CV-SUB/CV-SUPPLY-UNIT: go.expect_already_generated mismatch", problems)
        self.assertIn("CV-SUB/CV-SUPPLY-UNIT: rust.expect_already_generated mismatch", problems)
        self.assertIn("CV-SUB/CV-SUPPLY-UNIT: go.expect_already_generated_n1 mismatch", problems)
        self.assertIn("CV-SUB/CV-SUPPLY-UNIT: rust.expect_already_generated_n1 mismatch", problems)

    def test_block_basic_check_with_fees_does_not_require_post_supply_output(self):
        token = str(MAX_U128)
        vector = {
            "id": "CV-SUPPLY-NONMUTATING",
            "op": "block_basic_check_with_fees",
            "block_hex": "00",
            "height": 1,
            "already_generated": token,
            "sum_fees": 0,
            "expect_ok": True,
        }

        problems, skipped, seen = self._run_with_responses(
            vector,
            [{"ok": True}, {"ok": True}],
        )

        self.assertEqual(problems, [])
        self.assertFalse(skipped)
        self.assertEqual([req["already_generated"] for req in seen], [token, token])


if __name__ == "__main__":
    unittest.main()

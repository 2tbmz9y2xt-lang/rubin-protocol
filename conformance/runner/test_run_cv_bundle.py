import unittest
from pathlib import Path
from unittest import mock

if __package__:
    from .run_cv_bundle import TXCTX_GOVERNANCE_VECTOR_IDS, normalized_vector_op, validate_vector
else:
    from run_cv_bundle import TXCTX_GOVERNANCE_VECTOR_IDS, normalized_vector_op, validate_vector


class RunCvBundleOpNormalizationTests(unittest.TestCase):
    def test_txctx_whitespace_op_defaults_to_spend_vector(self):
        op = normalized_vector_op("CV-TXCTX", {"id": "CV-TXCTX-01", "op": "   "})
        self.assertEqual(op, "txctx_spend_vector")

    def test_txctx_governance_vectors_route_to_governance_harness(self):
        vector_id = next(iter(TXCTX_GOVERNANCE_VECTOR_IDS))
        op = normalized_vector_op("CV-TXCTX", {"id": vector_id, "op": "   "})
        self.assertEqual(op, "txctx_governance_vector")

    def test_non_txctx_whitespace_op_is_missing(self):
        op = normalized_vector_op("CV-OTHER", {"id": "X", "op": "   "})
        self.assertEqual(op, "   ")

    def test_noncanonical_whitespace_is_not_silently_normalized(self):
        op = normalized_vector_op("CV-TXCTX", {"id": "CV-TXCTX-01", "op": " txctx_spend_vector "})
        self.assertEqual(op, " txctx_spend_vector ")

    def test_txctx_invalid_nonstring_op_returns_validation_error_instead_of_crashing(self):
        problems, skipped = validate_vector("CV-TXCTX", {"id": "CV-TXCTX-01", "op": 0}, None, None, {})
        self.assertEqual(problems, ["CV-TXCTX/CV-TXCTX-01: missing op"])
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
                    problems, skipped = validate_vector(
                        "CV-NATIVE-ROTATION-DESCRIPTOR",
                        vector,
                        Path("/tmp/go-cli"),
                        Path("/tmp/rust-cli"),
                        {},
                    )
                self.assertEqual(problems, [])
                self.assertFalse(skipped)
                self.assertEqual(len(seen), 2)
                for req in seen:
                    self.assertEqual(req["op"], expected_op)
                    self.assertEqual(req["network"], vector["network"])


if __name__ == "__main__":
    unittest.main()

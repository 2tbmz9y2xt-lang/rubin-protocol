import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from txctx_case import build_txctx_case, build_txctx_governance_request


FIXTURE = {
    "profiles": {
        "p": {
            "ext_id": 0x0FFE,
            "activation_height": 100,
            "txcontext_enabled": 1,
            "allowed_sighash_set": 1,
            "max_ext_payload_bytes": 48,
            "binding_kind": 2,
            "suite_count": 1,
            "suite_id": 16,
        }
    }
}


class TxctxCaseTests(unittest.TestCase):
    def test_explicit_zero_height_is_preserved(self):
        vector = {
            "id": "v",
            "profile": "p",
            "height": 0,
            "self_input_value": 5,
            "continuing_outputs": [],
        }
        case = build_txctx_case(vector, FIXTURE)
        self.assertEqual(case["height"], 0)

    def test_output_covenant_type_defaults_to_valid_value(self):
        vector = {
            "id": "v",
            "profile": "p",
            "height": 200,
            "output_covenant_types": ["CORE_P2PK"],
        }
        case = build_txctx_case(vector, FIXTURE)
        self.assertEqual(case["outputs"][0]["value"], 1)

    def test_output_count_padding_uses_positive_value(self):
        vector = {"id": "v", "profile": "p", "height": 200, "output_count": 1}
        case = build_txctx_case(vector, FIXTURE)
        self.assertEqual(case["outputs"][0]["covenant_type"], "CORE_P2PK")
        self.assertEqual(case["outputs"][0]["value"], 1)

    def test_continuing_output_count_padding_uses_positive_value(self):
        vector = {
            "id": "v",
            "profile": "p",
            "height": 200,
            "continuing_output_count": 1,
        }
        case = build_txctx_case(vector, FIXTURE)
        self.assertEqual(case["outputs"][0]["covenant_type"], "CORE_EXT")
        self.assertEqual(case["outputs"][0]["value"], 1)

    def test_prevout_short_hex_left_pads_before_width_fixing(self):
        vector = {
            "id": "v",
            "profile": "p",
            "height": 200,
            "inputs": [
                {"prevout": "1:0"},
                {"prevout": "01:0"},
            ],
        }
        case = build_txctx_case(vector, FIXTURE)
        self.assertEqual(case["inputs"][0]["prevout_txid_hex"], case["inputs"][1]["prevout_txid_hex"])

    def test_governance_request_uses_duplicate_suite_ids_from_profile_attempt(self):
        vector = {
            "id": "CV-TXCTX-60",
            "profile_attempt": {
                "ext_id": 0x0FEB,
                "allowed_suite_ids": [16, 16],
            },
        }
        request = build_txctx_governance_request(vector, FIXTURE)
        self.assertEqual(request["op"], "txctx_governance_vector")
        self.assertEqual(request["core_ext_profiles"][0]["allowed_suite_ids"], [16, 16])
        self.assertEqual(request["dependency_checklists"][0]["profile_ext_id"], "0x0feb")
        self.assertTrue(request["artifact_hex"])
        self.assertTrue(request["expected_artifact_hash_hex"])

    def test_governance_request_carries_transition_height_guard(self):
        vector = {
            "id": "CV-TXCTX-GOV-01",
            "profile_under_test": {
                "activation_height": 99,
                "transition_height": 100,
            },
        }
        request = build_txctx_governance_request(vector, FIXTURE)
        self.assertEqual(request["transition_height"], 100)
        self.assertEqual(request["core_ext_profiles"][0]["activation_height"], 99)
        self.assertTrue(request["artifact_hex"])
        self.assertTrue(request["expected_artifact_hash_hex"])


if __name__ == "__main__":
    unittest.main()

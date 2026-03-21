import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from txctx_case import build_txctx_case


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


if __name__ == "__main__":
    unittest.main()

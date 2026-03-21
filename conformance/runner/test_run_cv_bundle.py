import unittest

from run_cv_bundle import TXCTX_GOVERNANCE_SKIP_IDS, normalized_vector_op


class RunCvBundleOpNormalizationTests(unittest.TestCase):
    def test_txctx_whitespace_op_defaults_to_spend_vector(self):
        op = normalized_vector_op("CV-TXCTX", {"id": "CV-TXCTX-01", "op": "   "})
        self.assertEqual(op, "txctx_spend_vector")

    def test_txctx_governance_skip_keeps_none(self):
        vector_id = next(iter(TXCTX_GOVERNANCE_SKIP_IDS))
        op = normalized_vector_op("CV-TXCTX", {"id": vector_id, "op": "   "})
        self.assertIsNone(op)

    def test_non_txctx_whitespace_op_is_missing(self):
        op = normalized_vector_op("CV-OTHER", {"id": "X", "op": "   "})
        self.assertIsNone(op)


if __name__ == "__main__":
    unittest.main()

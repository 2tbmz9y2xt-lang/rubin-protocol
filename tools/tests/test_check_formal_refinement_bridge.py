from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import check_formal_refinement_bridge as m  # noqa: E402


class FormalRefinementBridgeTests(unittest.TestCase):
    def test_limitations_must_be_non_empty_string_list(self) -> None:
        self.assertTrue(m.valid_non_empty_string_list(["bounded trace scope"]))
        self.assertFalse(m.valid_non_empty_string_list([]))
        self.assertFalse(m.valid_non_empty_string_list([""]))
        self.assertFalse(m.valid_non_empty_string_list(["ok", 7]))
        self.assertFalse(m.valid_non_empty_string_list("bounded trace scope"))

    def test_scope_marker_rejects_unbounded(self) -> None:
        self.assertTrue(m.states_bounded_scope("bounded fixture trace scope"))
        self.assertFalse(m.states_bounded_scope("unbounded universal proof"))
        self.assertFalse(m.states_bounded_scope("bounded universal proof for all inputs"))
        self.assertFalse(m.states_bounded_scope("not bounded universal proof"))
        self.assertFalse(m.states_bounded_scope("fixture trace scope"))

    def test_trace_ids_for_op_uses_exact_trace_subset(self) -> None:
        trace_text = '''
def parseOuts : List ParseOut := [
  { id := "PARSE-01", ok := true },
  { id := "PARSE-16", ok := true }
]

def powOuts : List PowOut := [
  { id := "POW-01", op := "retarget_v1", ok := true },
  { id := "POW-04", op := "block_hash", ok := true }
]
'''

        self.assertEqual(m.trace_ids_for_op(trace_text, "parse_tx"), {"PARSE-01", "PARSE-16"})
        self.assertEqual(m.trace_ids_for_op(trace_text, "retarget_v1"), {"POW-01"})


if __name__ == "__main__":
    unittest.main()

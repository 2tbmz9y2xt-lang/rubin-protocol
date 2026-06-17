from __future__ import annotations

import unittest

from tools.formal.gen_lean_conformance_vectors import _optional_hex


class LeanConformanceVectorGeneratorTests(unittest.TestCase):
    def test_optional_hex_allows_absent_and_non_empty_values(self) -> None:
        self.assertIsNone(_optional_hex({}, "program_hex"))
        self.assertEqual(_optional_hex({"program_hex": "24"}, "program_hex"), "24")
        self.assertEqual(_optional_hex({"program_hex": "0x24"}, "program_hex"), "0x24")

    def test_optional_hex_rejects_present_empty_values(self) -> None:
        for value in ("", "   ", "0x", "0X", " 0x "):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "program_hex must be a non-empty hex string"):
                    _optional_hex({"program_hex": value}, "program_hex")


if __name__ == "__main__":
    unittest.main()

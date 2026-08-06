from __future__ import annotations

import unittest

from tools.formal.gen_lean_conformance_vectors import _optional_hex, _widened_fee

MAX_U64 = (1 << 64) - 1
MAX_U128 = (1 << 128) - 1


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


class WidenedFeeReaderTests(unittest.TestCase):
    """Pins the reader that decides which fixture fee spellings reach the
    formal layer. Same contract as `exact_uint` in the conformance runner, Go
    `consensus.Uint128.UnmarshalJSON`, and Rust `uint128_json::deserialize`.
    """

    def read(self, value: object) -> int:
        return _widened_fee({"expect_fee": value}, "expect_fee", "CV-X-001")

    def test_accepts_legacy_numeric_tokens_through_u64(self) -> None:
        for value in (0, 1, MAX_U64):
            with self.subTest(value=value):
                self.assertEqual(self.read(value), value)

    def test_accepts_canonical_decimal_strings_through_u128(self) -> None:
        for text, want in (
            ("0", 0),
            ("1", 1),
            (str(MAX_U64 + 1), MAX_U64 + 1),
            (str(MAX_U128), MAX_U128),
        ):
            with self.subTest(text=text):
                self.assertEqual(self.read(text), want)

    def test_rejects_every_other_spelling(self) -> None:
        for value in (
            # A JSON null never reads as legacy zero (RUB-1127 fixed_json_rule).
            None,
            True,
            False,
            -1,
            MAX_U64 + 1,
            1.0,
            "",
            "00",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1.0",
            "1e3",
            str(MAX_U128 + 1),
            [],
            {},
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self.read(value)


if __name__ == "__main__":
    unittest.main()

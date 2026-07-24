import json
from pathlib import Path
import subprocess
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


class CovenantRegistryDispositionTests(unittest.TestCase):
    def assert_lean_decisions(self, predicates: list[str]) -> None:
        source = "\n".join(
            [
                "import RubinFormal.CovenantRegistryExhaustive",
                "open RubinFormal",
                *(f"#eval decide ({predicate})" for predicate in predicates),
                "",
            ]
        )
        completed = subprocess.run(
            ["lake", "env", "lean", "/dev/stdin"],
            cwd=REPO_ROOT,
            input=source,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.splitlines(), ["true"] * len(predicates))

    def test_full_explicit_matrix_and_unknown_tags(self) -> None:
        expected_dispositions = {
            0x0000: "CovenantDisposition.accepted CovenantKind.coreP2PK",
            0x0001: "CovenantDisposition.invalidCovenantType",
            0x0002: "CovenantDisposition.accepted CovenantKind.coreAnchor",
            0x00FF: "CovenantDisposition.reserved",
            0x0100: "CovenantDisposition.accepted CovenantKind.coreHTLC",
            0x0101: "CovenantDisposition.accepted CovenantKind.coreVault",
            0x0102: "CovenantDisposition.invalidCovenantType",
            0x0103: "CovenantDisposition.accepted CovenantKind.coreDACommit",
            0x0104: "CovenantDisposition.accepted CovenantKind.coreMultisig",
            0x0105: "CovenantDisposition.accepted CovenantKind.coreStealth",
            0x0106: "CovenantDisposition.deploymentGated CovenantKind.coreSimplicity",
            0x0003: "CovenantDisposition.invalidCovenantType",
            0x00FE: "CovenantDisposition.invalidCovenantType",
            0x0107: "CovenantDisposition.invalidCovenantType",
            0xFFFF: "CovenantDisposition.invalidCovenantType",
            0x10000: "CovenantDisposition.invalidCovenantType",
        }
        predicates = [
            f"covenantDisposition {tag} = {expected}"
            for tag, expected in expected_dispositions.items()
        ]
        self.assert_lean_decisions(predicates)

    def test_invalid_dispositions_keep_the_exact_registry_error_marker(self) -> None:
        self.assert_lean_decisions(
            [
                "CovenantDisposition.errorCode? (covenantDisposition 0x0001) = some invalidCovenantTypeError",
                "CovenantDisposition.errorCode? (covenantDisposition 0x0102) = some invalidCovenantTypeError",
                "CovenantDisposition.errorCode? (covenantDisposition 0x0107) = some invalidCovenantTypeError",
                "invalidCovenantTypeError = \"TX_ERR_COVENANT_TYPE_INVALID\"",
                "CovenantDisposition.errorCode? (covenantDisposition 0x00FF) = none",
                "CovenantDisposition.errorCode? (covenantDisposition 0x0105) = none",
                "CovenantDisposition.errorCode? (covenantDisposition 0x0106) = none",
            ]
        )

    def test_coverage_registers_the_exhaustive_disposition_theorem(self) -> None:
        coverage = json.loads((REPO_ROOT / "proof_coverage.json").read_text(encoding="utf-8"))
        row = next(item for item in coverage["coverage"] if item["section_key"] == "covenant_registry")

        theorem = "RubinFormal.covenantDispositionComplete"
        self.assertIn(theorem, row["theorems"])
        self.assertEqual(
            row["theorem_files"][theorem],
            "rubin-formal/RubinFormal/CovenantRegistryExhaustive.lean",
        )


if __name__ == "__main__":
    unittest.main()

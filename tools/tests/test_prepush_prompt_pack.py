#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import prepush_prompt_pack as m


class PrepushPromptPackTests(unittest.TestCase):
    def test_compose_prompt_includes_base_contract_and_lenses(self):
        prompt = m.compose_prompt(
            check_type="diff_only",
            active_lenses=["code-review", "diff-scan"],
            fullscan_text="Skill-backed full-scan supplement:",
            focus_lines=["Focus A", "Focus B"],
            bundle_text="=== PUSH TARGET ===\n...",
        )
        self.assertIn("You are RUBIN pre-push security reviewer operating in FAIL-CLOSED mode.", prompt)
        self.assertIn("CHECK_TYPE=diff_only", prompt)
        self.assertIn("ACTIVE_LENSES=code-review,diff-scan", prompt)
        self.assertIn("summary MUST be single-line machine-readable", prompt)
        self.assertIn("Mandatory review focuses for this diff:", prompt)
        self.assertIn("- Focus A", prompt)
        self.assertIn("Diff bundle follows.", prompt)

    def test_each_check_type_has_overlay(self):
        expectations = {
            "consensus_critical": "Threat model: malformed input adversary",
            "formal_lean": "Lean proof soundness boundaries",
            "code_noncritical": "Correctness regressions, security defaults",
            "diff_only": "Strict changed-line scan",
        }
        for check_type, phrase in expectations.items():
            with self.subTest(check_type=check_type):
                prompt = m.compose_prompt(
                    check_type=check_type,
                    active_lenses=["code-review", "diff-scan"],
                    fullscan_text="",
                    focus_lines=[],
                    bundle_text="=== PUSH TARGET ===\n...",
                )
                self.assertIn(phrase, prompt)

    def test_compose_prompt_rejects_unknown_check_type(self):
        with self.assertRaisesRegex(ValueError, "unsupported check_type"):
            m.compose_prompt(
                check_type="unknown",
                active_lenses=[],
                fullscan_text="",
                focus_lines=[],
                bundle_text="=== PUSH TARGET ===\n...",
            )

    def test_compose_prompt_rejects_empty_bundle(self):
        with self.assertRaisesRegex(ValueError, "diff bundle is empty"):
            m.compose_prompt(
                check_type="diff_only",
                active_lenses=[],
                fullscan_text="",
                focus_lines=[],
                bundle_text=" \n",
            )


if __name__ == "__main__":
    unittest.main()

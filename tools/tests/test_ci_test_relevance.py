import subprocess
import unittest
from pathlib import Path

from tools import ci_test_relevance as subject


def diff(*records):
    return b"".join(b"\0".join(item.encode() for item in record) + b"\0" for record in records)


def runner(payload=b"M\0docs/readme.md\0", *, verify_code=0, ancestor_code=0, diff_code=0):
    def run(command, **_kwargs):
        if command[1] == "rev-parse":
            code, output = verify_code, b"base\n"
        elif command[1] == "merge-base":
            code, output = ancestor_code, b""
        else:
            code, output = diff_code, payload
        return subprocess.CompletedProcess(command, code, output, b"")
    return run


class TestRelevanceTests(unittest.TestCase):
    def decision(self, payload):
        return subject.decide("pull_request", "a" * 40, runner(payload), lambda _path: False)

    def test_profile_rows_and_nearest_misses(self):
        cases = {
            ".gitattributes": True, ".github/workflows/ci.yml": True, ".node-version": True,
            "go.work": True, "go.work.sum": True,
            "rust-toolchain": True, "rust-toolchain.toml": True,
            "rustfmt.toml": True, ".rustfmt.toml": True,
            "clippy.toml": True, ".clippy.toml": True,
            "evidence/.gitattributes": True, "evidence/runtime-perf/.gitattributes": True,
            "evidence/runtime-perf/RUST_RUNTIME_PERF_GUARDRAILS.md": True,
            ".cargo/config": True, ".cargo/config.toml": True,
            ".github/actions/a/action.yml": True, "clients/go/x.go": True,
            "conformance/x.go": True, "scripts/x.sh": True, "tools/x.py": True, "vendor/modules.txt": True,
            ".cargo": False, ".cargos/config.toml": False,
            "client/x.go": False, "tool/x.py": False, "script/x.sh": False,
            ".github/workflows/ci.yaml": False, "rust-toolchain.toml.bak": False,
            "vendorized/modules.txt": False,
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(self.decision(diff(("M", path))).run_test, expected)

    def test_add_delete_modify_type_change_and_mixed_diffs(self):
        for status in "ADMT":
            with self.subTest(status=status):
                self.assertTrue(self.decision(diff((status, ".node-version"))).run_test)
        self.assertFalse(self.decision(diff(("D", "docs/readme.md"))).run_test)
        self.assertTrue(self.decision(diff(("M", "docs/readme.md"), ("M", "tools/x.py"))).run_test)

    def test_rename_and_copy_check_both_paths(self):
        for status in ("R100", "C100"):
            for old, new in (("docs/a.md", "tools/a.py"), ("tools/a.py", "docs/a.md")):
                with self.subTest(status=status, old=old, new=new):
                    self.assertTrue(self.decision(diff((status, old, new))).run_test)

    def test_malformed_empty_unknown_and_invalid_records_run(self):
        payloads = (
            b"", b"\0", b"M\0tools/a.py", b"R\0a\0b\0", b"R101\0a\0b\0",
            b"Cabc\0a\0b\0", b"X\0a\0", b"M\0\0", b"M\0../a\0",
            b"M\0/a\0", b"M\0\xff\0", b"M\0a\\b\0", b"M\0a\nb\0",
            b"M\0a\rb\0", b"M\0a\tb\0", b"M\0a\x7fb\0",
        )
        payloads += tuple(
            b"M\0a" + chr(codepoint).encode("utf-8") + b"b\0"
            for codepoint in range(0x80, 0xA0)
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                self.assertTrue(self.decision(payload).run_test)

    def test_events_and_git_errors_run(self):
        self.assertTrue(subject.decide("push", "", runner()).run_test)
        self.assertTrue(subject.decide("pull_request", "", runner()).run_test)
        self.assertTrue(subject.decide("pull_request", "main", runner()).run_test)
        self.assertTrue(subject.decide("pull_request", "a" * 40, runner(verify_code=1), lambda _path: False).run_test)
        self.assertTrue(subject.decide("pull_request", "a" * 40, runner(ancestor_code=1), lambda _path: False).run_test)
        self.assertTrue(subject.decide("pull_request", "a" * 40, runner(diff_code=1), lambda _path: False).run_test)
        def broken(*_args, **_kwargs):
            raise RuntimeError("boom")
        with self.assertRaises(RuntimeError):
            subject.decide("pull_request", "a" * 40, broken, lambda _path: False)

    def test_delegating_repository_configs_force_full_run(self):
        for present in subject.DELEGATING_CONFIGS:
            with self.subTest(present=present):
                decision = subject.decide(
                    "pull_request", "a" * 40, runner(), lambda path: path == present,
                )
                self.assertTrue(decision.run_test)
                self.assertIn(present, decision.reason)

    def test_diff_command_enables_nul_rename_and_copy_detection(self):
        commands = []
        base_sha = "a" * 40
        def record(command, **kwargs):
            commands.append(command)
            return runner()(command, **kwargs)
        subject.decide("pull_request", base_sha, record, lambda _path: False)
        self.assertEqual(commands[0], ["git", "rev-parse", "--verify", f"{base_sha}^{{commit}}"])
        self.assertEqual(commands[1], ["git", "merge-base", "--is-ancestor", base_sha, "HEAD"])
        self.assertEqual(commands[2][:4], ["git", "diff", "--name-status", "-z"])
        self.assertEqual(commands[2][-1], f"{base_sha}..HEAD")
        self.assertNotIn("origin/", " ".join(" ".join(command) for command in commands))
        for flag in ("--find-renames", "--find-copies", "--find-copies-harder"):
            self.assertIn(flag, commands[2])

    def test_workflow_keeps_json_unconditional_and_gates_other_steps(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text()
        job = workflow.split("\n  test:\n", 1)[1].split("\n  go_race_node:", 1)[0]
        steps = job.split("\n      - ")[1:]
        gate = "steps.test_gate.outputs.run_test == 'true'"
        self.assertIn("\n    env:\n      PYTHONSAFEPATH: '1'\n", job)
        self.assertIn("\n        with:\n          fetch-depth: 0\n", steps[0])
        self.assertEqual(steps[1].splitlines()[:5], ["name: Classify test relevance", "        id: test_gate", "        env:", "          RUBIN_TEST_RELEVANCE_BASE_SHA: ${{ github.event.pull_request.base.sha }}", "        run: python3 tools/ci_test_relevance.py"])
        self.assertTrue(steps[2].startswith("name: Strict JSON parse (tracked)\n"))
        self.assertNotIn("\n        if:", steps[1])
        self.assertNotIn("\n        if:", steps[2])
        for step in steps[3:]:
            self.assertEqual([line.strip() for line in step.splitlines() if line.startswith("        if:")], [f"if: {gate}"], step)
        setup_node = next(step for step in steps if "uses: actions/setup-node@" in step)
        self.assertIn("\n          package-manager-cache: false\n", setup_node)


if __name__ == "__main__":
    unittest.main()

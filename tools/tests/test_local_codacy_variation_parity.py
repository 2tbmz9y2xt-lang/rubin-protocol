#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "local-codacy-variation-parity.sh"
CASES = [
    ("published matching", {"checkout": "published"}, 0, "PASS: Codacy metadata binds published PR head"),
    ("unpublished descendant", {}, 0, "PASS: Codacy metadata binds published PR head"),
    ("wrong ancestor", {"codacy_ancestor": "main"}, 1, "differs from published-head merge-base"),
    ("stale head", {"codacy_head": "main"}, 1, "differs from published PR head"),
    ("unrelated published head", {"head": "unrelated", "codacy_head": "unrelated"}, 1, "is not an ancestor of local candidate"),
    ("missing head", {"head": ""}, 1, "missing or not a 40-hex object id"),
    ("missing head fallback", {"head": "", "curl_fail": True}, 1, "missing or not a 40-hex object id"),
    ("changed head", {"second": "main"}, 1, "changed during metadata parity check"),
    ("changed head fallback", {"second": "main", "curl_fail": True}, 1, "changed during metadata parity check"),
    ("malformed json", {"malformed": "json"}, 1, "malformed Codacy PR metadata"),
    ("ancestor not object", {"malformed": "ancestor_object"}, 1, "malformed Codacy PR metadata"),
    ("head not object", {"malformed": "head_object"}, 1, "malformed Codacy PR metadata"),
    ("ancestor reports not list", {"malformed": "ancestor_reports"}, 1, "malformed Codacy PR metadata"),
    ("head reports not list", {"malformed": "head_reports"}, 1, "malformed Codacy PR metadata"),
    ("ancestor report not object", {"malformed": "shape"}, 1, "malformed Codacy PR metadata"),
    ("head report not object", {"malformed": "head_shape"}, 1, "malformed Codacy PR metadata"),
    ("5001 digit integer", {"malformed": "huge_int"}, 1, "malformed Codacy PR metadata"),
    ("surrogate head", {"codacy_head": "\ud800"}, 1, "differs from published PR head"),
    ("surrogate ancestor", {"codacy_ancestor": "\ud800"}, 1, "differs from published-head merge-base"),
    ("no open PR", {"pr": False}, 0, "PASS: no open PR"),
    ("metadata unavailable", {"curl_fail": True}, 0, "PASS: Codacy metadata unavailable"),
]
MALFORMED = {
    "ancestor_object": ("commonAncestorCommit", "bad"),
    "head_object": ("headCommit", "bad"),
    "ancestor_reports": ("commonAncestorCommit", {"reports": "bad"}),
    "head_reports": ("headCommit", {"reports": 7}),
    "shape": ("commonAncestorCommit", {"reports": [{"status": "Processed"}, "bad"]}),
    "head_shape": ("headCommit", {"reports": ["bad"]}),
}


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.repo = root / "candidate repo"
        self.origin = root / "origin.git"
        self.stub = root / "stub"
        self.bin = root / "bin"
        self.home = root / "home"
        for path in (self.repo, self.stub, self.bin, self.home):
            path.mkdir()
        self.env = os.environ.copy()
        self.env.update(
            {
                "HOME": str(self.home),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.com",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.com",
                "GIT_TERMINAL_PROMPT": "0",
                "PYTHONINTMAXSTRDIGITS": "4300",
                "PYTHONIOENCODING": "utf-8:strict",
            }
        )
        self.g("init", "--quiet", "--initial-branch=main", str(self.repo))
        blob = self.g("hash-object", "-w", "--stdin", cwd=self.repo, input_text="fixture\n")
        tree = self.g("mktree", cwd=self.repo, input_text=f"100644 blob {blob}\tfixture.txt\n")
        self.base = self.commit(tree, "base")
        self.main = self.commit(tree, "main", self.base)
        self.published = self.commit(tree, "published", self.base)
        self.candidate = self.commit(tree, "candidate", self.published, self.main)
        self.unrelated = self.commit(tree, "unrelated", self.base)
        self.g("update-ref", "refs/heads/main", self.main, cwd=self.repo)
        self.g("update-ref", "refs/heads/agent", self.published, cwd=self.repo)
        self.g("clone", "--quiet", "--bare", str(self.repo), str(self.origin))
        self.g("remote", "add", "origin", str(self.origin), cwd=self.repo)
        (self.repo / "scripts").mkdir()
        self.script = self.repo / "scripts" / SCRIPT.name
        shutil.copy2(SCRIPT, self.script)
        self._stubs()

    def g(self, *args: str, cwd: Path | None = None, input_text: str | None = None) -> str:
        result = subprocess.run(
            ["git", *args], cwd=cwd or self.root, env=self.env, check=True,
            input=input_text, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20,
        )
        return result.stdout.strip()

    def commit(self, tree: str, message: str, *parents: str) -> str:
        args = ["-c", "user.name=Test", "-c", "user.email=test@example.com", "commit-tree", tree, "-m", message]
        for parent in parents:
            args.extend(["-p", parent])
        return self.g(*args, cwd=self.repo)

    def ref(self, name: object) -> str:
        value = str(name)
        return getattr(self, value) if value in {"base", "main", "published", "candidate", "unrelated"} else value

    def _stubs(self) -> None:
        (self.bin / "gh").write_text(
            """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == repo && "${2:-}" == view ]]; then
  printf '%s\\n' 'owner/repo'
  exit 0
fi
if [[ "${1:-}" == pr && "${2:-}" == view ]]; then
  if [[ " $* " == *' --json number '* ]]; then
    printf 'called\\n' >> "$STUB_DIR/number_calls"
    [[ "${STUB_PR_EXISTS:-1}" == 1 ]] && { printf '%s\\n' 7; exit 0; }
    exit 1
  fi
  if [[ " $* " == *' --json headRefOid '* ]]; then
    count=0
    [[ -f "$STUB_DIR/head_calls" ]] && count="$(cat "$STUB_DIR/head_calls")"
    count=$((count + 1))
    printf '%s\\n' "$count" > "$STUB_DIR/head_calls"
    if [[ "$count" -le 1 ]]; then printf '%s\\n' "$STUB_HEAD_FIRST"; else printf '%s\\n' "${STUB_HEAD_SECOND:-$STUB_HEAD_FIRST}"; fi
    exit 0
  fi
fi
exit 1
""",
            encoding="utf-8",
        )
        (self.bin / "curl").write_text(
            """#!/usr/bin/env bash
set -euo pipefail
[[ -n "${STUB_CURL_FAIL:-}" ]] && exit 22
cat "$STUB_DIR/codacy.json"
""",
            encoding="utf-8",
        )
        for name in ("gh", "curl"):
            (self.bin / name).chmod(0o755)

    def payload(self, opts: dict[str, object]) -> str:
        ancestor = self.ref(opts.get("codacy_ancestor", "base"))
        head = self.ref(opts.get("codacy_head", "published"))
        malformed = opts.get("malformed")
        data = {
            "data": {
                "commonAncestorCommit": {"commitSha": ancestor, "reports": [{"status": "Processed"}]},
                "headCommit": {"commitSha": head, "reports": [{"status": "Processed"}]},
            }
        }
        holder = data["data"]
        mutation = MALFORMED.get(malformed)
        if mutation:
            key, patch = mutation
            if isinstance(patch, dict):
                holder[key].update(patch)
            else:
                holder[key] = patch
        payload = "{not json" if malformed == "json" else json.dumps(data, ensure_ascii=True)
        if malformed == "huge_int":
            payload = payload[:-1] + ',"padding":' + "1" * 5001 + "}"
        return payload

    def run(self, branch: str, opts: dict[str, object]) -> subprocess.CompletedProcess[str]:
        self.g("checkout", "--quiet", "-B", branch, self.ref(opts.get("checkout", "candidate")), cwd=self.repo)
        head_name = opts.get("head", "published")
        first = self.ref(head_name) if head_name else ""
        second = self.ref(opts["second"]) if "second" in opts else first
        (self.stub / "codacy.json").write_text(self.payload(opts), encoding="utf-8")
        (self.stub / "head_calls").unlink(missing_ok=True)
        (self.stub / "number_calls").unlink(missing_ok=True)
        env = self.env.copy()
        env.update(
            {
                "PATH": f"{self.bin}{os.pathsep}{env['PATH']}",
                "STUB_DIR": str(self.stub),
                "STUB_HEAD_FIRST": first,
                "STUB_HEAD_SECOND": second,
                "STUB_PR_EXISTS": "1" if opts.get("pr", True) else "0",
            }
        )
        env.pop("CODACY_PR_NUMBER", None)
        env.pop("STUB_CURL_FAIL", None)
        if opts.get("curl_fail"):
            env["STUB_CURL_FAIL"] = "1"
        for name in ("GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH"):
            env.pop(name, None)
        return subprocess.run(
            ["bash", str(self.script)], cwd=self.repo, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )


class LocalCodacyVariationParityTests(unittest.TestCase):
    def test_local_metadata_cases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="codacy parity ") as tmp:
            fixture = Fixture(Path(tmp))
            for index, (name, opts, expected_exit, marker) in enumerate(CASES):
                with self.subTest(case=name):
                    result = fixture.run(f"case-{index}", opts)
                    self.assertTrue((fixture.stub / "number_calls").is_file(), "gh number discovery not called")
                    self.assertEqual(result.returncode, expected_exit, result.stderr)
                    if expected_exit == 0:
                        self.assertIn(marker, result.stdout)
                    else:
                        self.assertIn(marker, result.stderr)
                        self.assertNotIn("PASS:", result.stdout + result.stderr)
                        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()

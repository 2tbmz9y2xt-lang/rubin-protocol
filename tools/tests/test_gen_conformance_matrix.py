"""Contract tests for tools/gen_conformance_matrix.py."""

from __future__ import annotations

import copy
import errno
import re
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import gen_conformance_matrix as m


class GenConformanceMatrixTests(unittest.TestCase):
    def test_load_protocol_artifact_rows_accepts_repo_protocol_artifacts(self) -> None:
        rows = m.load_protocol_artifact_rows()
        self.assertTrue(rows)
        self.assertIn(
            "protocol/live_binding_policy_v1.json",
            {row.path for row in rows},
        )

    def test_canonical_pipeline_corpus_is_a_registered_protocol_artifact(self) -> None:
        # RUB-922 / C01 and RUB-1207 / C01-R2: both revisions must appear in the
        # generated matrix inventory, so a silently dropped artifact fails the
        # --check gate. Registration also strict-loads each artifact.
        rows = {row.path: row for row in m.load_protocol_artifact_rows()}
        for name in ("canonical_pipeline_v1.json", "canonical_pipeline_v2.json"):
            self.assertIn(name, m.EXPECTED_PROTOCOL_ARTIFACTS)
            self.assertIn(f"protocol/{name}", rows)
        # The dormant R2 revision must never be published as an active authority.
        self.assertIn("BUILDING", rows["protocol/canonical_pipeline_v2.json"].purpose)

    def test_load_protocol_artifact_rows_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = Path(tmpdir) / "live_binding_policy_v1.json"
            artifact.write_text(
                '{"version": 1, "version": 2, "entries": []}',
                encoding="utf-8",
            )
            with (
                mock.patch.object(m, "EXPECTED_PROTOCOL_ARTIFACTS", frozenset({artifact.name})),
                mock.patch.object(
                    m,
                    "PROTOCOL_ARTIFACT_META",
                    {artifact.name: ("Canonical live binding policy artifact", "tests")},
                ),
                mock.patch.object(m, "iter_protocol_artifacts", return_value=[artifact]),
            ):
                with self.assertRaisesRegex(RuntimeError, 'duplicate JSON key "version"'):
                    m.load_protocol_artifact_rows()

    def test_load_protocol_artifact_rows_rejects_malformed_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = Path(tmpdir) / "live_binding_policy_v1.json"
            artifact.write_text('{"version": 1,', encoding="utf-8")
            with (
                mock.patch.object(m, "EXPECTED_PROTOCOL_ARTIFACTS", frozenset({artifact.name})),
                mock.patch.object(
                    m,
                    "PROTOCOL_ARTIFACT_META",
                    {artifact.name: ("Canonical live binding policy artifact", "tests")},
                ),
                mock.patch.object(m, "iter_protocol_artifacts", return_value=[artifact]),
            ):
                with self.assertRaisesRegex(RuntimeError, "invalid JSON artifact"):
                    m.load_protocol_artifact_rows()

    def test_load_protocol_artifact_rows_rejects_nonstandard_json_numbers(self) -> None:
        cases = (
            ('{"version": NaN, "entries": []}', "invalid JSON constant 'NaN'"),
            ('{"version": Infinity, "entries": []}', "invalid JSON constant 'Infinity'"),
            ('{"version": -Infinity, "entries": []}', "invalid JSON constant '-Infinity'"),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                with tempfile.TemporaryDirectory() as tmpdir:
                    artifact = Path(tmpdir) / "live_binding_policy_v1.json"
                    artifact.write_text(raw, encoding="utf-8")
                    with (
                        mock.patch.object(
                            m, "EXPECTED_PROTOCOL_ARTIFACTS", frozenset({artifact.name})
                        ),
                        mock.patch.object(
                            m,
                            "PROTOCOL_ARTIFACT_META",
                            {artifact.name: ("Canonical live binding policy artifact", "tests")},
                        ),
                        mock.patch.object(m, "iter_protocol_artifacts", return_value=[artifact]),
                    ):
                        with self.assertRaisesRegex(RuntimeError, expected):
                            m.load_protocol_artifact_rows()

    def test_load_protocol_artifact_rows_rejects_non_utf8_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            artifact = Path(tmpdir) / "live_binding_policy_v1.json"
            artifact.write_bytes(b'{"version": 1, "entries": []}\xff')
            with (
                mock.patch.object(m, "EXPECTED_PROTOCOL_ARTIFACTS", frozenset({artifact.name})),
                mock.patch.object(
                    m,
                    "PROTOCOL_ARTIFACT_META",
                    {artifact.name: ("Canonical live binding policy artifact", "tests")},
                ),
                mock.patch.object(m, "iter_protocol_artifacts", return_value=[artifact]),
            ):
                with self.assertRaisesRegex(RuntimeError, "invalid JSON artifact"):
                    m.load_protocol_artifact_rows()

    def test_load_protocol_artifact_rows_rejects_unreadable_json(self) -> None:
        artifact = Path("/tmp") / "live_binding_policy_v1.json"
        with (
            mock.patch.object(m, "EXPECTED_PROTOCOL_ARTIFACTS", frozenset({artifact.name})),
            mock.patch.object(
                m,
                "PROTOCOL_ARTIFACT_META",
                {artifact.name: ("Canonical live binding policy artifact", "tests")},
            ),
            mock.patch.object(m, "iter_protocol_artifacts", return_value=[artifact]),
            mock.patch.object(
                Path,
                "read_text",
                side_effect=PermissionError(errno.EACCES, "Permission denied", str(artifact)),
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                r"^cannot read JSON artifact live_binding_policy_v1\.json: Permission denied$",
            ):
                m.load_protocol_artifact_rows()


class UtxoCommitmentExpectedTests(unittest.TestCase):
    """The one inert corpus's data contract, without interpreting its law."""

    def setUp(self) -> None:
        self.data = m.load_json_fail_closed(
            m.PROTOCOL_FIXTURES_DIR / "utxo_commitment_expected_v1.json"
        )

    def assert_input_references(self, value: object, corpus: dict) -> None:
        if isinstance(value, list):
            for item in value:
                self.assert_input_references(item, corpus)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key.endswith(("_ref", "_refs")):
                    refs = item if key.endswith("_refs") else [item]
                    self.assertIsInstance(refs, list, "input-reference list")
                    for ref in refs:
                        self.assertIsInstance(ref, str, "input-reference string")
                        self.assertTrue(
                            ref.startswith("/input_fixtures/"), "input/expect separation"
                        )
                        target = corpus
                        for part in ref.split("/")[1:]:
                            self.assertIsInstance(target, dict, "input-reference object")
                            self.assertIn(part, target, "input-reference unresolved")
                            target = target[part]
                else:
                    self.assert_input_references(item, corpus)

    def assert_byte_literals(self, value: object) -> None:
        if isinstance(value, list):
            for item in value:
                self.assert_byte_literals(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key.endswith("_hex") or key == "hex":
                    literals = item if isinstance(item, list) else [item]
                    for literal in literals:
                        self.assertIsInstance(literal, str, "expected hex type")
                        self.assertRegex(literal, r"\A(?:[0-9a-f]{2})*\Z", "expected hex")
                        width = value.get(key.removesuffix("_hex") + "_bytes")
                        if key == "hex" and {"offset", "end"} <= value.keys():
                            width = value["end"] - value["offset"]
                        if width is not None:
                            self.assertIs(type(width), int, "expected width type")
                            self.assertGreaterEqual(width, 0, "expected width unsigned")
                            self.assertEqual(len(literal), 2 * width, "expected width")
                        if key.endswith(
                            ("root_hex", "hash_hex", "txid_hex", "chain_id_hex")
                        ):
                            self.assertEqual(len(literal), 64, "expected digest width")
                        if key.endswith(
                            ("key_hex", "K_hex", "mask_hex", "prefix_hex")
                        ):
                            self.assertEqual(len(literal), 72, "expected key width")
                elif isinstance(item, str) and key in {
                    "request_id", "last_used_id", "cumulative_chainwork", "W_min"
                }:
                    self.assertRegex(item, r"\A(?:0|[1-9][0-9]*)\Z", "wide unsigned")
                else:
                    self.assert_byte_literals(item)

    def assert_corpus_contract(self, data: dict) -> None:
        self.assertEqual(set(data), {
            "artifact", "format_version", "corpus_status", "authority",
            "normative_ref_registry", "input_fixtures", "cases",
        }, "corpus envelope")
        self.assertEqual(data["artifact"], "utxo_commitment_expected_v1")
        self.assertEqual(data["format_version"], 1)
        self.assertEqual(data["corpus_status"], "FROZEN_EXPECTED")
        authority = data["authority"]
        for field, repository, oid in (
            ("spec_ref", "rubin-spec", "2a30f15bbc4868f46fb7ccba9c776c80624159ad"),
            ("protocol_ref", "rubin-protocol", "8b76a1c308857c352ff1b690036a06b8aea78475"),
            ("control_plane_ref", "rubin-control-plane-private", "199e9b7d21f5a9e8ea7ef56ea38cbc6afe3031b3"),
        ):
            self.assertEqual(authority[field], {
                "repository": f"2tbmz9y2xt-lang/{repository}", "oid": oid,
            }, "authority binding")
        self.assertEqual(authority["execution"], "INERT_EXPECTED_DATA_ONLY")
        self.assertTrue(authority["expected_value_source"])
        self.assertTrue(authority["observation_boundary"])
        registry = data["normative_ref_registry"]
        refs: set[str] = set()
        for ref in registry:
            self.assertEqual(set(ref), {"id", "repository", "oid", "path", "sections"})
            self.assertIsInstance(ref["id"], str)
            self.assertRegex(ref["id"], r"\A[A-Z][A-Z0-9]*\Z")
            self.assertNotIn(ref["id"], refs, "duplicate source id")
            refs.add(ref["id"])
            self.assertEqual(ref["repository"], authority["spec_ref"]["repository"])
            self.assertEqual(ref["oid"], authority["spec_ref"]["oid"], "source binding")
            path = PurePosixPath(ref["path"])
            self.assertTrue(
                not path.is_absolute() and ".." not in path.parts
                and path.parts[0] == "spec" and "\\" not in ref["path"],
                "source path",
            )
            self.assertIsInstance(ref["sections"], list)
            self.assertTrue(ref["sections"])
            self.assertTrue(all(isinstance(s, str) and s for s in ref["sections"]))
        self.assertIsInstance(data["input_fixtures"], dict)
        self.assertTrue(data["input_fixtures"])
        self.assert_byte_literals(data["input_fixtures"])
        self.assertEqual(len(data["cases"]), 350, "case count")
        ids: set[str] = set()
        for case in data["cases"]:
            self.assertEqual(set(case), {"id", "input", "expect", "normative_refs"})
            self.assertIsInstance(case["id"], str)
            self.assertRegex(case["id"], r"\A(?:TREE|READ|HEADER|PAIR|WIRE|IMAGE|RESOURCE|BODY|ORDER)-[A-Za-z0-9_-]+\Z")
            self.assertNotIn(case["id"], ids, "duplicate case id")
            ids.add(case["id"])
            self.assertTrue(case["normative_refs"], "nonempty normative_refs")
            self.assertTrue(set(case["normative_refs"]) <= refs, "unresolved normative_refs")
            self.assertEqual(len(set(case["normative_refs"])), len(case["normative_refs"]))
            self.assertIsInstance(case["input"], dict)
            self.assertIsInstance(case["expect"], dict)
            self.assertTrue(case["expect"], "nonempty expected cells")
            self.assert_input_references(case["input"], data)
            self.assert_byte_literals(case["input"])
            boundary = case["input"]["boundary"]
            self.assertIn(boundary, {
                "SERIALIZATION_DOMAIN", "BLOCK_VALIDITY", "SYMBOLIC_OWNER_TRANSITION",
            }, "input boundary")
            if boundary != "SERIALIZATION_DOMAIN":
                expected = case["expect"]
                for field in (
                    "result", "state", "first_observation", "effects", "releases",
                    "publication", "next_operation",
                ):
                    self.assertIn(field, expected, f"applicable expected {field}")
                self.assertEqual(set(expected["result"]), {
                    "owner", "class", "truth", "diagnostic", "validity",
                }, "applicable result tuple")
                self.assertIsInstance(expected["state"], dict)
                self.assertIsInstance(expected["releases"], list)
                state = expected["state"]
                if "CURRENT" in state or "LAG" in state:
                    for role in ("CURRENT", "LAG"):
                        self.assertIn(role, state, "applicable expected role")
                        for field in ("generation_id", "role", "nodes", "index", "assurance"):
                            self.assertIn(field, state[role], "applicable expected role field")
                        self.assertTrue(
                            {"entries_hex", "symbolic_map_extent"} & state[role].keys(),
                            "applicable expected complete map or symbolic extent",
                        )
            self.assert_byte_literals(case["expect"])
        self.assertEqual(len(registry), 28, "source registry count")

    def test_utxo_expected_corpus_data_contract(self) -> None:
        self.assert_corpus_contract(self.data)
        rows = {row.path: row for row in m.load_protocol_artifact_rows()}
        row = rows["protocol/utxo_commitment_expected_v1.json"]
        self.assertIn("inert", row.coverage)
        self.assertIn("RUB-1681", row.coverage)

    def test_utxo_expected_corpus_rejects_one_dimension_format_changes(self) -> None:
        # These controls falsify separate data-contract assertions. No semantic
        # expected value, complete case inventory or client result is copied.
        controls = (
            ("source_ref", "unresolved normative_refs"),
            ("source_oid", "source binding"),
            ("absolute_path", "source path"),
            ("traversing_path", "source path"),
            ("duplicate_id", "duplicate case id"),
            ("input_ref", "input-reference unresolved"),
            ("expected_as_input", "input/expect separation"),
            ("result", "applicable expected result"),
            ("state", "applicable expected state"),
            ("first_observation", "applicable expected first_observation"),
            ("role", "applicable expected role field"),
            ("hex", "expected hex"),
            ("width", "expected width"),
            ("type", "expected hex type"),
            ("shared_input_hex", "expected hex"),
            ("input_hex", "expected hex"),
            ("input_width", "expected width"),
            ("state_digest_short", "expected digest width"),
            ("state_digest_long", "expected digest width"),
        )
        for control, diagnostic in controls:
            with self.subTest(control=control):
                data = copy.deepcopy(self.data)
                scalar = data["cases"][0]
                symbolic = next(c for c in data["cases"] if "CURRENT" in c["expect"].get("state", {}))
                if control == "source_ref":
                    del data["normative_ref_registry"][0]
                elif control == "source_oid":
                    data["normative_ref_registry"][0]["oid"] = "0" * 40
                elif control in {"absolute_path", "traversing_path"}:
                    data["normative_ref_registry"][0]["path"] = (
                        "/spec/source.md" if control == "absolute_path" else "spec/../source.md"
                    )
                elif control == "duplicate_id":
                    data["cases"][-1]["id"] = scalar["id"]
                elif control == "input_ref":
                    del data["input_fixtures"]["empty_map"]
                elif control == "expected_as_input":
                    scalar["input"]["map_ref"] = "/cases/0/expect/root_hex"
                elif control in {"result", "state", "first_observation"}:
                    del symbolic["expect"][control]
                elif control == "role":
                    del symbolic["expect"]["state"]["CURRENT"]["role"]
                elif control == "shared_input_hex":
                    data["input_fixtures"]["wire"]["Q_empty_hex"] = "GG0"
                elif control == "input_hex":
                    case = next(c for c in data["cases"] if c["id"] == "HEADER-08")
                    case["input"]["header_hex"] = "0"
                elif control == "input_width":
                    case = next(c for c in data["cases"] if c["id"] == "ORDER-09")
                    case["input"]["chunk_hex"] = case["input"]["chunk_hex"][:-2]
                elif control in {"state_digest_short", "state_digest_long"}:
                    case = next(c for c in data["cases"] if c["id"] == "READ-04-total")
                    state = case["expect"]["state"]["CURRENT"]
                    literal = state["binding_root_hex"]
                    state["binding_root_hex"] = (
                        literal[:-2] if control == "state_digest_short" else literal + literal[:2]
                    )
                else:
                    scalar["expect"]["root_hex"] = {
                        "hex": "GG", "width": "00" * 31, "type": 0,
                    }[control]
                with self.assertRaisesRegex(AssertionError, re.escape(diagnostic)):
                    self.assert_corpus_contract(data)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

import check_conformance_fixtures_drift as m
from gen_conformance_matrix import load_json_fail_closed, reject_duplicate_json_object_pairs

# RUB-1207 / C01-R2: the known-valid observation row every schema negative below
# mutates in exactly one dimension. It carries the complete required shape --
# typed input, typed expected output, per-image projection and summary rows --
# so a negative that passes proves the closure, not a missing constraint.
_IMAGES = ("CHAIN_IMAGE_V1", "STANDARD_MEMPOOL_IMAGE_V1", "RETAINED_DA_IMAGE_V1", "OWNER_IMAGE_V1")
V2_CONTROL_ROW = {
    "row_id": "C01-DIRECT-001", "kind": "observation", "notes": ["control row for the RUB-1207 schema negatives"],
    "release_requirements": {
        "go": [{"issue": "RUB-890", "surface": "one canonical index commit", "delivery_receipt_required": True}],
        "rust": [{"issue": "RUB-897", "surface": "mirror one canonical index commit", "delivery_receipt_required": True}],
    },
    "cases": [{
        "case_id": "MAIN",
        "input": [{"pointer": "/input/stimulus_block", "type": "alias", "value_or_alias": "B1",
                   "provenance": "normative_boundary", "production_setup_sink": "node.Miner.MineOne", "consumption_proof_owner": "RUB-923"}],
        "schedule_id": None,
        "expected": {
            "result": "ACCEPTED", "commit_truth": "NEW",
            "rpc_projection": {"class": "MINED_200_COMMITTED", "http": 200, "commit_state": "committed", "mined": "true",
                               "success_identity": "present", "error_class": None, "phase": "result_selecting_mined_candidate"},
            "canonical_counters": {"accepted_delta": "+1", "rejected_delta": "0"},
            "effects": {"publication_events": {"value": 1, "type": "u64", "required": True, "observer": "publication counter"}},
            "state_image": {image: {"relation": "new", "digest_alias": f"{image}@C01-DIRECT-001/MAIN:new",
                                    "direct_fields": {"tip_hash": "tip_hash@C01-DIRECT-001/MAIN:new"}} for image in _IMAGES},
            "canonical_applied_blocks": [{"block_id": "B1", "block_hash": "B1_HASH", "complete_da_ids": ["DA_ID_1"]}],
        },
        "obligation_ids": ["OBL-OWN-PUBCHAIN-018"], "sources": ["canonical_pipeline_v1.json row C01-DIRECT-001"],
    }],
}


def _populate_committed(root: Path) -> None:
    for rel in m.EXPECTED_FIXTURES:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(rel.as_posix().encode("utf-8"))


def _populate_candidate(
    root: Path,
    *,
    skip: tuple[Path, ...] = (),
    extra: tuple[Path, ...] = (),
    mutate: tuple[Path, ...] = (),
) -> None:
    for rel in m.EXPECTED_FIXTURES:
        if rel in skip:
            continue
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        body = rel.as_posix().encode("utf-8")
        if rel in mutate:
            body = body + b"-MUTATED"
        path.write_bytes(body)
    for rel in extra:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"extra")


class DiffSetTests(unittest.TestCase):
    def test_all_match(self):
        with tempfile.TemporaryDirectory() as td:
            committed = Path(td) / "committed"
            candidate = Path(td) / "candidate"
            committed.mkdir()
            candidate.mkdir()
            _populate_committed(committed)
            _populate_candidate(candidate)
            missing_committed, differing, matching, missing_candidate, extra_candidate = (
                m.diff_set(candidate, committed)
            )
        self.assertEqual(missing_committed, [])
        self.assertEqual(differing, [])
        self.assertEqual(len(matching), len(m.EXPECTED_FIXTURES))
        self.assertEqual(missing_candidate, [])
        self.assertEqual(extra_candidate, [])

    def test_byte_differing(self):
        target = m.EXPECTED_FIXTURES[0]
        with tempfile.TemporaryDirectory() as td:
            committed = Path(td) / "committed"
            candidate = Path(td) / "candidate"
            committed.mkdir()
            candidate.mkdir()
            _populate_committed(committed)
            _populate_candidate(candidate, mutate=(target,))
            _, differing, matching, missing_candidate, extra_candidate = m.diff_set(
                candidate, committed
            )
        self.assertEqual(differing, [target])
        self.assertEqual(len(matching), len(m.EXPECTED_FIXTURES) - 1)
        self.assertEqual(missing_candidate, [])
        self.assertEqual(extra_candidate, [])

    def test_missing_candidate(self):
        target = m.EXPECTED_FIXTURES[2]
        with tempfile.TemporaryDirectory() as td:
            committed = Path(td) / "committed"
            candidate = Path(td) / "candidate"
            committed.mkdir()
            candidate.mkdir()
            _populate_committed(committed)
            _populate_candidate(candidate, skip=(target,))
            _, differing, matching, missing_candidate, extra_candidate = m.diff_set(
                candidate, committed
            )
        self.assertEqual(differing, [])
        self.assertEqual(len(matching), len(m.EXPECTED_FIXTURES) - 1)
        self.assertEqual(missing_candidate, [target])
        self.assertEqual(extra_candidate, [])

    def test_extra_candidate(self):
        extra = Path("CV-NOT-EXPECTED.json")
        with tempfile.TemporaryDirectory() as td:
            committed = Path(td) / "committed"
            candidate = Path(td) / "candidate"
            committed.mkdir()
            candidate.mkdir()
            _populate_committed(committed)
            _populate_candidate(candidate, extra=(extra,))
            missing_committed, _, matching, missing_candidate, extra_candidate = m.diff_set(
                candidate, committed
            )
        self.assertEqual(missing_committed, [extra])
        self.assertEqual(len(matching), len(m.EXPECTED_FIXTURES))
        self.assertEqual(missing_candidate, [])
        self.assertEqual(extra_candidate, [extra])


class MainExitCodeTests(unittest.TestCase):
    def test_main_clean_returns_zero(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            def fake_run(_repo_root, out_dir):
                _populate_candidate(out_dir)

            captured = io.StringIO()
            with mock.patch.object(m, "run_generator", side_effect=fake_run):
                with mock.patch("sys.stdout", captured):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 0)
        self.assertIn(
            f"OK: conformance fixture drift check passed ({len(m.EXPECTED_FIXTURES)} generator-owned files match committed)",
            captured.getvalue(),
        )

    def test_main_missing_committed_dir_returns_two(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            captured = io.StringIO()
            with mock.patch("sys.stderr", captured):
                rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 2)
        self.assertIn("ERROR: committed fixtures dir not found", captured.getvalue())

    def test_main_subprocess_filenotfound_returns_two(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            def raise_fnf(*_args, **_kwargs):
                raise FileNotFoundError(2, "No such file or directory: 'go'")

            captured = io.StringIO()
            with mock.patch("subprocess.run", side_effect=raise_fnf):
                with mock.patch("sys.stderr", captured):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 2)
        self.assertIn("ERROR:", captured.getvalue())
        self.assertNotIn("Traceback", captured.getvalue())

    def test_main_candidate_inside_committed_root_refused(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            forbidden_root = committed / "candidate"
            forbidden_root.mkdir()

            def fake_mkdtemp(prefix=""):  # noqa: ARG001 - matches stdlib signature
                _ = prefix
                return str(forbidden_root)

            captured = io.StringIO()
            with mock.patch("tempfile.mkdtemp", side_effect=fake_mkdtemp):
                with mock.patch("sys.stderr", captured):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 2)
        self.assertIn(
            "candidate output", captured.getvalue()
        )

    def test_main_drift_detected_returns_one(self):
        target = m.EXPECTED_FIXTURES[1]
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            def fake_run(_repo_root, out_dir):
                _populate_candidate(out_dir, mutate=(target,))

            captured = io.StringIO()
            with mock.patch.object(m, "run_generator", side_effect=fake_run):
                with mock.patch("sys.stderr", captured):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 1)
        self.assertIn(f"~ {target}", captured.getvalue())

    def test_main_missing_expected_returns_one(self):
        target = m.EXPECTED_FIXTURES[3]
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            def fake_run(_repo_root, out_dir):
                _populate_candidate(out_dir, skip=(target,))

            captured = io.StringIO()
            with mock.patch.object(m, "run_generator", side_effect=fake_run):
                with mock.patch("sys.stderr", captured):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 1)
        self.assertIn(f"- {target}", captured.getvalue())


class CanonicalPipelineSchemaTests(unittest.TestCase):
    """RUB-922 / C01: the committed corpus validates and rejects duplicate ids."""

    REPO_ROOT = TOOLS_DIR.parent
    ARTIFACT = REPO_ROOT / "conformance/fixtures/protocol/canonical_pipeline_v1.json"
    SCHEMA = REPO_ROOT / "conformance/schemas/cv-canonical-pipeline-v1.json"

    def _load(self):
        import jsonschema  # fail closed: the schema gate requires the library

        # A duplicate JSON key would silently drop the expectation it repeats.
        schema = json.loads(self.SCHEMA.read_text(encoding="utf-8", errors="strict"), object_pairs_hook=reject_duplicate_json_object_pairs)
        data = json.loads(self.ARTIFACT.read_text(encoding="utf-8", errors="strict"), object_pairs_hook=reject_duplicate_json_object_pairs)
        jsonschema.Draft202012Validator.check_schema(schema)
        return jsonschema.Draft202012Validator(schema), data

    def test_every_row_validates_against_the_versioned_schema(self):
        validator, data = self._load()
        errors = [
            f"{'.'.join(str(p) for p in e.absolute_path)}: {e.message}"
            for e in sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        ]
        self.assertEqual(errors, [])
        self.assertTrue(data["rows"])

    def test_committed_corpus_has_no_duplicate_row_ids(self):
        _, data = self._load()
        ids = [row["id"] for row in data["rows"]]
        self.assertEqual(len(ids), len(set(ids)), "committed corpus has duplicate row ids")

    def test_result_pattern_rejects_malformed_taxonomy_strings(self):
        validator, data = self._load()
        row = next(r for r in data["rows"] if r["kind"] == "observation")
        self.assertFalse(any(validator.is_valid({**data, "rows": [{**row, "result": s}]}) for s in ("ACCEPTED(extra)", "KNOWN_BLOCK_NOOP(OTHER)", "TERMINAL_PERSISTENCE", "LOCAL_RESOURCE_UNAVAILABLE(bogus)", "CONSENSUS_INVALID()", "bogus", "ACCEPTED\n")))

    def test_row_kind_exclusions_and_receipt_size_are_closed(self):
        validator, data = self._load()
        rows = {r["kind"]: r for r in data["rows"]}
        self.assertFalse(any(validator.is_valid({**data, "rows": [{**rows[k], "forbidden_observation": "x"}]}) for k in ("authority", "observation")))
        self.assertTrue(validator.is_valid({**data, "rows": [rows["forbidden"]]}))
        self.assertFalse(validator.is_valid({**data, "authority": {**data["authority"], "status": ""}}))
        self.assertFalse(any(validator.is_valid({**data, "coverage_receipt": r}) for r in ({**data["coverage_receipt"], "taxonomy:EXTRA": "C01-DIRECT-001"}, dict(list(data["coverage_receipt"].items())[1:]))))

    def test_machine_tokens_reject_trailing_newline(self):
        validator, data = self._load()
        rows = data["rows"]
        po = next(r for r in rows if r.get("pending_owner"))
        cc = next(r for r in rows if r.get("canonical_counters"))
        self.assertFalse(any(validator.is_valid({**data, "rows": [m]}) for m in ({**rows[0], "id": rows[0]["id"] + "\n"}, {**po, "pending_owner": po["pending_owner"] + "\n"}, {**cc, "canonical_counters": {**cc["canonical_counters"], "accepted_delta": cc["canonical_counters"]["accepted_delta"] + "\n"}})))
        k, v = next(iter(data["coverage_receipt"].items()))
        self.assertTrue(validator.is_valid({**data, "coverage_receipt": {**data["coverage_receipt"], k: v}}))
        self.assertFalse(any(validator.is_valid({**data, "coverage_receipt": r}) for r in ({**data["coverage_receipt"], k + "\n": v}, {**data["coverage_receipt"], k: v + "\n"})))
        self.assertFalse(any(validator.is_valid({**data, "result_taxonomy": t}) for t in (["BOGUS"] + data["result_taxonomy"][1:], data["result_taxonomy"] + ["EXTRA"])))

class CanonicalPipelineV2SchemaTests(unittest.TestCase):
    """RUB-1207 / C01-R2: the dormant pair strict-loads, validates, and fails closed."""

    REPO_ROOT = TOOLS_DIR.parent
    ARTIFACT = REPO_ROOT / "conformance/fixtures/protocol/canonical_pipeline_v2.json"
    SCHEMA = REPO_ROOT / "conformance/schemas/cv-canonical-pipeline-v2.json"

    def _load(self):
        import jsonschema  # fail closed: the schema gate requires the library

        # load_json_fail_closed is the repo's one strict loader: UTF-8 strict,
        # duplicate-key reject, NaN/Infinity reject, single JSON document.
        schema = load_json_fail_closed(self.SCHEMA)
        data = load_json_fail_closed(self.ARTIFACT)
        jsonschema.Draft202012Validator.check_schema(schema)
        return jsonschema.Draft202012Validator(schema), data

    def test_committed_pair_validates_and_is_a_dormant_building_revision(self):
        validator, data = self._load()
        errors = [
            f"{'.'.join(str(p) for p in e.absolute_path)}: {e.message}"
            for e in sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        ]
        self.assertEqual(errors, [])
        self.assertEqual(data["rows"], [])
        self.assertEqual(data["_meta"]["closure_epoch"]["status"], "building")
        self.assertNotIn("pending_owner", self.ARTIFACT.read_text(encoding="utf-8", errors="strict"))

    def test_inherited_identities_match_the_byte_frozen_v1_parent(self):
        _, data = self._load()
        v1 = load_json_fail_closed(
            self.REPO_ROOT / "conformance/fixtures/protocol/canonical_pipeline_v1.json"
        )
        registry = data["row_registry"]
        self.assertEqual(len(v1["rows"]), 62)
        self.assertEqual(
            {r["id"]: r["kind"] for r in v1["rows"]},
            {rid: kind for rid, kind in registry.items() if rid in {r["id"] for r in v1["rows"]}},
        )
        # The 17 remaining identities are the closure-authorized R2 rows.
        self.assertEqual(len(registry) - len(v1["rows"]), 17)

    def test_control_row_validates(self):
        validator, data = self._load()
        errors = [e.message for e in validator.iter_errors({**data, "rows": [V2_CONTROL_ROW]})]
        self.assertEqual(errors, [])

    def _row_rejections(self, mutate) -> set:
        """Return {(json pointer, failing keyword)} for a one-dimension mutation."""
        validator, data = self._load()
        row = json.loads(json.dumps(V2_CONTROL_ROW))
        mutate(row)
        return {
            ("/".join(str(p) for p in e.absolute_path), e.validator)
            for e in validator.iter_errors({**data, "rows": [row]})
        }

    def test_one_dimension_row_mutations_are_rejected_for_the_exact_reason(self):
        def set_expected(key, value):
            return lambda r: r["cases"][0]["expected"].__setitem__(key, value)

        def set_effect(row, key, value, tag):
            row["cases"][0]["expected"]["effects"][key] = {"value": value, "type": tag, "required": True, "observer": "observer"}

        def set_rpc(key, value):
            return lambda r: r["cases"][0]["expected"]["rpc_projection"].__setitem__(key, value)

        expected = "rows/0/cases/0/expected"
        for name, (mutate, reason) in {
            "row id off grammar": (lambda r: r.__setitem__("row_id", "X01-DIRECT-001"), ("rows/0/row_id", "pattern")),
            "kind carries foreign payload": (lambda r: r.__setitem__("forbidden_observation", "x"), ("rows/0", "not")),
            "kind change": (lambda r: r.__setitem__("kind", "authority"), ("rows/0", "not")),
            "unknown compared field": (set_expected("detail", {"note": "x"}), (expected, "additionalProperties")),
            "missing compared field": (lambda r: r["cases"][0]["expected"].pop("commit_truth"), (expected, "required")),
            "commit truth off domain": (set_expected("commit_truth", "MAYBE"), (f"{expected}/commit_truth", "enum")),
            "result off taxonomy": (set_expected("result", "ACCEPTED(extra)"), (f"{expected}/result", "oneOf")),
            "rpc class off domain": (set_rpc("class", "MINED_201_COMMITTED"), (f"{expected}/rpc_projection/class", "enum")),
            "rpc http off domain": (set_rpc("http", 418), (f"{expected}/rpc_projection/http", "enum")),
            "rpc mined off domain": (set_rpc("mined", "yes"), (f"{expected}/rpc_projection/mined", "enum")),
            "surplus pipeline_reached": (set_expected("pipeline_reached", False), (expected, "not")),
            "missing pipeline_reached": (set_expected("result", None), (expected, "required")),
            "case id whitespace": (lambda r: r["cases"][0].__setitem__("case_id", "MAIN CASE"), ("rows/0/cases/0/case_id", "pattern")),
            "digest alias newline": (
                lambda r: r["cases"][0]["expected"]["state_image"]["CHAIN_IMAGE_V1"].__setitem__("digest_alias", "CHAIN\n"),
                (f"{expected}/state_image/CHAIN_IMAGE_V1/digest_alias", "not"),
            ),
            "notes carry a machine value": (lambda r: r.__setitem__("notes", [7]), ("rows/0/notes/0", "type")),
            "input carries an expected value": (
                lambda r: r["cases"][0]["input"][0].__setitem__("result", "ACCEPTED"),
                ("rows/0/cases/0/input/0", "additionalProperties"),
            ),
            "wire disposition off domain": (set_expected("wire_disposition", "FRAME_BOGUS"), (f"{expected}/wire_disposition", "enum")),
            "u64 input literal mismatch": (
                lambda r: r["cases"][0]["input"][0].update({"type": "u64", "value_or_alias": "abc"}),
                ("rows/0/cases/0/input/0/value_or_alias", "oneOf"),
            ),
            "bool input literal mismatch": (
                lambda r: r["cases"][0]["input"][0].update({"type": "bool", "value_or_alias": "yes"}),
                ("rows/0/cases/0/input/0/value_or_alias", "oneOf"),
            ),
            "inline object stimulus": (
                lambda r: r["cases"][0]["input"][0].update({"type": "object", "value_or_alias": {"height": 1}}),
                ("rows/0/cases/0/input/0/value_or_alias", "type"),
            ),
            "rpc class contradicts its fields": (set_rpc("http", 503), (f"{expected}/rpc_projection/http", "const")),
            "wire disposition under NEW": (
                lambda r: r["cases"][0]["expected"].update({"result": None, "pipeline_reached": False, "wire_disposition": "CHECKSUM_REJECT"}),
                (f"{expected}/commit_truth", "const"),
            ),
            "withheld image under NEW": (
                lambda r: r["cases"][0]["expected"]["state_image"]["CHAIN_IMAGE_V1"].__setitem__("relation", "withheld"),
                (f"{expected}/state_image/CHAIN_IMAGE_V1/relation", "enum"),
            ),
            "authority carries a non-machine value": (
                lambda r: r.__setitem__("authority", {"class_order": [None]}),
                ("rows/0/authority/class_order", "oneOf"),
            ),
            "counters contradict the truth": (
                lambda r: r["cases"][0]["expected"]["canonical_counters"].__setitem__("rejected_delta", "+1"),
                (f"{expected}/commit_truth", "const"),
            ),
            "array effect with a prose leaf": (
                lambda r: set_effect(r, "relay_frames", [None, 1.5], "array"),
                (f"{expected}/effects/relay_frames/value/0", "oneOf"),
            ),
            "array effect with a scalar value": (
                lambda r: set_effect(r, "relay_frames", 1, "array"),
                (f"{expected}/effects/relay_frames/value", "type"),
            ),
            "hash effect value off grammar": (
                lambda r: set_effect(r, "gc_victim_hash", "H FULL 1", "hash"),
                (f"{expected}/effects/gc_victim_hash/value", "oneOf"),
            ),
            "release requirement without receipt flag": (
                lambda r: r["release_requirements"]["go"][0].pop("delivery_receipt_required"),
                ("rows/0/release_requirements/go/0", "required"),
            ),
        }.items():
            with self.subTest(mutation=name):
                self.assertIn(reason, self._row_rejections(mutate))

    def test_closure_epoch_and_parent_pins_are_const(self):
        validator, data = self._load()
        for pointer, value in (
            ("manifest_root_sha256", "0" * 64),
            # `complete` is the value RUB-1204 will set; this revision pins `building`.
            ("status", "complete"),
        ):
            with self.subTest(field=pointer):
                epoch = {**data["_meta"]["closure_epoch"], pointer: value}
                self.assertFalse(validator.is_valid({**data, "_meta": {**data["_meta"], "closure_epoch": epoch}}))
        self.assertFalse(
            validator.is_valid({**data, "_meta": {**data["_meta"], "parent_artifact_sha256": "0" * 64}})
        )

    def test_fixture_entries_are_typed_literals(self):
        # A catalog entry is a typed literal, never an alias to an alias, and a
        # structured one is grammar-closed.
        validator, data = self._load()
        self.assertTrue(validator.is_valid({**data, "fixtures": {"B1": {"type": "u64", "value": 7}}}))
        for broken in (
            {"B1": {"type": "u64", "value": "abc"}},
            {"B1": {"type": "alias", "value": "B2"}},
            {"B1": {"type": "object", "value": {"note": "a b"}}},
        ):
            self.assertFalse(validator.is_valid({**data, "fixtures": broken}), broken)

    def test_top_level_consts_equal_the_enums_that_use_them(self):
        _, data = self._load()
        schema = load_json_fail_closed(self.SCHEMA)
        defs, exp = schema["$defs"], schema["$defs"]["expected"]["properties"]
        for const, enum in (
            (data["rpc_projection_classes"], defs["rpcProjection"]["properties"]["class"]["enum"]),
            (data["commit_truth_values"], exp["commit_truth"]["enum"]),
            (data["wire_disposition_values"], exp["wire_disposition"]["enum"]),
            (data["recovery_outcome_values"], exp["recovery_outcome"]["enum"]),
        ):
            self.assertEqual(sorted(const), sorted(enum))

    def test_row_registry_is_pinned_as_an_exact_map(self):
        # The schema pins the map as a `const`, independently of the generator
        # constant: a removed identity, an unauthorized key, a kind change and a
        # same-cardinality substitution all fail on this side alone.
        validator, data = self._load()
        registry = data["row_registry"]
        substituted = dict(list(registry.items())[1:]) | {"C01-SUBSTITUTED-001": "observation"}
        self.assertEqual(len(substituted), len(registry))
        for broken in (
            dict(list(registry.items())[1:]),
            {**registry, "C01-NOT-AUTHORIZED-001": "observation"},
            {**registry, "C01-PATHS-001": "conjecture"},
            substituted,
        ):
            self.assertFalse(validator.is_valid({**data, "row_registry": broken}))

    def test_strict_loader_rejects_every_parser_boundary(self):
        raw = self.SCHEMA.read_text(encoding="utf-8", errors="strict")
        artifact_raw = self.ARTIFACT.read_text(encoding="utf-8", errors="strict")
        cases = {
            "schema duplicate key": (raw.replace('"type": "object",', '"type": "object", "type": "object",', 1).encode(), 'duplicate JSON key "type"'),
            "artifact duplicate key": (artifact_raw.replace('"artifact":', '"artifact": "x", "artifact":', 1).encode(), 'duplicate JSON key "artifact"'),
            "artifact NaN constant": (artifact_raw.replace('"schema_version": 2', '"schema_version": NaN', 1).encode(), "invalid JSON constant 'NaN'"),
            "artifact trailing document": ((artifact_raw + "{}").encode(), "invalid JSON artifact"),
            "artifact non-utf8": (artifact_raw.encode() + b"\xff", "invalid JSON artifact"),
        }
        with tempfile.TemporaryDirectory() as td:
            for name, (body, expected) in cases.items():
                with self.subTest(boundary=name):
                    path = Path(td) / "candidate.json"
                    path.write_bytes(body)
                    with self.assertRaisesRegex(RuntimeError, expected):
                        load_json_fail_closed(path)


if __name__ == "__main__":
    unittest.main()

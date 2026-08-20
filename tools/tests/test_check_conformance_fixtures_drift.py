#!/usr/bin/env python3
from __future__ import annotations

import io
import json
import os
import re
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
# Per-image direct-field key sets, exactly as image_manifest.images.<IMAGE>.direct_fields
# pins them; the schema arms require this key set and nothing else.
_IMAGE_DIRECT_FIELDS = {
    "CHAIN_IMAGE_V1": ["tip_hash", "height", "utxo_count"],
    "STANDARD_MEMPOOL_IMAGE_V1": ["current_mempool_min_fee_rate", "last_admission_seq", "used_bytes", "tx_count", "record_count"],
    "RETAINED_DA_IMAGE_V1": ["set_count", "orphan_bytes", "pinned_payload_bytes"],
    "OWNER_IMAGE_V1": ["claim_count", "stable_tip"],
}

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
                                    "direct_fields": {f: f"{f}@C01-DIRECT-001/MAIN:new" for f in fields}}
                            for image, fields in _IMAGE_DIRECT_FIELDS.items()},
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
    def setUp(self):
        # The fake repo's sentinel bytes are not the real v2 artifact, so these
        # tests opt out through the environment sentinel; no CLI flag can.
        patcher = mock.patch.dict(os.environ, {m.FAKE_REPO_ENV: "1"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_main_clean_returns_zero(self):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)

            def fake_run(_repo_root, out_dir):
                _populate_candidate(out_dir)

            captured, errors = io.StringIO(), io.StringIO()
            with mock.patch.object(m, "run_generator", side_effect=fake_run):
                with mock.patch("sys.stdout", captured), mock.patch("sys.stderr", errors):
                    rc = m.main(["--repo-root", str(repo_root)])
        self.assertEqual(rc, 0)
        self.assertIn(
            f"OK: conformance fixture drift check passed ({len(m.EXPECTED_FIXTURES)} generator-owned files match committed)",
            captured.getvalue(),
        )
        # Loud on stderr, and the rc above is unchanged: visibility, not a failure.
        self.assertIn("NOTICE: canonical_pipeline_v2 semantic gate SKIPPED (fake-repo sentinel)", errors.getvalue())

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


class V2SemanticGateExitCodeTests(unittest.TestCase):
    """A v2 semantic/receipt violation is DRIFT (exit 1), never an environment
    error, and a programming error raised outside the gate is never swallowed."""

    BROKEN_V2 = b'{"_meta": "not an object"}\n'

    def _run(self, *, skip=(), v2_body=None, authority=b"{}\n"):
        with tempfile.TemporaryDirectory() as td:
            repo_root = Path(td)
            committed = repo_root / m.COMMITTED_FIXTURES_REL
            committed.mkdir(parents=True)
            _populate_committed(committed)
            (repo_root / m.GO_MODULE_REL).mkdir(parents=True, exist_ok=True)
            authority_path = repo_root / m.V2_AUTHORITY_REL
            authority_path.parent.mkdir(parents=True, exist_ok=True)
            if authority is not None:
                authority_path.write_bytes(authority)
            if v2_body is not None:
                (committed / m.V2_REL).write_bytes(v2_body)

            def fake_run(_repo_root, out_dir):
                _populate_candidate(out_dir, skip=skip)
                if v2_body is not None and m.V2_REL not in skip:
                    (out_dir / m.V2_REL).write_bytes(v2_body)

            err = io.StringIO()
            with mock.patch.object(m, "run_generator", side_effect=fake_run):
                with mock.patch("sys.stderr", err), mock.patch("sys.stdout", io.StringIO()):
                    rc = m.main(["--repo-root", str(repo_root)])
        return rc, err.getvalue()

    def test_semantic_violation_is_drift(self):
        rc, err = self._run(v2_body=self.BROKEN_V2)
        self.assertEqual(rc, 1)
        self.assertIn("ERROR: canonical_pipeline_v2: _meta.closure_epoch is not an object", err)
        self.assertNotIn("Traceback", err)

    def test_duplicate_key_in_the_authority_source_is_drift(self):
        # json.loads and Go's encoding/json both keep the LAST of two duplicate
        # keys, so an edited authority could hide a dropped expectation from every
        # downstream check; the gate strict-loads it before the artifact.
        rc, err = self._run(v2_body=self.BROKEN_V2, authority=b'{"rows": [], "rows": []}\n')
        self.assertEqual(rc, 1)
        self.assertIn("duplicate", err)
        self.assertIn(m.V2_AUTHORITY_REL.name, err)
        self.assertNotIn("Traceback", err)
        # And the missing file is drift too, never a silent skip.
        rc, err = self._run(v2_body=self.BROKEN_V2, authority=None)
        self.assertEqual((rc, "Traceback" in err), (1, False), err)
        self.assertIn(m.V2_AUTHORITY_REL.name, err)

    def test_missing_generated_v2_reaches_the_regression_diagnostic(self):
        rc, err = self._run(skip=(m.V2_REL,))
        self.assertEqual(rc, 1)
        self.assertIn("regression in generator output set", err)
        self.assertIn(f"- {m.V2_REL}", err)

    def test_programming_errors_are_labelled_inside_the_gate_only(self):
        with mock.patch.object(m, "validate_canonical_pipeline_v2_semantics", side_effect=KeyError("rows")):
            rc, err = self._run(v2_body=self.BROKEN_V2)
        self.assertEqual(rc, 1)
        self.assertIn("ERROR: canonical_pipeline_v2 ", err)
        self.assertIn("KeyError('rows')", err)
        for exc in (IndexError("rows[0]"), AttributeError("pop"), ValueError("bad literal")):
            with mock.patch.object(m, "validate_canonical_pipeline_v2_semantics", side_effect=exc):
                rc, err = self._run(v2_body=self.BROKEN_V2)
            self.assertEqual((rc, repr(exc) in err, "Traceback" in err), (1, True, False), err)
        # Outside the gate the same exception type stays unhandled: the tool must
        # not turn a bug in its own machinery into a fixture verdict.
        with mock.patch.dict(os.environ, {m.FAKE_REPO_ENV: "1"}):
            with mock.patch.object(m, "diff_set", side_effect=KeyError("outside")):
                with self.assertRaises(KeyError):
                    self._run()


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
    """RUB-1208 / C01-R2: the migrated BUILDING pair strict-loads, validates, and fails closed."""

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

    def test_committed_pair_validates_and_is_a_building_revision(self):
        validator, data = self._load()
        errors = [
            f"{'.'.join(str(p) for p in e.absolute_path)}: {e.message}"
            for e in sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        ]
        self.assertEqual(errors, [])
        self.assertEqual(len(data["rows"]), 8)
        self.assertEqual(sum(len(row["cases"]) for row in data["rows"]), 24)
        self.assertEqual(data["_meta"]["closure_epoch"]["closure_manifest_version"], "rubin-c01-design-closure-v8")
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
            "zero width setup sink": (
                lambda r: r["cases"][0]["input"][0].__setitem__("production_setup_sink", "\ufeff"),
                ("rows/0/cases/0/input/0/production_setup_sink", "pattern"),
            ),
            "wire disposed image relation": (
                lambda r: r["cases"][0]["expected"].update(
                    {"result": None, "pipeline_reached": False, "wire_disposition": "CHECKSUM_REJECT", "commit_truth": "OLD",
                     "canonical_applied_blocks": None,
                     "rpc_projection": {**r["cases"][0]["expected"]["rpc_projection"], "class": "NOT_REACHED", "http": None,
                                        "commit_state": None, "mined": "not_applicable", "success_identity": "not_applicable",
                                        "phase": "not_reached"}}
                ),
                (f"{expected}/state_image/CHAIN_IMAGE_V1/relation", "const"),
            ),
            "whitespace-only setup sink": (
                lambda r: r["cases"][0]["input"][0].__setitem__("production_setup_sink", "   "),
                ("rows/0/cases/0/input/0/production_setup_sink", "pattern"),
            ),
            "accepted with old truth": (lambda r: r["cases"][0]["expected"].__setitem__("commit_truth", "OLD"), (f"{expected}/commit_truth", "const")),
            "unauthorized row id": (lambda r: r.__setitem__("row_id", "C01-UNAUTHORIZED-001"), ("rows/0/row_id", "enum")),
            "authority id as observation": (lambda r: r.__setitem__("row_id", "C01-PATHS-001"), ("rows/0/row_id", "enum")),
            "not reached commit state": (
                lambda r: r["cases"][0]["expected"]["rpc_projection"].update(
                    {"class": "NOT_REACHED", "http": None, "mined": "not_applicable", "success_identity": "not_applicable", "phase": "not_reached", "commit_state": "unknown"}
                ),
                (f"{expected}/rpc_projection/commit_state", "enum"),
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
            "authority carries a retired key": (
                lambda r: r.__setitem__("authority", {"pending_owner": "RUB_1195"}),
                ("rows/0/authority", "not"),
            ),
            "effect key is a retired name": (
                lambda r: r["cases"][0]["expected"]["effects"].__setitem__(
                    "detail", {"value": 1, "type": "u64", "required": True, "observer": "observer"}
                ),
                (f"{expected}/effects", "not"),
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
                (f"{expected}/effects/gc_victim_hash/value", "pattern"),
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

    def test_recursion_error_is_an_invalid_json_artifact(self):
        # CPython's C scanner is iterative, so no depth raises here; the pure-Python
        # fallback scanner does, and the translation must keep it fail-closed.
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "deep.json"
            path.write_text("[[1]]", encoding="utf-8")
            with mock.patch("json.loads", side_effect=RecursionError):
                with self.assertRaisesRegex(RuntimeError, "nesting too deep"):
                    load_json_fail_closed(path)

    def test_fixture_entries_are_typed_literals(self):
        # A catalog entry is a typed literal, never an alias to an alias, and a
        # structured one is grammar-closed.
        validator, data = self._load()
        self.assertTrue(validator.is_valid({**data, "fixtures": {"B1": {"type": "u64", "value": 7}}}))
        for broken in (
            {"B1": {"type": "u64", "value": "abc"}},
            {"B1": {"type": "alias", "value": "B2"}},
            {"B1": {"type": "object", "value": {"note": "a b"}}},
            {"B1": {"type": "object", "value": {"height": 18446744073709551616}}},
        ):
            self.assertFalse(validator.is_valid({**data, "fixtures": broken}), broken)

    def test_top_level_consts_equal_the_enums_that_use_them(self):
        _, data = self._load()
        schema = load_json_fail_closed(self.SCHEMA)
        # The RPC/wire/recovery arrays are pinned Go-vs-schema by the generator's
        # parity test and are the artifact's own source, so only commit_truth is left.
        exp = schema["$defs"]["expected"]["properties"]
        self.assertEqual(sorted(data["commit_truth_values"]), sorted(exp["commit_truth"]["enum"]))
        # Each per-kind row_id enum is exactly the registry slice of that kind.
        for arm in schema["$defs"]["row"]["allOf"]:
            kind = arm["if"]["properties"]["kind"]["const"]
            self.assertEqual(
                sorted(arm["then"]["properties"]["row_id"]["enum"]),
                sorted(rid for rid, k in data["row_registry"].items() if k == kind),
            )

    def test_result_truth_arms_partition_the_taxonomy(self):
        # Every taxonomy member, expanded to its argument forms, matches exactly one arm.
        _, data = self._load()
        # Select the result -> commit_truth arms by what they CONCLUDE. RUB-1208
        # added truth -> image-relation arms that also guard on a string result,
        # and those are a different relation, not a fifth taxonomy arm.
        arms = [(a["if"]["properties"]["result"], a["then"]["properties"]["commit_truth"]["const"])
                for a in load_json_fail_closed(self.SCHEMA)["$defs"]["expected"]["allOf"]
                if a["if"]["properties"].get("result", {}).get("type") == "string"
                and "commit_truth" in a["then"]["properties"]]
        self.assertEqual(len(arms), 4)
        for entry in data["result_taxonomy"]:
            head, _, args = entry.partition("(")
            for member in ([head] if not args else [f"{head}({a})" for a in args.rstrip(")").split("|")]):
                member = member.replace("exact_error", "X").replace("resource", "orphan_pool")
                self.assertEqual(len([t for c, t in arms if bool(re.fullmatch(c.get("pattern") or c["not"]["pattern"], member)) != ("not" in c)]), 1, member)

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


class CanonicalPipelineV2RUB1208Tests(unittest.TestCase):
    """RUB-1208: the schema and the drift checker reject each assigned mutation."""

    REPO_ROOT = TOOLS_DIR.parent
    ARTIFACT = REPO_ROOT / "conformance/fixtures/protocol/canonical_pipeline_v2.json"
    SCHEMA = REPO_ROOT / "conformance/schemas/cv-canonical-pipeline-v2.json"

    def setUp(self):
        import jsonschema

        self.data = load_json_fail_closed(self.ARTIFACT)
        schema = load_json_fail_closed(self.SCHEMA)
        jsonschema.Draft202012Validator.check_schema(schema)
        self.validator = jsonschema.Draft202012Validator(schema)
        self.assertTrue(self.validator.is_valid(self.data), "control artifact must validate")

    def _case(self, data, row_id, case_id):
        row = next(r for r in data["rows"] if r["row_id"] == row_id)
        return next(c for c in row["cases"] if c["case_id"] == case_id)

    def _first_resolved(self, data, tag):
        return next(k for k, v in data["resolved_values"].items() if v["type"] == tag)

    def _rejections(self, mutate) -> set:
        """{(json pointer, failing keyword)} after mutating a deep copy of the
        KNOWN-VALID control in one dimension. Asserting the POINTER, not bare
        invalidity, is what ties each negative to its own arm."""
        data = json.loads(json.dumps(self.data))
        mutate(data)
        return {
            ("/".join(str(p) for p in e.absolute_path), e.validator)
            for e in self.validator.iter_errors(data)
        }

    def _pointer(self, row_id, case_id, tail) -> str:
        row = next(i for i, r in enumerate(self.data["rows"]) if r["row_id"] == row_id)
        case = next(i for i, c in enumerate(self.data["rows"][row]["cases"]) if c["case_id"] == case_id)
        return f"rows/{row}/cases/{case}/{tail}"

    def test_schema_rejects_every_assigned_single_dimension_mutation(self):
        at = self._pointer
        u64_key = self._first_resolved(self.data, "u64")
        b32_key = self._first_resolved(self.data, "bytes32_hex")

        def swap_manifest_member(d):
            # Same cardinality, one authorized member replaced by an unauthorized
            # one of identical shape (mechanic 2, identity not count).
            d["image_manifest"]["images"]["CHAIN_IMAGE_V1"]["direct_fields"] = [
                "tip_hash", "height", "already_generated"
            ]

        def swap_summary_manifest_member(d):
            d["summary_manifest"]["assigned_mutations"][0]["id"] = "M99"

        mutations = {
            "image_manifest same-cardinality substitution": (swap_manifest_member, ("image_manifest", "const")),
            "summary_manifest same-cardinality substitution": (swap_summary_manifest_member, ("summary_manifest", "const")),
            "closure input_schema_design_hash": (lambda d: d["_meta"]["closure_epoch"].__setitem__("input_schema_design_hash", "00" * 32), ("_meta/closure_epoch/input_schema_design_hash", "const")),
            "closure expected_projection_design_hash": (lambda d: d["_meta"]["closure_epoch"].__setitem__("expected_projection_design_hash", "00" * 32), ("_meta/closure_epoch/expected_projection_design_hash", "const")),
            "closure image_manifest_hash": (lambda d: d["_meta"]["closure_epoch"].__setitem__("image_manifest_hash", "00" * 32), ("_meta/closure_epoch/image_manifest_hash", "const")),
            "closure summary_manifest_hash": (lambda d: d["_meta"]["closure_epoch"].__setitem__("summary_manifest_hash", "00" * 32), ("_meta/closure_epoch/summary_manifest_hash", "const")),
            "authority_source_sha256": (lambda d: d["_meta"].__setitem__("authority_source_sha256", "00" * 32), ("_meta/authority_source_sha256", "const")),
            "generated warning reworded": (lambda d: d["_meta"].__setitem__("warning", "machine-generated file"), ("_meta/warning", "const")),
            "generated warning trailing newline": (lambda d: d["_meta"].__setitem__("warning", d["_meta"]["warning"] + "\n"), ("_meta/warning", "const")),
            "resolvedEntry unknown tag": (lambda d: d["resolved_values"][self._first_resolved(d, "u64")].__setitem__("type", "bytes"), (f"resolved_values/{u64_key}/type", "enum")),
            "resolvedEntry extra property": (lambda d: d["resolved_values"][self._first_resolved(d, "u64")].__setitem__("note", "x"), (f"resolved_values/{u64_key}", "additionalProperties")),
            "resolvedEntry bytes32 short": (lambda d: d["resolved_values"][self._first_resolved(d, "bytes32_hex")].__setitem__("value", "ab"), (f"resolved_values/{b32_key}/value", "pattern")),
            "resolvedEntry bytes32 uppercase": (lambda d: d["resolved_values"][self._first_resolved(d, "bytes32_hex")].__setitem__("value", "AB" * 32), (f"resolved_values/{b32_key}/value", "pattern")),
            "resolvedEntry u64 as string": (lambda d: d["resolved_values"][self._first_resolved(d, "u64")].__setitem__("value", "12"), (f"resolved_values/{u64_key}/value", "type")),
            "resolvedEntry u64 negative": (lambda d: d["resolved_values"][self._first_resolved(d, "u64")].__setitem__("value", -1), (f"resolved_values/{u64_key}/value", "minimum")),
            "resolvedEntry u64 two to the 64": (lambda d: d["resolved_values"][self._first_resolved(d, "u64")].__setitem__("value", 2 ** 64), (f"resolved_values/{u64_key}/value", "maximum")),
            "resolved key whitespace only": (lambda d: d["resolved_values"].__setitem__(" ", {"type": "u64", "value": 1}), ("resolved_values", "not")),
            "resolved key trailing newline": (lambda d: d["resolved_values"].__setitem__(self._first_resolved(d, "u64") + "\n", {"type": "u64", "value": 1}), ("resolved_values", "not")),
            "resolved key missing argument": (lambda d: d["resolved_values"].__setitem__("tip_hash", {"type": "u64", "value": 1}), ("resolved_values", "pattern")),
            "resolved key invalid relation suffix": (lambda d: d["resolved_values"].__setitem__("tip_hash@C01-DIRECT-001/MAIN:bogus", {"type": "u64", "value": 1}), ("resolved_values", "pattern")),
            "direct_fields dropped key": (lambda d: self._case(d, "C01-DIRECT-001", "MAIN")["expected"]["state_image"]["STANDARD_MEMPOOL_IMAGE_V1"]["direct_fields"].pop("used_bytes"), (at("C01-DIRECT-001", "MAIN", "expected/state_image/STANDARD_MEMPOOL_IMAGE_V1/direct_fields"), "required")),
            "direct_fields extra key": (lambda d: self._case(d, "C01-DIRECT-001", "MAIN")["expected"]["state_image"]["CHAIN_IMAGE_V1"]["direct_fields"].__setitem__("bogus", "tip_hash@C01-DIRECT-001/MAIN:new"), (at("C01-DIRECT-001", "MAIN", "expected/state_image/CHAIN_IMAGE_V1/direct_fields"), "enum")),
            "relation contradicts NEW": (lambda d: self._case(d, "C01-DIRECT-001", "MAIN")["expected"]["state_image"]["CHAIN_IMAGE_V1"].__setitem__("relation", "old"), (at("C01-DIRECT-001", "MAIN", "expected/state_image/CHAIN_IMAGE_V1/relation"), "const")),
            "relation contradicts OLD": (lambda d: self._case(d, "C01-DACLEAN-001", "CORRUPT_FIRST")["expected"]["state_image"]["CHAIN_IMAGE_V1"].__setitem__("relation", "new"), (at("C01-DACLEAN-001", "CORRUPT_FIRST", "expected/state_image/CHAIN_IMAGE_V1/relation"), "const")),
            "relation contradicts NOT_APPLICABLE": (lambda d: self._case(d, "C01-SIDE-001", "MAIN")["expected"]["state_image"]["CHAIN_IMAGE_V1"].__setitem__("relation", "new"), (at("C01-SIDE-001", "MAIN", "expected/state_image/CHAIN_IMAGE_V1/relation"), "const")),
            "summary block_hash inline literal": (lambda d: self._case(d, "C01-DIRECT-001", "MAIN")["expected"]["canonical_applied_blocks"][0].__setitem__("block_hash", "ab" * 32), (at("C01-DIRECT-001", "MAIN", "expected/canonical_applied_blocks"), "oneOf")),
            "obligation id trailing dash": (lambda d: self._case(d, "C01-DIRECT-001", "MAIN")["obligation_ids"].__setitem__(0, "OBL-X-"), (at("C01-DIRECT-001", "MAIN", "obligation_ids/0"), "pattern")),
            "obligation id empty segment": (lambda d: self._case(d, "C01-DIRECT-001", "MAIN")["obligation_ids"].__setitem__(0, "OBL--X"), (at("C01-DIRECT-001", "MAIN", "obligation_ids/0"), "pattern")),
            "disconnect summary null instead of []": (lambda d: self._case(d, "C01-DISCONNECT-001", "MAIN")["expected"].__setitem__("canonical_applied_blocks", None), (at("C01-DISCONNECT-001", "MAIN", "expected/canonical_applied_blocks"), "type")),
            "non-NEW summary is an array": (lambda d: self._case(d, "C01-SIDE-001", "MAIN")["expected"].__setitem__("canonical_applied_blocks", []), (at("C01-SIDE-001", "MAIN", "expected/canonical_applied_blocks"), "type")),
            "hash effect value as an alias": (lambda d: self._case(d, "C01-REORG-001", "MAIN")["expected"]["effects"].__setitem__("gc_victim_hash", {"value": "NO_SUCH_ALIAS_XYZ", "type": "hash", "required": True, "observer": "probe"}), (at("C01-REORG-001", "MAIN", "expected/effects/gc_victim_hash/value"), "pattern")),
        }
        for name, (mutate, reason) in mutations.items():
            with self.subTest(name):
                self.assertIn(reason, self._rejections(mutate), f"schema accepted {name}")

    def test_relation_arms_keep_wire_and_recovery_rows_expressible(self):
        # The truth -> relation arms are guarded on a CLASSIFIED result on all
        # three sides. Without that guard a DD-001 wire-disposed OLD row (every
        # image `unchanged`, C01-SIDE-001/MAIN) and a DD-002 recovery
        # NOT_APPLICABLE row (`new`, C01-DIRECT-001/MAIN) become unsatisfiable,
        # so the positive control asserts the semantic gate too, not only the
        # schema: the generator and the drift gate must accept them as well.
        base = {
            "result": None, "pipeline_reached": False, "canonical_applied_blocks": None,
            "canonical_counters": {"accepted_delta": "0", "rejected_delta": "0"},
            "rpc_projection": {"class": "NOT_REACHED", "http": None, "commit_state": None,
                               "mined": "not_applicable", "success_identity": "not_applicable",
                               "error_class": None, "phase": "not_reached"},
        }
        # Dropping the summary un-names the fixtures only its rows named, and the
        # catalog gate is reverse reachability, not a whitelist, so they go too.
        for label, row_id, extra, truth, unnamed in (
            ("wire disposed", "C01-SIDE-001", {"wire_disposition": "CHECKSUM_REJECT"}, "OLD", ()),
            ("recovery", "C01-DIRECT-001", {"recovery_outcome": "identity_proven_route1"}, "NOT_APPLICABLE",
             ("R1208_DIRECT_001_MAIN_B1_HASH", "R1208_DIRECT_001_MAIN_DA_ID_1")),
        ):
            with self.subTest(label):
                data = json.loads(json.dumps(self.data))
                for alias in unnamed:
                    del data["fixtures"][alias]
                case = self._case(data, row_id, "MAIN")
                case["expected"].update(base)
                case["expected"].update(extra)
                case["expected"]["commit_truth"] = truth
                self.assertTrue(self.validator.is_valid(data), f"{label} row must stay expressible")
                with tempfile.TemporaryDirectory() as td:
                    path = Path(td) / "row.json"
                    path.write_text(json.dumps(data), encoding="utf-8")
                    m.validate_canonical_pipeline_v2_semantics(path)

    def test_shipped_semantic_negative_controls_all_redden(self):
        # The five-plus controls live in the production checker so the drift gate
        # runs them; run them here too so the cheap unittest gate covers them.
        m.assert_canonical_pipeline_v2_negative_controls(self.ARTIFACT)

    def test_semantic_gate_accepts_the_committed_artifact(self):
        m.validate_canonical_pipeline_v2_semantics(self.ARTIFACT)

    def test_obligation_receipts_reject_a_census_preserving_edit(self):
        # Killer for the forward receipt hash: both edits keep the unique (143)
        # and occurrence (259) counts exactly, so the hash is the only check left.
        for label, mutate in (
            ("renamed id", lambda d: self._case(d, "C01-DIRECT-001", "MAIN")["obligation_ids"].__setitem__(0, "OBL-NOT-A-CENSUS-ID-999")),
            ("moved id", self._move_one_obligation),
        ):
            with self.subTest(label):
                data = json.loads(json.dumps(self.data))
                mutate(data)
                unique = {o for r in data["rows"] for c in r["cases"] for o in c["obligation_ids"]}
                occurrences = sum(len(c["obligation_ids"]) for r in data["rows"] for c in r["cases"])
                self.assertEqual(occurrences, m.V2_RUB1208_OBLIGATION_OCCURRENCES)
                self.assertEqual(len(unique), m.V2_RUB1208_OBLIGATION_UNIQUE)
                with tempfile.TemporaryDirectory() as td:
                    path = Path(td) / "mutated.json"
                    path.write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaises(RuntimeError) as ctx:
                        m.validate_canonical_pipeline_v2_semantics(path)
                self.assertIn("obligation forward receipt hash mismatch", str(ctx.exception))

    def _move_one_obligation(self, data):
        source = self._case(data, "C01-DACLEAN-001", "CORRUPT_FIRST")
        target = self._case(data, "C01-DIRECT-001", "MAIN")
        movable = [o for o in source["obligation_ids"] if o not in target["obligation_ids"]]
        source["obligation_ids"].remove(movable[0])
        target["obligation_ids"].append(movable[0])

    def test_semantic_gate_does_not_depend_on_the_schema_file(self):
        # Regression: the gate used to run only `if V2_SCHEMA_REL.is_file()`, so
        # deleting or renaming an unrelated file switched it off silently.
        self.assertNotIn("V2_SCHEMA_REL", INSPECT_SOURCE)
        # And it is not switchable from the command line at all: the only opt-out
        # is the environment sentinel the fake-repo tests set.
        self.assertNotIn("skip-v2-semantics", INSPECT_SOURCE)
        self.assertIn('os.environ.get(FAKE_REPO_ENV) == "1"', INSPECT_SOURCE)

    def test_meta_is_read_fail_closed(self):
        for label, mutate in (
            ("closure_epoch is a list", lambda d: d["_meta"].__setitem__("closure_epoch", [])),
        ):
            with self.subTest(label):
                data = json.loads(json.dumps(self.data))
                mutate(data)
                with tempfile.TemporaryDirectory() as td:
                    path = Path(td) / "mutated.json"
                    path.write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaises(RuntimeError):
                        m.validate_canonical_pipeline_v2_semantics(path)

    def test_go_and_python_agree_on_the_row_case_census(self):
        # Every list this slice maintains on more than one side is pinned equal:
        # the census, the composed-key grammar and the direct-field type map.
        go_source = (self.REPO_ROOT / "clients/go/cmd/gen-conformance-fixtures/runtime.go").read_text(encoding="utf-8")
        block = go_source.split("var cp2R1208Rows = map[string]int{", 1)[1].split("}", 1)[0]
        go_counts = {k: int(v) for k, v in re.findall(r'"([^"]+)":\s*(\d+)', block)}
        self.assertEqual(go_counts, m.V2_RUB1208_CASE_COUNTS)
        schema = load_json_fail_closed(self.SCHEMA)
        self.assertEqual(m.V2_RESOLVED_KEY_RE.pattern, schema["$defs"]["resolvedKey"]["pattern"])
        types = go_source.split("var cp2DirectFieldTypes = map[string]string{", 1)[1].split("}", 1)[0]
        self.assertEqual(dict(re.findall(r'"([a-z_]+)":\s*"([a-z0-9_]+)"', types)), m.V2_DIRECT_FIELD_TYPES)


INSPECT_SOURCE = (TOOLS_DIR / "check_conformance_fixtures_drift.py").read_text(encoding="utf-8")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Check-only conformance fixture drift gate.

Generates the deterministic generator-owned fixture set into an isolated
temporary output directory via `clients/go/cmd/gen-conformance-fixtures
--output-dir <abs>` and compares each produced file byte-for-byte against
the corresponding file under `conformance/fixtures/`. Exits 0 when every
generated file matches its committed counterpart, exits 1 on any drift --
byte drift, a missing or unexpected generated file, and a
canonical_pipeline_v2 semantic/receipt violation alike -- and exits 2 on
usage / environment errors only. Never writes inside
`conformance/fixtures/**` and never invokes the generator without the
`--output-dir` flag, so committed fixtures are never mutated. Manual
fixture regeneration remains the authoritative path; this gate only
detects drift after the fact.
"""

from __future__ import annotations

import argparse
import copy
import filecmp
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from gen_conformance_matrix import load_json_fail_closed


COMMITTED_FIXTURES_REL = Path("conformance/fixtures")
# Set only by the isolated fake-repo unit tests; see main().
FAKE_REPO_ENV = "_RUBIN_DRIFT_FAKE_REPO"
GENERATOR_PACKAGE = "./cmd/gen-conformance-fixtures"
GO_MODULE_REL = Path("clients/go")
V2_REL = Path("protocol/canonical_pipeline_v2.json")
V2_AUTHORITY_REL = Path("clients/go/cmd/gen-conformance-fixtures/canonical_pipeline_v2_authority.json")
V2_RUB1208_CASE_COUNTS = {
    "C01-DACLEAN-001": 12,
    "C01-DIRECT-001": 1,
    "C01-DISCONNECT-001": 1,
    "C01-EQUALWORK-001": 1,
    "C01-GENESIS-001": 1,
    "C01-REORG-001": 1,
    "C01-SIDE-001": 1,
    "C01-SUMMARY-001": 6,
}
# Canonical SHA-256 of the 24-case obligation receipts: forward is
# {row/case -> sorted obligation_ids}, reverse is {obligation_id -> sorted row/case}.
# Both literals were recomputed from the bound closure snapshot
# rubin-c01-design-closure-v8 case_design.canonical.json (the 24 entries whose
# sha256 is _meta.closure_epoch.row_case_design_hash), NOT from the artifact they
# pin, so the pin is independent of its subject. The reverse receipt and the two
# counts below are pure functions of the forward map: they carry the error string
# a dropped id asserts, and the forward hash is the killer for all four
# (test_obligation_receipts_reject_a_census_preserving_edit renames one id and
# moves one between cases, leaving both counts untouched).
V2_RUB1208_OBLIGATION_FORWARD_SHA256 = "f0be2577e0e5ed13ab2bcf50163d5289f7a04fd48352dea29fa7b216f310d45b"
V2_RUB1208_OBLIGATION_REVERSE_SHA256 = "378f3789d24c2a43bc2c29e50e0efa96232b666ede32bc8e9b30dcdebf71c60b"
V2_RUB1208_OBLIGATION_UNIQUE = 143
V2_RUB1208_OBLIGATION_OCCURRENCES = 259

# Hardcoded expected generator-owned fixture set per
# rubin-protocol#1358 task body. Every entry MUST be emitted by the
# deterministic generator and MUST byte-match the committed fixture.
# Adding or removing an entry here is a deliberate scope change.
EXPECTED_FIXTURES: tuple[Path, ...] = (
    Path("CV-UTXO-BASIC.json"),
    Path("CV-MULTISIG.json"),
    Path("CV-VAULT.json"),
    Path("CV-HTLC.json"),
    Path("CV-SUBSIDY.json"),
    Path("devnet/devnet-vault-create-01.json"),
    Path("devnet/devnet-htlc-claim-01.json"),
    Path("devnet/devnet-multisig-spend-01.json"),
    # RUB-922 / C01 canonical publication observables corpus. Generator-owned
    # and byte-frozen: only the C01 owner issue (RUB-922, then its R2 successor RUB-1204) may change its expected rows.
    Path("protocol/canonical_pipeline_v1.json"),
    # RUB-1208 / C01-R2 BUILDING successor. Generator-owned; schema shape is
    # checked by tools/tests/test_check_conformance_fixtures_drift.py and the
    # semantic cross-image / summary relations are checked below for both the
    # generated candidate and committed artifact before byte equality is accepted.
    V2_REL,
)


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="check_conformance_fixtures_drift.py",
        description=(
            "Generate fixtures into an isolated temp dir and fail on byte "
            "drift vs committed fixtures. Never writes committed files."
        ),
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Path to the rubin-protocol repo root (default: cwd).",
    )
    parser.add_argument(
        "--keep-output-dir",
        action="store_true",
        help="Do not delete the candidate output directory on exit.",
    )
    return parser.parse_args(argv)


def run_generator(repo_root: Path, output_dir: Path) -> None:
    if not output_dir.is_absolute():
        raise RuntimeError(f"output_dir must be absolute: {output_dir}")
    cmd = [
        "go",
        "run",
        GENERATOR_PACKAGE,
        f"--output-dir={output_dir}",
    ]
    go_cwd = repo_root / GO_MODULE_REL
    if not go_cwd.is_dir():
        raise RuntimeError(f"missing Go module dir: {go_cwd}")
    completed = subprocess.run(
        cmd,
        cwd=str(go_cwd),
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise RuntimeError(
            f"generator exited with code {completed.returncode}"
        )


def relative_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            out.append(path.relative_to(root))
    return out


def diff_set(
    candidate_root: Path, committed_root: Path
) -> tuple[list[Path], list[Path], list[Path], list[Path], list[Path]]:
    missing_committed: list[Path] = []
    differing: list[Path] = []
    matching: list[Path] = []
    seen_in_candidate: set[Path] = set()
    for rel in relative_files(candidate_root):
        seen_in_candidate.add(rel)
        committed_path = committed_root / rel
        candidate_path = candidate_root / rel
        if not committed_path.is_file():
            missing_committed.append(rel)
            continue
        if filecmp.cmp(str(candidate_path), str(committed_path), shallow=False):
            matching.append(rel)
        else:
            differing.append(rel)
    expected_set = set(EXPECTED_FIXTURES)
    missing_candidate = sorted(expected_set - seen_in_candidate)
    extra_candidate = sorted(seen_in_candidate - expected_set)
    return missing_committed, differing, matching, missing_candidate, extra_candidate


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _case_alias_prefix(where: str) -> str:
    """The catalog namespace of one case: every fixture a migrated case names is
    keyed R1208_<ROW>_<CASE>_... . Mirrors Go cp2CaseFixture."""
    row_id, case_id = where.split("/")[:2]
    return "R1208_" + row_id.removeprefix("C01-").replace("-", "_") + "_" + case_id + "_"


def _fixture_value(fixtures: dict, alias: object, want: Optional[str], where: str):
    """Resolve one catalog alias: existence, declared tag (`want=None` accepts any
    tag, mirroring Go's bare `alias` input tag) and the naming case's namespace."""
    if not isinstance(alias, str):
        raise RuntimeError(f"{where}: fixture alias is not a string")
    entry = fixtures.get(alias)
    if not isinstance(entry, dict):
        raise RuntimeError(f"{where}: fixture alias {alias!r} is absent")
    if want is not None and entry.get("type") != want:
        raise RuntimeError(
            f"{where}: fixture alias {alias!r} type={entry.get('type')!r} want {want}"
        )
    if not alias.startswith(_case_alias_prefix(where)):
        raise RuntimeError(f"{where}: fixture alias {alias!r} is outside the case namespace")
    return entry.get("value")


# Type of every direct field. The frozen image manifest names the per-image
# field LIST but not the tags, so the names come from the manifest at run time
# and only the name -> type mapping lives here. Mirrors Go cp2DirectFieldTypes.
V2_DIRECT_FIELD_TYPES = {
    "claim_count": "u64",
    "current_mempool_min_fee_rate": "u64",
    "height": "u64",
    "last_admission_seq": "u64",
    "orphan_bytes": "u64",
    "pinned_payload_bytes": "u64",
    "record_count": "u64",
    "set_count": "u64",
    "stable_tip": "object",
    "tip_hash": "bytes32_hex",
    "tx_count": "u64",
    "used_bytes": "u64",
    "utxo_count": "u64",
}
V2_UPPER_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# Closed input vocabulary of the migrated corpus (the pointers a derivation
# consumes plus the declarative ones). The schema pins a pointer's GRAMMAR only,
# so without this set a typo is a well-formed pointer that reads as a silently
# ABSENT stimulus. Mirrors Go cp2StatedPointers; a new stimulus lands in both.
V2_STATED_POINTERS = frozenset({
    "/input/block_complete_da_ids_in_transaction_order", "/input/block_complete_da_set_count", "/input/block_included_set_identities", "/input/block_includes", "/input/candidate_a", "/input/candidate_b", "/input/candidate_hash_relation", "/input/candidate_work_relation",
    "/input/chain_id", "/input/connect_count", "/input/cross_block_da_id", "/input/datadir_state", "/input/delivery_entrypoint", "/input/detached_branch_only_output_spender", "/input/disconnect_command", "/input/final_chain_invalid_members", "/input/genesis_pack",
    "/input/owner_token_fault", "/input/prestate_canonical_chain", "/input/prestate_owner_claims", "/input/prestate_retained_da_sets", "/input/prestate_standard_min_fee_rate_raised_above_default", "/input/prestate_standard_records", "/input/prestored_side_branch",
    "/input/retained_record_fault", "/input/schedule_arms", "/input/selected_record_plan_order", "/input/stimulus_block", "/input/stimulus_block_parent_relation", "/input/stimulus_block_work_relation",
})
V2_RESOLVED_KEY_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*@C01(-[A-Z0-9]+)+-[0-9]{3}/[A-Z][A-Z0-9_]*:(new|old|unchanged|withheld)$"
)
V2_BYTES32_RE = re.compile(r"^[0-9a-f]{64}$")


def _relations_for_truth(expected: dict, truth: str, image: str) -> tuple:
    """Relations one image may carry under a commit truth. Mirrors Go
    cp2RelationForTruth and the $defs/expected arms, whose classified arms are
    guarded on a string result: a case whose result is not yet classified is a
    DD-001 wire disposition (the frame touched no image) or a DD-002 recovery
    (startup left every image or proved one new identity)."""
    if not isinstance(expected.get("result"), str):
        if "wire_disposition" in expected:
            return ("unchanged",)
        if "recovery_outcome" in expected:
            return ("unchanged", "new")
        return ()
    if truth == "UNKNOWN":
        return ("withheld",)
    if truth == "OLD":
        return ("old",)
    if truth == "NOT_APPLICABLE":
        return ("unchanged",)
    if truth == "NEW":
        if image in ("CHAIN_IMAGE_V1", "OWNER_IMAGE_V1"):
            return ("new",)
        return ("new", "unchanged")
    return ()


def _direct_field_names(manifest: object) -> dict:
    """Per-image direct-field list, read from the frozen image manifest."""
    if not isinstance(manifest, dict) or not isinstance(manifest.get("images"), dict):
        raise RuntimeError("canonical_pipeline_v2: image_manifest carries no images map")
    out = {}
    for image, entry in sorted(manifest["images"].items()):
        fields = entry.get("direct_fields") if isinstance(entry, dict) else None
        if not isinstance(fields, list) or not fields:
            raise RuntimeError(f"canonical_pipeline_v2: image manifest {image} names no direct_fields")
        for name in fields:
            if not isinstance(name, str):
                raise RuntimeError(f"canonical_pipeline_v2: image manifest {image} direct_fields carries a non-string")
            if name not in V2_DIRECT_FIELD_TYPES:
                raise RuntimeError(
                    f"canonical_pipeline_v2: image manifest {image} direct field {name!r} has no declared type"
                )
        out[image] = list(fields)
    return out


def _resolved_entry(values: dict, alias: object, want: str, where: str):
    """Resolve one composed alias in resolved_values, fail-closed on absence,
    key grammar and tag. Mirrors Go cp2ResolvedType plus cp2ValidateResolved."""
    if not isinstance(alias, str):
        raise RuntimeError(f"{where}: alias is not a string")
    if not V2_RESOLVED_KEY_RE.fullmatch(alias):
        raise RuntimeError(f"{where}: resolved alias {alias!r} is not the composed full form")
    entry = values.get(alias)
    if not isinstance(entry, dict):
        raise RuntimeError(f"{where}: resolved alias {alias!r} is absent")
    if entry.get("type") != want:
        raise RuntimeError(
            f"{where}: resolved alias {alias!r} type={entry.get('type')!r} want {want}"
        )
    return entry.get("value")


def _validate_resolved_values(resolved: dict) -> None:
    """Every entry is a typed literal of its declared tag, keyed by the composed
    full form. Mirrors Go cp2ValidateResolved except the `object` arm, whose closed-object grammar Go and the schema own."""
    for name in sorted(resolved):
        if not V2_RESOLVED_KEY_RE.fullmatch(name):
            raise RuntimeError(f"resolved_values key {name!r} is not the composed full form")
        entry = resolved[name]
        if not isinstance(entry, dict) or set(entry) != {"type", "value"}:
            raise RuntimeError(f"resolved_values[{name}] is not a closed typed literal")
        tag, value = entry["type"], entry["value"]
        if tag == "bytes32_hex":
            ok = isinstance(value, str) and bool(V2_BYTES32_RE.fullmatch(value))
        elif tag == "u64":
            ok = type(value) is int and 0 <= value <= 18446744073709551615
        elif tag == "object":
            ok = isinstance(value, dict) and bool(value)
        else:
            raise RuntimeError(f"resolved_values[{name}] type {tag!r} is outside the closed tag set")
        if not ok:
            raise RuntimeError(f"resolved_values[{name}] is not a valid {tag} literal")


_ABSENT = object()
_PRESTATE_POINTER = {
    "STANDARD_MEMPOOL_IMAGE_V1": "/input/prestate_standard_records",
    "RETAINED_DA_IMAGE_V1": "/input/prestate_retained_da_sets",
    "OWNER_IMAGE_V1": "/input/prestate_owner_claims",
}


def _input_value(inputs: object, pointer: str):
    """The value one stated stimulus carries, or _ABSENT when the case states no
    such pointer and therefore constrains nothing. Mirrors Go cp2InputValue."""
    if isinstance(inputs, list):
        for entry in inputs:
            if isinstance(entry, dict) and entry.get("pointer") == pointer:
                return entry.get("value_or_alias")
    return _ABSENT


def _validate_input_aliases(where: str, case: dict, fixtures: dict, named: set) -> None:
    """Every alias an input pointer or the schedule id names must exist, carry the
    tag the pointer declares and live in this case's own namespace: existence and
    tag alone would let one case drive its stimulus from another case's fixture.
    Mirrors Go cp2ValidateAliases/cp2ResolveAliases -- a `token` tag carries a
    machine token, never an alias, and a bare `alias` tag accepts any catalog tag --
    plus the closed pointer vocabulary (Go cp2ValidateR1208Expected) and the
    once-per-array alias rule (Go cp2InputOK). Every alias it resolves is recorded
    in `named` for the catalog reverse-reachability gate."""
    stated = list(case.get("input") or [])
    for entry in stated:
        if entry.get("pointer") not in V2_STATED_POINTERS:
            raise RuntimeError(f"{where}: input pointer {entry.get('pointer')!r} is outside the closed stated vocabulary")
    if isinstance(case.get("schedule_id"), str):
        stated.append({"pointer": "/schedule_id", "type": "object", "value_or_alias": case["schedule_id"]})
    for entry in stated:
        tag = entry.get("type")
        if not isinstance(tag, str) or tag in ("token", "array<token>"):
            continue
        want = tag.removeprefix("array<").removesuffix(">")
        value = entry.get("value_or_alias")
        aliases = [item for item in (value if isinstance(value, list) else [value])
                   if isinstance(item, str) and V2_UPPER_TOKEN_RE.fullmatch(item)]
        # A stated array names each alias ONCE: it states occurrences, and every
        # derivation over it set-normalizes, so a repeat would silently stand in
        # for a dropped occurrence instead of being the second occurrence it spells.
        if len(set(aliases)) != len(aliases):
            raise RuntimeError(f"{where}: input {entry.get('pointer')} names an alias more than once")
        for item in aliases:
            _fixture_value(
                fixtures, item, None if want == "alias" else want,
                f"{where}{entry.get('pointer')}",
            )
            named.add(item)


def _derived_counts(where: str, image: str, relation: str, inputs: object, fixtures: dict) -> tuple:
    """Counters an image that did not move republishes: an `unchanged` or `old`
    image is exactly the prestate the case states, so M15 (stale standard), M16
    (stale retained-DA) and M17 (stale owner claim) redden instead of being
    authored freely. Mirrors Go cp2DerivedCounts; the `new` transition rule is
    deferred to RUB-1204 and derived nowhere here.

    Returns (exact equalities, lower bounds). `last_admission_seq` is the
    monotone high-water M1 preserves (manifest mutation M15 "rewound"), which
    the reference only requires at or above the greatest resident
    admission_seq, so an evicted higher seq legally leaves it ABOVE the stated
    maximum. `orphan_bytes` (excluded wireBytes accounting) and
    `current_mempool_min_fee_rate` are functions of no stated record."""
    pointer = _PRESTATE_POINTER.get(image)
    if pointer is None or relation not in ("unchanged", "old"):
        return {}, {}
    value = _input_value(inputs, pointer)
    if value is _ABSENT:
        return {}, {}
    if not isinstance(value, list):
        raise RuntimeError(f"{where}{pointer}: not an array")
    records = [_fixture_value(fixtures, alias, "object", f"{where}{pointer}") for alias in value]
    if image == "RETAINED_DA_IMAGE_V1":
        # RUBIN_COMPACT_BLOCKS 5.1 counts DA payload bytes only for a retained COMPLETE_SET; every other state contributes zero (da_relay_state.go pinnedPayloadAccountingBytes).
        pinned = 0
        for record in records:
            if not isinstance(record, dict) or record.get("state") != "COMPLETE_SET":
                continue
            payload = record.get("payload_bytes")
            if type(payload) is not int or not 0 <= payload < 2**64 or pinned > 2**64 - 1 - payload:
                raise RuntimeError(f"{where}{pointer}: carries a COMPLETE_SET without a u64 payload_bytes or overflows the pinned-payload total")
            pinned += payload
        return {"set_count": len(records), "pinned_payload_bytes": pinned}, {}
    if image == "OWNER_IMAGE_V1":
        return {"claim_count": len(records)}, {}
    used = last = 0
    for record in records:
        size = record.get("size") if isinstance(record, dict) else None
        seq = record.get("admission_seq") if isinstance(record, dict) else None
        if type(size) is not int or not 0 <= size < 2**64 or used > 2**64 - 1 - size \
                or type(seq) is not int or not 0 <= seq < 2**64:
            raise RuntimeError(f"{where}{pointer}: carries a record without a u64 size or admission_seq or overflows the used-bytes total")
        used += size
        last = max(last, seq)
    return ({"record_count": len(records), "tx_count": len(records), "used_bytes": used},
            {"last_admission_seq": last})


def _set_identity_da_id(raw: object, where: str) -> str:
    if not isinstance(raw, dict) or not isinstance(raw.get("da_id"), str):
        raise RuntimeError(f"{where}: included-set identity carries no da_id")
    return raw["da_id"]


def _flat_stated_da_ids(where: str, inputs: object, fixtures: dict) -> tuple:
    """The two other spellings of the same occurrence fact:
    /input/block_includes states one block's complete DA-set identities inline
    and /input/block_complete_da_ids_in_transaction_order states that block's
    da_ids by catalog alias. Neither carries a block binding, exactly like a flat
    included-set identity. Two stated spellings must name the SAME id set: a union
    would let either drop one. Mirrors Go cp2FlatStatedDAIDs."""
    out, stated = [], False
    includes = _input_value(inputs, "/input/block_includes")
    if includes is not _ABSENT:
        stated = True
        where_in = f"{where}/input/block_includes"
        block = _fixture_value(fixtures, includes, "object", where_in)
        identities = block.get("complete_da_set_identities") if isinstance(block, dict) else None
        if not isinstance(identities, list):
            raise RuntimeError(f"{where_in}: names no complete_da_set_identities")
        out.extend(_set_identity_da_id(raw, where_in) for raw in identities)
        if len(set(out)) != len(out):
            raise RuntimeError(f"{where_in}: states an identity more than once")
    ordered = _input_value(inputs, "/input/block_complete_da_ids_in_transaction_order")
    if ordered is _ABSENT:
        return out, stated
    where_in = f"{where}/input/block_complete_da_ids_in_transaction_order"
    if not isinstance(ordered, list):
        raise RuntimeError(f"{where_in}: not an array")
    ids = [_fixture_value(fixtures, alias, "bytes32_hex", where_in) for alias in ordered]
    if stated and sorted(set(out)) != sorted(set(ids)):
        raise RuntimeError(f"{where}: stated occurrence spellings disagree on the complete DA-set identities")
    return out + ids, True


def _included_set_da_ids(where: str, inputs: object, fixtures: dict, summary: list):
    """Expected per-block da_id lists derived from the case's own
    /input/block_included_set_identities. Mirrors Go cp2IncludedSetDAIDs:
    grouped {block_id, identities} entries bind by block-alias suffix, flat
    entries carry no block binding and need a single-row summary, and the two
    shapes are never mixed. Returns None when the case states no such stimulus."""
    if not isinstance(inputs, list):
        return None
    aliases, stated = [], False
    for entry in inputs:
        if not isinstance(entry, dict):
            raise RuntimeError(f"{where}: input entry is not an object")
        if entry.get("pointer") != "/input/block_included_set_identities":
            continue
        stated = True
        values = entry.get("value_or_alias")
        if not isinstance(values, list):
            raise RuntimeError(f"{where}/input/block_included_set_identities: not an array")
        aliases.extend(values)
    extra, extra_stated = _flat_stated_da_ids(where, inputs, fixtures)
    if not stated and not extra_stated:
        return None

    grouped, flat, shapes = {}, [], set()
    if extra_stated:
        shapes.add("flat")
    for alias in aliases:
        value = _fixture_value(
            fixtures, alias, "object", f"{where}/input/block_included_set_identities"
        )
        if not isinstance(value, dict):
            raise RuntimeError(f"{where}: included-set fixture {alias!r} is not an object")
        has_block = isinstance(value.get("block_id"), str)
        has_identities = isinstance(value.get("identities"), list)
        if has_block and has_identities:
            shapes.add("grouped")
            ids = grouped.setdefault(value["block_id"], [])
            ids.extend(_set_identity_da_id(x, f"{where}/{alias}") for x in value["identities"])
            if len(set(ids)) != len(ids):
                raise RuntimeError(f"{where}: included-set group {value['block_id']!r} states an identity more than once")
        elif not has_block and not has_identities:
            shapes.add("flat")
            flat.append(_set_identity_da_id(value, f"{where}/{alias}"))
        else:
            raise RuntimeError(
                f"{where}: included-set fixture {alias!r} is neither a flat identity "
                f"nor a {{block_id, identities}} group"
            )
    if len(shapes) > 1:
        raise RuntimeError(f"{where}: mixes flat and grouped included-set identities")
    # Set-normalized on purpose, unlike one spelling's own identity list: two
    # spellings state the SAME fact, and a flat entry is one identity, not one
    # occurrence (the DACLEAN CORRUPT_* prestates state one da_id under two
    # distinct identities). Mirrors Go cp2IncludedSetDAIDs.
    if stated and extra_stated and sorted(set(flat)) != sorted(set(extra)):
        raise RuntimeError(f"{where}: stated occurrence spellings disagree on the complete DA-set identities")
    flat.extend(extra)

    def block_alias(index: int) -> str:
        row = summary[index]
        if not isinstance(row, dict) or not isinstance(row.get("block_id"), str):
            raise RuntimeError(f"{where}/canonical_applied_blocks/{index}: block_id is not an alias")
        return row["block_id"]

    out = {}
    if "grouped" in shapes:
        for suffix in sorted(grouped):
            matches = [
                block_alias(i) for i in range(len(summary))
                if block_alias(i).endswith("_" + suffix)
            ]
            if len(matches) != 1:
                raise RuntimeError(
                    f"{where}: included-set block {suffix!r} matches {len(matches)} summary rows"
                )
            # Two keys may suffix-match the SAME row (`..._B1P` ends in `_B1P` AND
            # `_IDENTITY_B1P`): the last sorted key would silently overwrite the
            # other group's constraint. Mirrors Go cp2IncludedSetDAIDs.
            if matches[0] in out:
                raise RuntimeError(f"{where}: summary row {matches[0]!r} is bound by more than one included-set group")
            out[matches[0]] = sorted(set(grouped[suffix]))
        # Every key is one distinct summary row, so equal sizes is exactly "every
        # row bound": a row no group binds is a row whose list nothing checks.
        if len(out) != len(summary):
            raise RuntimeError(
                f"{where}: binds {len(out)} of {len(summary)} summary rows to a "
                f"stated included-set group"
            )
        return out
    want = sorted(set(flat))
    if not want:
        return {block_alias(i): [] for i in range(len(summary))}
    if len(summary) != 1:
        raise RuntimeError(
            f"{where}: carries {len(want)} flat included-set identities but "
            f"{len(summary)} summary rows, so no row binding is derivable"
        )
    return {block_alias(0): want}


def _summary_rows_effect(where: str, expected: dict, rows: int) -> None:
    """The stated row-count effect against the rows the case publishes. Secondary
    consistency only: the typed rows are the primary evidence, so this runs LAST
    on both paths and never preempts them. Mirrors Go cp2SummaryRowsEffect."""
    effects = expected.get("effects")
    effect = effects.get("summary_rows") if isinstance(effects, dict) else None
    if isinstance(effect, dict) and (
        type(effect.get("value")) is not int or effect["value"] != rows
    ):
        raise RuntimeError(
            f"{where}/effects.summary_rows: {effect.get('value')!r} differs from the "
            f"{rows} published rows"
        )


def _prestate_chain_block(where: str, prestate: object, fixtures: dict, from_end: int) -> dict:
    """The stated prestate chain entry `from_end` places from its end: 1 is the
    stated prestate tip, 2 the entry below it. Mirrors Go cp2PrestateChainBlock."""
    chain = prestate if isinstance(prestate, list) else []
    if len(chain) < from_end:
        raise RuntimeError(f"{where}/CHAIN: states a {len(chain)}-block prestate chain, so entry -{from_end} is not stated")
    block = _fixture_value(fixtures, chain[-from_end], "object", f"{where}/CHAIN/prestate chain")
    if not isinstance(block, dict):
        raise RuntimeError(f"{where}/CHAIN: prestate chain fixture is not an object")
    return block


def _stated_branch_blocks(where: str, inputs: object, fixtures: dict) -> list:
    """The ordered blocks a case states will become newly canonical: the
    pre-stored side branch in canonical order, the block a single-block stimulus
    names (a genesis pack or a relayed stimulus block) and the candidate an
    equal-work tie-break names. A case stating none of them constrains nothing.
    Mirrors Go cp2StatedBranchBlocks."""
    branch = _input_value(inputs, "/input/prestored_side_branch")
    out = list(branch) if isinstance(branch, list) else []
    for pointer in ("/input/genesis_pack", "/input/stimulus_block"):
        value = _input_value(inputs, pointer)
        if value is not _ABSENT:
            out.append(value)
    first = _input_value(inputs, "/input/candidate_a")
    second = _input_value(inputs, "/input/candidate_b")
    if first is _ABSENT and second is _ABSENT:
        return out
    # Equal-work tie-break: the candidate with the lower raw-byte block hash is
    # the sole newly canonical block. The stated relation is enforced against the
    # candidates' OWN declared hashes (both bytes32 lowercase hex, so string
    # order is raw-byte order), so a stated-but-false relation is a rejection
    # rather than a license for whichever winner the case then publishes. A
    # half-stated pair resolves the absent alias and is rejected there.
    hashes, works = [], []
    for alias in (first, second):
        block = _fixture_value(fixtures, alias, "object", f"{where}/equal-work candidate")
        hashes.append(block.get("block_hash") if isinstance(block, dict) else None)
        works.append(block.get("cumulative_chainwork") if isinstance(block, dict) else None)
    relation = _input_value(inputs, "/input/candidate_hash_relation")
    if (
        relation != "hash_ba_lt_hash_bb_raw_bytes"
        or not all(isinstance(h, str) and V2_BYTES32_RE.match(h) for h in hashes)
        or hashes[0] >= hashes[1]
    ):
        raise RuntimeError(
            f"{where}: states candidate_hash_relation {relation!r}, which the candidates' "
            f"own hashes {hashes[0]!r} / {hashes[1]!r} do not establish"
        )
    # The tie-break is reached only on EQUAL work (node/sync_reorg.go:224
    # shouldSwitchToBranch): unequal candidates are decided by work alone, so a
    # lower hash would not make the stated winner canonical.
    # Type AND range, like Go cp2UintOf: `True == 1` and a negative int would pass
    # a bare equality that the generator rejects.
    work_relation = _input_value(inputs, "/input/candidate_work_relation")
    if (work_relation != "exactly_equal_cumulative_chainwork"
            or not all(type(w) is int and 0 <= w < 2**64 for w in works)
            or works[0] != works[1]):
        raise RuntimeError(
            f"{where}: states candidate_work_relation {work_relation!r}, which the candidates' "
            f"own cumulative_chainwork {works[0]!r} / {works[1]!r} do not establish"
        )
    return out + [first]


def validate_canonical_pipeline_v2_semantics(path: Path) -> None:
    """RUB-1208 relation/receipt gate independent of generator byte equality.

    Most relations below are also enforced by the generator
    (clients/go/cmd/gen-conformance-fixtures/runtime.go cp2ValidateR1208Payload
    and cp2ValidateR1208Expected), but neither side is the other's superset: the
    `fixtures` catalog literals are validated by Go (cp2ValidateFixtures) and the
    schema, the obligation forward/reverse receipts only here.
    """
    data = load_json_fail_closed(path)
    if not isinstance(data, dict):
        raise RuntimeError("canonical_pipeline_v2: top-level value is not an object")
    meta = data.get("_meta")
    epoch = meta.get("closure_epoch") if isinstance(meta, dict) else None
    if not isinstance(epoch, dict):
        raise RuntimeError("canonical_pipeline_v2: _meta.closure_epoch is not an object")
    if epoch.get("closure_manifest_version") != "rubin-c01-design-closure-v8":
        raise RuntimeError("canonical_pipeline_v2: closure epoch is not frozen v8")
    if epoch.get("status") != "building":
        raise RuntimeError("canonical_pipeline_v2: closure status is not building")

    fixtures = data.get("fixtures")
    resolved = data.get("resolved_values")
    rows = data.get("rows")
    if not isinstance(fixtures, dict) or not isinstance(resolved, dict) or not isinstance(rows, list):
        raise RuntimeError("canonical_pipeline_v2: fixtures/resolved_values/rows shape")
    _validate_resolved_values(resolved)
    # No fixtures/resolved_values disjointness check exists because a collision is
    # unreachable: a catalog key matches ^[A-Z][A-Z0-9_]*$ (no `@`) while every
    # resolved key is the composed NAME@ROW/CASE:relation form (always one `@`).
    direct_fields = _direct_field_names(data.get("image_manifest"))

    got_counts = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("cases"), list):
            raise RuntimeError("canonical_pipeline_v2: migrated row shape")
        row_id = row.get("row_id")
        if not isinstance(row_id, str):
            raise RuntimeError(f"canonical_pipeline_v2: row_id {row_id!r} is not a string")
        if row_id in got_counts:
            raise RuntimeError(f"canonical_pipeline_v2: duplicate migrated row {row_id!r}")
        got_counts[row_id] = len(row["cases"])
    if got_counts != V2_RUB1208_CASE_COUNTS:
        raise RuntimeError(
            f"canonical_pipeline_v2: RUB-1208 row/case census {got_counts!r} "
            f"!= {V2_RUB1208_CASE_COUNTS!r}"
        )

    obligation_forward = {}
    obligation_reverse = {}
    obligation_occurrences = 0
    referenced = set()
    named = set()

    for row in rows:
        row_id = row["row_id"]
        for case in row["cases"]:
            case_id = case.get("case_id")
            where = f"{row_id}/{case_id}"
            obligations = case.get("obligation_ids")
            if (
                not isinstance(obligations, list)
                or not obligations
                or not all(isinstance(value, str) for value in obligations)
                or len(obligations) != len(set(obligations))
            ):
                raise RuntimeError(f"{where}/obligation_ids: must be non-empty unique strings")
            sorted_obligations = sorted(obligations)
            obligation_forward[where] = sorted_obligations
            obligation_occurrences += len(sorted_obligations)
            for obligation in sorted_obligations:
                obligation_reverse.setdefault(obligation, []).append(where)

            _validate_input_aliases(where, case, fixtures, named)
            expected = case.get("expected")
            if not isinstance(expected, dict):
                raise RuntimeError(f"{where}: expected is not an object")
            inputs = case.get("input")
            truth = expected.get("commit_truth")
            images = expected.get("state_image")
            if not isinstance(images, dict) or set(images) != set(direct_fields):
                raise RuntimeError(
                    f"{where}: state_image must carry exactly the {len(direct_fields)} manifest images"
                )

            for image in sorted(direct_fields):
                projection = images[image]
                if not isinstance(projection, dict):
                    raise RuntimeError(f"{where}/{image}: projection is not an object")
                relation = projection.get("relation")
                allowed = _relations_for_truth(expected, truth, image)
                if not allowed:
                    raise RuntimeError(f"{where}: no allowed relation: truth {truth!r} unknown or null result, no disposition")
                if relation not in allowed:
                    raise RuntimeError(
                        f"{where}/{image}: relation={relation!r} invalid for {truth}, "
                        f"want one of {list(allowed)}"
                    )
                digest = projection.get("digest_alias")
                want_digest = f"{image}@{where}:{relation}"
                if digest != want_digest:
                    raise RuntimeError(
                        f"{where}/{image}: digest_alias={digest!r} want {want_digest!r}"
                    )
                _resolved_entry(resolved, digest, "bytes32_hex", f"{where}/{image}/digest_alias")
                referenced.add(digest)
                derived, at_least = _derived_counts(where, image, relation, inputs, fixtures)
                written = projection.get("direct_fields")
                if not isinstance(written, dict) or set(written) != set(direct_fields[image]):
                    raise RuntimeError(
                        f"{where}/{image}/direct_fields: key set differs from the manifest "
                        f"{sorted(direct_fields[image])!r}"
                    )
                for field in sorted(direct_fields[image]):
                    alias = written[field]
                    want_alias = f"{field}@{where}:{relation}"
                    if alias != want_alias:
                        raise RuntimeError(
                            f"{where}/{image}/{field}: alias={alias!r} want {want_alias!r}"
                        )
                    value = _resolved_entry(
                        resolved, alias, V2_DIRECT_FIELD_TYPES[field],
                        f"{where}/{image}/{field}",
                    )
                    referenced.add(alias)
                    if field in derived and value != derived[field]:
                        raise RuntimeError(
                            f"{where}/{image}/{field}: {value!r} differs from the "
                            f"{derived[field]} the stated prestate derives"
                        )
                    if field in at_least and value < at_least[field]:
                        raise RuntimeError(
                            f"{where}/{image}/{field}: {value!r} is rewound below the "
                            f"{at_least[field]} the stated prestate requires"
                        )

            chain = images["CHAIN_IMAGE_V1"]["direct_fields"]
            owner = images["OWNER_IMAGE_V1"]["direct_fields"]
            chain_hash = _resolved_entry(
                resolved, chain.get("tip_hash"), "bytes32_hex", f"{where}/CHAIN/tip_hash"
            )
            chain_height = _resolved_entry(
                resolved, chain.get("height"), "u64", f"{where}/CHAIN/height"
            )
            # All three CHAIN direct fields are bound to the tip block, so a count belonging to another block is a substituted identity. Mirrors Go cp2ValidateChainTip.
            chain_utxo = _resolved_entry(resolved, chain.get("utxo_count"), "u64", f"{where}/CHAIN/utxo_count")
            stable_tip = _resolved_entry(
                resolved, owner.get("stable_tip"), "object", f"{where}/OWNER/stable_tip"
            )
            # Value AND type, like Go cp2ValidateOwnerStableTip: `1 == True` and
            # `4 == 4.0` in Python, so a bare equality admits what cp2UintOf rejects.
            want_tip = {"has_tip": (True, bool), "height": (chain_height, int), "hash": (chain_hash, str)}
            if {k: (v, type(v)) for k, v in stable_tip.items()} != want_tip:
                raise RuntimeError(
                    f"{where}/OWNER/stable_tip: must equal published CHAIN tip hash/height"
                )

            summary = expected.get("canonical_applied_blocks")
            if truth != "NEW":
                if summary is not None:
                    raise RuntimeError(f"{where}/canonical_applied_blocks: non-NEW must be null")
                # A published CHAIN image that is not `new` never moved, so the tip
                # is still the last entry of the stated prestate chain. The key is
                # that relation, not the truth: DD-002 proves a new identity under
                # NOT_APPLICABLE, and there the tip does move. Mirrors Go.
                prestate = _input_value(inputs, "/input/prestate_canonical_chain")
                if prestate is not _ABSENT and images["CHAIN_IMAGE_V1"].get("relation") != "new":
                    tip_block = _prestate_chain_block(where, prestate, fixtures, 1)
                    if chain_hash != tip_block.get("block_hash") or chain_height != tip_block.get("height") \
                            or chain_utxo != tip_block.get("utxo_count"):
                        raise RuntimeError(f"{where}/CHAIN: tip must equal the stated prestate chain tip")
                # A non-NEW case publishes no summary at all, so its stated row
                # count is exactly 0: reached here, the arm is unreachable behind
                # the NEW path. Mirrors Go cp2ValidateR1208Summary.
                _summary_rows_effect(where, expected, 0)
                continue
            if not isinstance(summary, list):
                raise RuntimeError(f"{where}/canonical_applied_blocks: NEW must be an array")

            disconnect = isinstance(inputs, list) and any(
                isinstance(x, dict) and x.get("pointer") == "/input/disconnect_command"
                for x in inputs
            )
            if not summary and not disconnect:
                raise RuntimeError(
                    f"{where}/canonical_applied_blocks: empty but the case carries no "
                    f"/input/disconnect_command stimulus"
                )
            if summary and disconnect:
                raise RuntimeError(
                    f"{where}/canonical_applied_blocks: a standalone disconnect must carry "
                    f"an exact empty summary"
                )
            # A stated connect count is the number of blocks the frame connects,
            # which is exactly the number of summary rows.
            stated_connects = _input_value(inputs, "/input/connect_count")
            if stated_connects is not _ABSENT and (
                type(stated_connects) is not int or stated_connects != len(summary)
            ):
                raise RuntimeError(
                    f"{where}/canonical_applied_blocks: {len(summary)} rows, the case "
                    f"states connect_count {stated_connects!r}"
                )
            want_da = _included_set_da_ids(where, inputs, fixtures, summary)

            last_height, last_block, occurrences = None, None, 0
            for index, summary_row in enumerate(summary):
                sw = f"{where}/canonical_applied_blocks/{index}"
                if not isinstance(summary_row, dict):
                    raise RuntimeError(f"{sw}: row is not an object")
                block = _fixture_value(
                    fixtures, summary_row.get("block_id"), "object", f"{sw}/block_id"
                )
                block_hash = _fixture_value(
                    fixtures, summary_row.get("block_hash"), "bytes32_hex", f"{sw}/block_hash"
                )
                if not isinstance(block, dict) or type(block.get("height")) is not int or not 0 <= block["height"] < 2**64:
                    raise RuntimeError(f"{sw}/block_id: fixture has no u64 height")
                # Exact block identity (summary_manifest M14/identity).
                if block.get("block_hash") != block_hash:
                    raise RuntimeError(
                        f"{sw}/block_hash: {summary_row.get('block_hash')!r} is not the hash of "
                        f"block_id {summary_row.get('block_id')!r}"
                    )
                height = block["height"]
                if last_height is not None and height <= last_height:
                    raise RuntimeError(f"{where}/canonical_applied_blocks: heights not strictly canonical")
                last_height, last_block = height, block

                da_ids = summary_row.get("complete_da_ids")
                if not isinstance(da_ids, list):
                    raise RuntimeError(f"{sw}/complete_da_ids: not an array")
                raw_ids = [
                    _fixture_value(fixtures, alias, "bytes32_hex", f"{sw}/complete_da_ids/{i}")
                    for i, alias in enumerate(da_ids)
                ]
                # Strictly ascending: an equal neighbour is a duplicated
                # occurrence, which a complete per-block set may never carry.
                if any(b <= a for a, b in zip(raw_ids, raw_ids[1:])):
                    raise RuntimeError(f"{sw}/complete_da_ids: not strictly ascending raw bytes")
                occurrences += len(raw_ids)
                named.update((summary_row.get("block_id"), summary_row.get("block_hash"), *da_ids))
                if want_da is not None:
                    bound = want_da.get(summary_row.get("block_id"))
                    if bound is not None and raw_ids != bound:
                        raise RuntimeError(
                            f"{sw}/complete_da_ids: {raw_ids!r} differ from the included-set "
                            f"identities {bound!r} of this block"
                        )

            # The published blocks are the blocks the case states, in order: a
            # dropped, reordered or substituted one stops being the frame's own
            # ordered outcome even where every row is individually well-formed.
            branch = _stated_branch_blocks(where, inputs, fixtures)
            if branch and [r["block_id"] for r in summary] != branch:
                raise RuntimeError(
                    f"{where}/canonical_applied_blocks: published blocks differ from "
                    f"the stated branch {branch!r}"
                )

            # One stimulus states the occurrence fact for the whole case rather
            # than per identity, so an added or dropped occurrence reddens even
            # where no identity is stated. SEMANTICS, both sides: the stated count
            # is the CASE TOTAL -- occurrences summed over EVERY summary row, never
            # per block, so a multi-row case states the total.
            stated_count = _input_value(inputs, "/input/block_complete_da_set_count")
            if stated_count is not _ABSENT and (
                type(stated_count) is not int or stated_count != occurrences
            ):
                raise RuntimeError(
                    f"{where}/canonical_applied_blocks: {occurrences} complete DA-set "
                    f"occurrences, the case states {stated_count!r}"
                )

            # Fork choice is what makes a stated branch canonical at all: greater
            # cumulative chainwork than the current tip, or equal work with a
            # lexicographically lower tip hash (node/sync_reorg.go:224
            # shouldSwitchToBranch, applied by applyPreferredBranch at :261).
            prestate = _input_value(inputs, "/input/prestate_canonical_chain")
            if prestate is not _ABSENT and last_block is not None:
                pre_tip = _prestate_chain_block(where, prestate, fixtures, 1)
                got, want = last_block.get("cumulative_chainwork"), pre_tip.get("cumulative_chainwork")
                if not all(type(w) is int and 0 <= w < 2**64 for w in (got, want)) or got < want or (
                    got == want and str(last_block.get("block_hash")) >= str(pre_tip.get("block_hash"))
                ):
                    raise RuntimeError(
                        f"{where}/canonical_applied_blocks: branch tip cumulative_chainwork {got!r} "
                        f"does not win fork choice against the stated prestate tip's {want!r}"
                    )
            # The published chain tip is the last newly canonical block -- or, for
            # a standalone disconnect, which publishes no row at all, the entry
            # BELOW the disconnected tip in the stated prestate chain.
            tip_block, tip_what = last_block, "the last canonical-applied block"
            if disconnect:
                prestate = _input_value(inputs, "/input/prestate_canonical_chain")
                tip_block = _prestate_chain_block(where, prestate, fixtures, 2)
                tip_what = "the block below the disconnected tip"
            if tip_block is not None and (
                chain_hash != tip_block.get("block_hash") or chain_height != tip_block.get("height")
                or chain_utxo != tip_block.get("utxo_count")
            ):
                raise RuntimeError(f"{where}/CHAIN: tip must equal {tip_what}")

            _summary_rows_effect(where, expected, len(summary))

    orphans = sorted(set(resolved) - referenced)
    if orphans:
        raise RuntimeError(
            f"canonical_pipeline_v2: resolved_values[{orphans[0]}] is referenced by no image projection"
        )
    # The same reverse reachability for the catalog: an entry no case names is a
    # stimulus nothing states, which is where a stale or substituted-away fixture
    # hides. The three alias positions the schema admits are all recorded above.
    unnamed = sorted(set(fixtures) - named)
    if unnamed:
        raise RuntimeError(f"canonical_pipeline_v2: fixtures[{unnamed[0]}] is named by no case")

    for cases in obligation_reverse.values():
        cases.sort()
    if obligation_occurrences != V2_RUB1208_OBLIGATION_OCCURRENCES:
        raise RuntimeError(
            f"canonical_pipeline_v2: obligation occurrences={obligation_occurrences} "
            f"want {V2_RUB1208_OBLIGATION_OCCURRENCES}"
        )
    if len(obligation_reverse) != V2_RUB1208_OBLIGATION_UNIQUE:
        raise RuntimeError(
            f"canonical_pipeline_v2: unique obligations={len(obligation_reverse)} "
            f"want {V2_RUB1208_OBLIGATION_UNIQUE}"
        )
    if _canonical_sha256(obligation_forward) != V2_RUB1208_OBLIGATION_FORWARD_SHA256:
        raise RuntimeError("canonical_pipeline_v2: obligation forward receipt hash mismatch")
    if _canonical_sha256(obligation_reverse) != V2_RUB1208_OBLIGATION_REVERSE_SHA256:
        raise RuntimeError("canonical_pipeline_v2: obligation reverse receipt hash mismatch")


def assert_canonical_pipeline_v2_negative_controls(path: Path) -> None:
    """Run RUB-1208 single-dimension hostile mutations from a valid artifact.

    Every control starts from the committed artifact (a KNOWN-VALID control),
    changes exactly ONE dimension, and asserts the exact failure pointer, so a
    control that passes for the wrong reason is itself an error.
    """
    control = load_json_fail_closed(path)

    def case_of(data: dict, row_id: str, case_id: str) -> dict:
        row = next((row for row in data["rows"] if row["row_id"] == row_id), None)
        if row is None:
            raise RuntimeError(f"negative control target row {row_id} is gone")
        case = next((c for c in row["cases"] if c["case_id"] == case_id), None)
        if case is None:
            raise RuntimeError(f"negative control target case {row_id}/{case_id} is gone")
        return case

    def resolved_of(data: dict, row_id: str, case_id: str, image: str, field: str) -> dict:
        case = case_of(data, row_id, case_id)
        return data["resolved_values"][case["expected"]["state_image"][image]["direct_fields"][field]]

    def stale_standard_used_bytes(data: dict) -> None:
        resolved_of(data, "C01-SIDE-001", "MAIN", "STANDARD_MEMPOOL_IMAGE_V1", "used_bytes")["value"] = 999999

    def stale_retained_set_count(data: dict) -> None:
        resolved_of(data, "C01-DACLEAN-001", "ABSENT_RETAINED", "RETAINED_DA_IMAGE_V1", "set_count")["value"] = 0

    def stale_owner_claim_count(data: dict) -> None:
        resolved_of(data, "C01-DACLEAN-001", "CORRUPT_FIRST", "OWNER_IMAGE_V1", "claim_count")["value"] = 99

    def stale_retained_pinned_payload_bytes(data: dict) -> None:
        resolved_of(data, "C01-DISCONNECT-001", "MAIN", "RETAINED_DA_IMAGE_V1", "pinned_payload_bytes")["value"] = 999999

    def rewound_last_admission_seq(data: dict) -> None:
        # A rewind BELOW a resident record is M15; a watermark ABOVE it is legal (an evicted seq), so only this direction reddens.
        resolved_of(data, "C01-SIDE-001", "MAIN", "STANDARD_MEMPOOL_IMAGE_V1", "last_admission_seq")["value"] = 0

    def chain_utxo_count_off_the_tip_block(data: dict) -> None:
        resolved_of(data, "C01-SIDE-001", "MAIN", "CHAIN_IMAGE_V1", "utxo_count")["value"] = 777

    def drop_block_includes_occurrence(data: dict) -> None:
        case_of(data, "C01-DIRECT-001", "MAIN")["expected"]["canonical_applied_blocks"][0]["complete_da_ids"] = []

    def add_occurrence_where_count_is_zero(data: dict) -> None:
        case = case_of(data, "C01-SUMMARY-001", "SINGLE_BLOCK_NO_DA")
        case["expected"]["canonical_applied_blocks"][0]["complete_da_ids"] = [
            "R1208_SUMMARY_001_SINGLE_BLOCK_NO_DA_B1_HASH"
        ]

    def drop_one_occurrence_spelling(data: dict) -> None:
        # Both spellings state the same set, so a union let a drop from ONE through.
        case = case_of(data, "C01-SUMMARY-001", "SINGLE_BLOCK_WITH_DA")
        stated = next(i for i in case["input"] if i["pointer"].endswith("da_ids_in_transaction_order"))
        stated["value_or_alias"] = stated["value_or_alias"][:1]

    def empty_one_occurrence_spelling(data: dict) -> None:
        # A stated [] claims the EMPTY set, so it disagrees with the 2 ids the other spelling names.
        case = case_of(data, "C01-SUMMARY-001", "SINGLE_BLOCK_WITH_DA")
        stated = next(i for i in case["input"] if i["pointer"].endswith("included_set_identities"))
        stated["value_or_alias"] = []

    def grouped_included_set_entry_stated_empty(data: dict) -> None:
        data["fixtures"]["R1208_DACLEAN_001_MULTI_SET_SUCCESS_INPUT_BLOCK_INCLUDED_SET_IDENTITIES_1"]["value"]["identities"] = []

    def input_of(data: dict, row_id: str, case_id: str, pointer: str) -> dict:
        return next(i for i in case_of(data, row_id, case_id)["input"] if i["pointer"] == pointer)

    def omit_one_grouped_included_set_entry(data: dict) -> None:
        # The B2P group goes while its summary row keeps its occurrence: without
        # the coverage arm that row is bound by nothing and passes.
        stated = input_of(data, "C01-DACLEAN-001", "MULTI_SET_SUCCESS", "/input/block_included_set_identities")
        stated["value_or_alias"] = stated["value_or_alias"][:1]

    def substitute_one_stated_branch_block(data: dict) -> None:
        # The summary keeps its rows, heights and hashes, so only the branch-to-
        # summary derivation can reject the substituted branch block.
        input_of(data, "C01-REORG-001", "MAIN", "/input/prestored_side_branch")["value_or_alias"][0] = "R1208_REORG_001_MAIN_B3P"

    def borrow_another_cases_input_alias(data: dict) -> None:
        # A non-NEW case on purpose: its summary is null, so the branch derivation
        # cannot fire and the namespace is the only rule left.
        input_of(data, "C01-DACLEAN-001", "CORRUPT_FIRST", "/input/stimulus_block")["value_or_alias"] = "R1208_GENESIS_001_MAIN_G"

    def borrow_another_cases_da_alias(data: dict) -> None:
        case = case_of(data, "C01-REORG-001", "MAIN")
        case["expected"]["canonical_applied_blocks"][0]["complete_da_ids"][0] = "R1208_DACLEAN_001_EXACT_MATCH_DA_ID_1"

    def wire_disposed_row_with_an_old_image(data: dict) -> None:
        expected = case_of(data, "C01-SIDE-001", "MAIN")["expected"]
        expected["result"], expected["wire_disposition"], expected["commit_truth"] = None, "CHECKSUM_REJECT", "OLD"
        expected["state_image"]["CHAIN_IMAGE_V1"]["relation"] = "old"

    def summary_rows_effect_is_a_bool(data: dict) -> None:
        # A 1-ROW case on purpose: True == 1, so the count arm cannot fire and only the type guard is left.
        case_of(data, "C01-SUMMARY-001", "SINGLE_BLOCK_NO_DA")["expected"]["effects"]["summary_rows"]["value"] = True

    def stale_owner_tip(data: dict) -> None:
        case = case_of(data, "C01-DIRECT-001", "MAIN")
        alias = case["expected"]["state_image"]["OWNER_IMAGE_V1"]["direct_fields"]["stable_tip"]
        data["resolved_values"][alias]["value"]["hash"] = "00" * 32

    def float_stable_tip_height(data: dict) -> None:
        # Type-exactness pair: 4.0 equals 4 and -1 is an int, so both pass every value arm.
        stable = resolved_of(data, "C01-DIRECT-001", "MAIN", "OWNER_IMAGE_V1", "stable_tip")["value"]
        stable["height"] = float(stable["height"])

    def negative_summary_block_height(data: dict) -> None:
        # Row 0 of 3: ordering and the CHAIN-tip binding (last row) both still hold.
        row = case_of(data, "C01-REORG-001", "MAIN")["expected"]["canonical_applied_blocks"][0]
        data["fixtures"][row["block_id"]]["value"]["height"] = -1

    def float_connect_count(data: dict) -> None:
        # 3.0 equals 3 in the count arm, so only the type arm can reject it.
        stated = case_of(data, "C01-REORG-001", "MAIN")["input"]
        next(i for i in stated if i["pointer"] == "/input/connect_count")["value_or_alias"] = 3.0

    def float_da_set_count(data: dict) -> None:
        stated = case_of(data, "C01-SUMMARY-001", "SINGLE_BLOCK_NO_DA")["input"]
        next(i for i in stated if i["pointer"] == "/input/block_complete_da_set_count")["value_or_alias"] = 0.0

    def stale_chain_height(data: dict) -> None:
        # Same block hash, one-off height: the hash arm and the OWNER tip both pass.
        row = case_of(data, "C01-DIRECT-001", "MAIN")["expected"]["canonical_applied_blocks"][0]
        data["fixtures"][row["block_id"]]["value"]["height"] += 1

    def reverse_summary(data: dict) -> None:
        case = case_of(data, "C01-SUMMARY-001", "MULTI_BLOCK_ORDER")
        case["expected"]["canonical_applied_blocks"].reverse()

    def reverse_da_ids(data: dict) -> None:
        case = case_of(data, "C01-SUMMARY-001", "SINGLE_BLOCK_WITH_DA")
        case["expected"]["canonical_applied_blocks"][0]["complete_da_ids"].reverse()

    def non_new_summary(data: dict) -> None:
        case = case_of(data, "C01-SIDE-001", "MAIN")
        case["expected"]["canonical_applied_blocks"] = []

    def drop_obligation(data: dict) -> None:
        case = case_of(data, "C01-DIRECT-001", "MAIN")
        case["obligation_ids"].pop()

    def rename_obligation(data: dict) -> None:
        # Census-preserving: same unique count, same occurrence count. Only the
        # forward receipt hash can reject it.
        case = case_of(data, "C01-DIRECT-001", "MAIN")
        case["obligation_ids"][0] = "OBL-NOT-A-CENSUS-ID-999"

    def move_obligation(data: dict) -> None:
        # Census-preserving in both counts: one id moves to a case that does not
        # already carry it, so unique and occurrence counts are untouched and the
        # forward receipt hash is the only thing left that can reject it.
        source = case_of(data, "C01-DACLEAN-001", "CORRUPT_FIRST")
        target = case_of(data, "C01-DIRECT-001", "MAIN")
        movable = [o for o in source["obligation_ids"] if o not in target["obligation_ids"]]
        if not movable:
            raise RuntimeError(
                "negative control 'moved obligation id' has no movable obligation left"
            )
        source["obligation_ids"].remove(movable[0])
        target["obligation_ids"].append(movable[0])

    def swap_block_hash(data: dict) -> None:
        case = case_of(data, "C01-SUMMARY-001", "MULTI_BLOCK_ORDER")
        rows = case["expected"]["canonical_applied_blocks"]
        rows[0]["block_hash"], rows[1]["block_hash"] = rows[1]["block_hash"], rows[0]["block_hash"]

    def duplicate_da_id(data: dict) -> None:
        case = case_of(data, "C01-SUMMARY-001", "SINGLE_BLOCK_WITH_DA")
        ids = case["expected"]["canonical_applied_blocks"][0]["complete_da_ids"]
        ids[1] = ids[0]

    def drop_da_id(data: dict) -> None:
        case = case_of(data, "C01-DACLEAN-001", "MULTI_SET_SUCCESS")
        case["expected"]["canonical_applied_blocks"][0]["complete_da_ids"].pop()

    def empty_new_summary(data: dict) -> None:
        case = case_of(data, "C01-DIRECT-001", "MAIN")
        case["expected"]["canonical_applied_blocks"] = []

    def disconnect_summary_null(data: dict) -> None:
        case = case_of(data, "C01-DISCONNECT-001", "MAIN")
        case["expected"]["canonical_applied_blocks"] = None

    def relation_contradicts_truth(data: dict) -> None:
        case = case_of(data, "C01-SIDE-001", "MAIN")
        case["expected"]["state_image"]["CHAIN_IMAGE_V1"]["relation"] = "new"

    def relation_and_aliases_moved_together(data: dict) -> None:
        # Dual violation: the relation moves AND every alias encoding it moves
        # with it, so the composed-alias check still passes and only the
        # truth -> relation arm can reject this.
        case = case_of(data, "C01-SIDE-001", "MAIN")
        projection = case["expected"]["state_image"]["RETAINED_DA_IMAGE_V1"]
        values = data["resolved_values"]

        def rename(old_alias: str) -> str:
            renamed = old_alias.replace(":unchanged", ":new", 1)
            values[renamed] = values.pop(old_alias)
            return renamed

        projection["relation"] = "new"
        projection["digest_alias"] = rename(projection["digest_alias"])
        for field in sorted(projection["direct_fields"]):
            projection["direct_fields"][field] = rename(projection["direct_fields"][field])

    def stale_chain_tip(data: dict) -> None:
        # Dual violation: CHAIN tip AND the OWNER stable tip move together, so
        # the OWNER<->CHAIN relation still holds and only the summary binding
        # can reject it.
        case = case_of(data, "C01-DIRECT-001", "MAIN")
        fields = case["expected"]["state_image"]["CHAIN_IMAGE_V1"]["direct_fields"]
        stable = case["expected"]["state_image"]["OWNER_IMAGE_V1"]["direct_fields"]["stable_tip"]
        data["resolved_values"][fields["tip_hash"]]["value"] = "11" * 32
        data["resolved_values"][stable]["value"]["hash"] = "11" * 32

    def orphan_resolved_value(data: dict) -> None:
        data["resolved_values"]["tip_hash@C01-DIRECT-001/ORPHAN:new"] = {
            "type": "bytes32_hex",
            "value": "22" * 32,
        }

    def substituted_digest_alias(data: dict) -> None:
        # Resolves to a real bytes32_hex entry, just not this position's.
        case = case_of(data, "C01-SUMMARY-001", "MULTI_BLOCK_ORDER")
        other = case_of(data, "C01-DIRECT-001", "MAIN")
        case["expected"]["state_image"]["CHAIN_IMAGE_V1"]["digest_alias"] = (
            other["expected"]["state_image"]["CHAIN_IMAGE_V1"]["digest_alias"]
        )

    def resolved_key_trailing_newline(data: dict) -> None:
        alias = sorted(data["resolved_values"])[0]
        data["resolved_values"][alias + "\n"] = data["resolved_values"].pop(alias)

    def resolved_key_leading_space(data: dict) -> None:
        alias = sorted(data["resolved_values"])[0]
        data["resolved_values"][" " + alias] = data["resolved_values"].pop(alias)

    def bytes32_trailing_newline(data: dict) -> None:
        alias = next(k for k, v in sorted(data["resolved_values"].items()) if v["type"] == "bytes32_hex")
        data["resolved_values"][alias]["value"] += "\n"

    def standalone_disconnect_publishes_a_row(data: dict) -> None:
        case = case_of(data, "C01-DISCONNECT-001", "MAIN")
        case["expected"]["canonical_applied_blocks"] = [{}]

    def drop_a_connected_block(data: dict) -> None:
        case = case_of(data, "C01-REORG-001", "MAIN")
        case["expected"]["canonical_applied_blocks"].pop(0)

    def maybe_commit_truth(data: dict) -> None:
        case_of(data, "C01-DIRECT-001", "MAIN")["expected"]["commit_truth"] = "MAYBE"

    def overflow_prestate_sizes(data: dict) -> None:
        # 2**64-1 + 1 is the minimal sum past the u64 ceiling; Python ints never wrap like Go uint64, so record_count would reject without this guard.
        data["fixtures"]["R1208_SIDE_001_MAIN_TX_S1"]["value"]["size"] = 2**64 - 1
        # admission_seq is stated so the u64-shape arm cannot preempt the overflow arm this control exists to prove.
        data["fixtures"]["R1208_SIDE_001_MAIN_TX_S2"] = {"type": "object", "value": {"kind": "standard_record", "size": 1, "admission_seq": 2}}
        stated = next(i for i in case_of(data, "C01-SIDE-001", "MAIN")["input"] if i["pointer"] == "/input/prestate_standard_records")
        stated["value_or_alias"] = ["R1208_SIDE_001_MAIN_TX_S1", "R1208_SIDE_001_MAIN_TX_S2"]

    def summary_rows_effect_drift(data: dict) -> None:
        case = case_of(data, "C01-REORG-001", "MAIN")
        case["expected"]["effects"]["summary_rows"]["value"] = 99

    def substitute_the_genesis_summary_block(data: dict) -> None:
        # The substitute carries the genesis block's own hash and height, so only
        # the pack -> summary derivation can reject it.
        data["fixtures"]["R1208_GENESIS_001_MAIN_G2"] = data["fixtures"]["R1208_GENESIS_001_MAIN_G"]
        case_of(data, "C01-GENESIS-001", "MAIN")["expected"]["canonical_applied_blocks"][0]["block_id"] = "R1208_GENESIS_001_MAIN_G2"

    def substitute_the_equal_work_winner(data: dict) -> None:
        # Coherent: the row names the LOSER and the loser's own declared hash, so
        # only the stated tie-break can reject the substitution.
        loser = data["fixtures"]["R1208_EQUALWORK_001_MAIN_BB"]["value"]["block_hash"]
        data["fixtures"]["R1208_EQUALWORK_001_MAIN_BB_HASH"] = {"type": "bytes32_hex", "value": loser}
        row = case_of(data, "C01-EQUALWORK-001", "MAIN")["expected"]["canonical_applied_blocks"][0]
        row["block_id"], row["block_hash"] = "R1208_EQUALWORK_001_MAIN_BB", "R1208_EQUALWORK_001_MAIN_BB_HASH"

    def roll_back_the_non_new_chain_tip(data: dict) -> None:
        # Coherent: CHAIN and OWNER both name the block BELOW the stated prestate
        # tip, so only the prestate binding can reject it.
        case = case_of(data, "C01-SIDE-001", "MAIN")
        below = data["fixtures"]["R1208_SIDE_001_MAIN_B0"]["value"]
        fields = case["expected"]["state_image"]["CHAIN_IMAGE_V1"]["direct_fields"]
        stable = data["resolved_values"][case["expected"]["state_image"]["OWNER_IMAGE_V1"]["direct_fields"]["stable_tip"]]["value"]
        data["resolved_values"][fields["tip_hash"]]["value"] = below["block_hash"]
        data["resolved_values"][fields["height"]]["value"] = below["height"]
        stable["hash"], stable["height"] = below["block_hash"], below["height"]

    def roll_the_post_disconnect_tip_to_genesis(data: dict) -> None:
        # Swapped, never repeated: the entry BELOW the tip becomes genesis while the
        # array still names each block once, so this stays a single dimension.
        chain = input_of(data, "C01-DISCONNECT-001", "MAIN", "/input/prestate_canonical_chain")["value_or_alias"]
        chain[0], chain[1] = chain[1], chain[0]

    def flat_identities_on_a_multi_row_summary(data: dict) -> None:
        rows = case_of(data, "C01-DIRECT-001", "MAIN")["expected"]["canonical_applied_blocks"]
        rows.append(rows[0])

    def repeat_a_stated_alias(data: dict) -> None:
        stated = input_of(data, "C01-SUMMARY-001", "SINGLE_BLOCK_WITH_DA", "/input/block_complete_da_ids_in_transaction_order")
        stated["value_or_alias"] = stated["value_or_alias"] + stated["value_or_alias"][:1]

    group_1 = "R1208_DACLEAN_001_MULTI_SET_SUCCESS_INPUT_BLOCK_INCLUDED_SET_IDENTITIES_1"
    mutations = (
        ("orphan fixtures entry", lambda d: d["fixtures"].update({"R1208_DIRECT_001_MAIN_ORPHAN": {"type": "u64", "value": 1}}), "fixtures[R1208_DIRECT_001_MAIN_ORPHAN] is named by no case"),
        ("stated array repeats an alias", repeat_a_stated_alias, "names an alias more than once"),
        # Silently ABSENT without the closed vocabulary: the standard-mempool
        # derivation would simply stop constraining this case.
        ("input pointer typo", lambda d: input_of(d, "C01-SIDE-001", "MAIN", "/input/prestate_standard_records").update(pointer="/input/prestate_standard_record"), "'/input/prestate_standard_record' is outside the closed stated vocabulary"),
        ("branch tip does not out-work the prestate tip", lambda d: d["fixtures"]["R1208_REORG_001_MAIN_B3P"]["value"].update(cumulative_chainwork=3), "cumulative_chainwork 3 does not win fork choice"),
        ("equal-work candidates carry unequal work", lambda d: d["fixtures"]["R1208_EQUALWORK_001_MAIN_BB"]["value"].update(cumulative_chainwork=4), "own cumulative_chainwork 3 / 4 do not establish"),
        ("genesis summary block substituted", substitute_the_genesis_summary_block, "published blocks differ from the stated branch"),
        ("equal-work winner substituted", substitute_the_equal_work_winner, "published blocks differ from the stated branch"),
        ("equal-work hash relation contradicts the candidates", lambda d: input_of(d, "C01-EQUALWORK-001", "MAIN", "/input/candidate_hash_relation").update(value_or_alias="hash_bb_lt_hash_ba_raw_bytes"), "states candidate_hash_relation 'hash_bb_lt_hash_ba_raw_bytes'"),
        ("post-disconnect tip rolled to genesis", roll_the_post_disconnect_tip_to_genesis, "tip must equal the block below the disconnected tip"),
        ("non-NEW chain tip rolled back one block", roll_back_the_non_new_chain_tip, "tip must equal the stated prestate chain tip"),
        ("non-NEW effect claims summary rows", lambda d: case_of(d, "C01-SUMMARY-001", "NON_NEW_NULL")["expected"]["effects"]["summary_rows"].update(value=7), "effects.summary_rows: 7 differs from the 0 published rows"),
        ("two grouped keys bind one summary row", lambda d: d["fixtures"][group_1]["value"].update(block_id="SUCCESS_B1P"), "is bound by more than one included-set group"),
        ("grouped key matches no summary row", lambda d: d["fixtures"][group_1]["value"].update(block_id="NOPE"), "included-set block 'NOPE' matches 0 summary rows"),
        ("grouped key matches two summary rows", lambda d: case_of(d, "C01-DACLEAN-001", "MULTI_SET_SUCCESS")["expected"]["canonical_applied_blocks"][1].update(block_id="R1208_DACLEAN_001_MULTI_SET_SUCCESS_B1P"), "matches 2 summary rows"),
        ("flat and grouped shapes mixed", lambda d: d["fixtures"][group_1].update(value={"da_id": "0" * 63 + "9"}), "mixes flat and grouped included-set identities"),
        ("flat identities on a multi-row summary", flat_identities_on_a_multi_row_summary, "flat included-set identities but 2 summary rows"),
        ("closure epoch moved off v8", lambda d: d["_meta"]["closure_epoch"].update(closure_manifest_version="rubin-c01-design-closure-v9"), "closure epoch is not frozen v8"),
        ("closure status moved off building", lambda d: d["_meta"]["closure_epoch"].update(status="frozen"), "closure status is not building"),
        ("migrated row duplicated", lambda d: d["rows"].append(d["rows"][0]), "duplicate migrated row"),
        ("disconnect over a one-block prestate chain", lambda d: input_of(d, "C01-DISCONNECT-001", "MAIN", "/input/prestate_canonical_chain").update(value_or_alias=["R1208_DISCONNECT_001_MAIN_G"]), "states a 1-block prestate chain, so entry -2 is not stated"),
        ("stale OWNER stable_tip", stale_owner_tip, "OWNER/stable_tip"),
        ("connect_count stated as a float", float_connect_count, "states connect_count 3.0"),
        ("block_complete_da_set_count stated as a float", float_da_set_count, "the case states 0.0"),
        ("stale CHAIN height with a consistent owner", stale_chain_height, "tip must equal the last canonical-applied block"),
        ("OWNER stable_tip height stated as a float", float_stable_tip_height, "must equal published CHAIN tip"),
        ("summary block height stated as a negative integer", negative_summary_block_height, "fixture has no u64 height"),
        ("reversed same-count summary", reverse_summary, "heights not strictly canonical"),
        ("reversed DA ids", reverse_da_ids, "not strictly ascending raw bytes"),
        ("non-NEW summary", non_new_summary, "non-NEW must be null"),
        ("dropped obligation receipt", drop_obligation, "obligation occurrences"),
        ("renamed obligation id", rename_obligation, "obligation forward receipt hash mismatch"),
        ("moved obligation id", move_obligation, "obligation forward receipt hash mismatch"),
        ("substituted same-count block_hash", swap_block_hash, "is not the hash of block_id"),
        ("duplicated DA occurrence", duplicate_da_id, "not strictly ascending raw bytes"),
        ("dropped DA occurrence", drop_da_id, "differ from the included-set identities"),
        ("empty summary on a NEW connect", empty_new_summary, "/input/disconnect_command"),
        ("disconnect summary null instead of []", disconnect_summary_null, "NEW must be an array"),
        ("relation contradicts commit truth", relation_contradicts_truth, "invalid for NOT_APPLICABLE"),
        ("relation and its aliases moved together", relation_and_aliases_moved_together, "invalid for NOT_APPLICABLE"),
        ("stale CHAIN tip with a consistent owner", stale_chain_tip, "tip must equal the last canonical-applied block"),
        ("orphan resolved value", orphan_resolved_value, "referenced by no image projection"),
        ("substituted digest alias", substituted_digest_alias, "digest_alias="),
        ("summary_rows effect drift", summary_rows_effect_drift, "effects.summary_rows"),
        ("stale standard used_bytes", stale_standard_used_bytes, "differs from the 201 the stated prestate derives"),
        ("prestate sizes overflow the used-bytes total", overflow_prestate_sizes, "overflows the used-bytes total"),
        ("commit truth outside the closed set", maybe_commit_truth, "no allowed relation"),
        ("stale retained set_count", stale_retained_set_count, "differs from the 1 the stated prestate derives"),
        ("stale owner claim_count", stale_owner_claim_count, "differs from the 3 the stated prestate derives"),
        ("stale retained pinned_payload_bytes", stale_retained_pinned_payload_bytes, "differs from the 308 the stated prestate derives"),
        ("rewound last_admission_seq", rewound_last_admission_seq, "is rewound below the 1 the stated prestate requires"),
        ("chain utxo_count off the tip block", chain_utxo_count_off_the_tip_block, "tip must equal the stated prestate chain tip"),
        ("dropped occurrence on a block_includes case", drop_block_includes_occurrence, "differ from the included-set"),
        ("one occurrence spelling dropped", drop_one_occurrence_spelling, "stated occurrence spellings disagree"),
        ("one occurrence spelling stated empty", empty_one_occurrence_spelling, "stated occurrence spellings disagree"),
        ("grouped included-set entry stated empty", grouped_included_set_entry_stated_empty, "differ from the included-set"),
        ("occurrence added where the stated count is zero", add_occurrence_where_count_is_zero, "the case states 0"),
        ("summary borrows another case's da alias", borrow_another_cases_da_alias, "outside the case namespace"),
        ("one grouped included-set entry omitted", omit_one_grouped_included_set_entry, "binds 1 of 2 summary rows"),
        ("summary block substituted for another stated block", substitute_one_stated_branch_block, "published blocks differ from the stated branch"),
        ("input alias borrowed from another case", borrow_another_cases_input_alias, "outside the case namespace"),
        ("wire disposed row with an old image", wire_disposed_row_with_an_old_image, "invalid for OLD"),
        ("summary_rows effect is a bool", summary_rows_effect_is_a_bool, "True differs from the 1 published rows"),
        ("resolved key trailing newline", resolved_key_trailing_newline, "is not the composed full form"),
        ("resolved key leading space", resolved_key_leading_space, "is not the composed full form"),
        ("bytes32 value trailing newline", bytes32_trailing_newline, "is not a valid bytes32_hex literal"),
        ("standalone disconnect publishes a row", standalone_disconnect_publishes_a_row, "a standalone disconnect must carry"),
        ("connected block dropped from the summary", drop_a_connected_block, "2 rows, the case states connect_count 3"),
    )
    with tempfile.TemporaryDirectory(prefix="rubin-r1208-negative-") as td:
        for name, mutate, expected_reason in mutations:
            candidate = copy.deepcopy(control)
            mutate(candidate)
            mutated_path = Path(td) / (name.replace(" ", "_").replace("/", "_") + ".json")
            mutated_path.write_text(
                json.dumps(candidate, ensure_ascii=False, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            try:
                validate_canonical_pipeline_v2_semantics(mutated_path)
            except RuntimeError as exc:
                if expected_reason not in str(exc):
                    raise RuntimeError(
                        f"RUB-1208 negative {name!r} failed for wrong reason: {exc}"
                    ) from exc
            else:
                raise RuntimeError(f"RUB-1208 negative {name!r} was accepted")


def run_v2_gate(candidate: Path, committed: Path, authority: Path) -> None:
    """RUB-1208 semantic/receipt gate over both sides of the v2 pair: a violation
    is DRIFT (exit 1), not an environment failure, and a programming error raised
    INSIDE the gate by a hostile artifact is re-raised labelled rather than
    escaping as a traceback -- the same types raised elsewhere stay unhandled.

    The hand-authored authority source the artifact is generated from is
    strict-loaded FIRST: both json.loads and Go's encoding/json keep the last of
    two duplicate keys, so without this load an edited authority could carry a
    silently dropped expectation into every downstream check."""
    for check, path in (
        (load_json_fail_closed, authority),
        (validate_canonical_pipeline_v2_semantics, candidate),
        (validate_canonical_pipeline_v2_semantics, committed),
        (assert_canonical_pipeline_v2_negative_controls, committed),
    ):
        try:
            check(path)
        except (KeyError, TypeError, StopIteration, IndexError, AttributeError, ValueError) as exc:
            raise RuntimeError(f"canonical_pipeline_v2 {path}: {exc!r}") from exc


def assert_committed_untouched(
    repo_root: Path, candidate_root: Path
) -> None:
    committed_root = (repo_root / COMMITTED_FIXTURES_REL).resolve()
    candidate_resolved = candidate_root.resolve()
    if str(candidate_resolved).startswith(str(committed_root) + os.sep):
        raise RuntimeError(
            f"candidate output {candidate_resolved} is inside committed "
            f"fixture root {committed_root}; refusing to run"
        )
    if candidate_resolved == committed_root:
        raise RuntimeError(
            f"candidate output equals committed fixture root {committed_root}; "
            f"refusing to run"
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    committed_root = repo_root / COMMITTED_FIXTURES_REL
    if not committed_root.is_dir():
        print(
            f"ERROR: committed fixtures dir not found: {committed_root}",
            file=sys.stderr,
        )
        return 2

    try:
        output_dir = Path(tempfile.mkdtemp(prefix="rubin-fixture-drift-")).resolve()
    except OSError as exc:
        print(f"ERROR: failed to create candidate output dir: {exc}", file=sys.stderr)
        return 2
    try:
        assert_committed_untouched(repo_root, output_dir)
        run_generator(repo_root, output_dir)
        # An absent v2 artifact on either side is drift with its own diagnostic
        # below, so the gate runs only when both files exist. The isolated
        # fake-repo tests, whose generated files are sentinel bytes, opt out
        # through an environment sentinel -- never a public CLI flag, and never
        # an unrelated file's presence.
        candidate_v2, committed_v2 = output_dir / V2_REL, committed_root / V2_REL
        if os.environ.get(FAKE_REPO_ENV) == "1":
            # Loud: an inherited sentinel would otherwise disable the semantic gate,
            # the receipts and the negative controls with nothing on the terminal.
            print("NOTICE: canonical_pipeline_v2 semantic gate SKIPPED (fake-repo sentinel)", file=sys.stderr)
        elif candidate_v2.is_file() and committed_v2.is_file():
            try:
                run_v2_gate(candidate_v2, committed_v2, repo_root / V2_AUTHORITY_REL)
            except RuntimeError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1
        (
            missing_committed,
            differing,
            matching,
            missing_candidate,
            extra_candidate,
        ) = diff_set(output_dir, committed_root)
        expected_count = len(EXPECTED_FIXTURES)
        all_expected_matched = (
            len(matching) == expected_count
            and not missing_committed
            and not differing
            and not missing_candidate
            and not extra_candidate
        )
        if all_expected_matched:
            print(
                f"OK: conformance fixture drift check passed "
                f"({len(matching)} generator-owned files match committed)"
            )
            return 0
        if missing_candidate:
            print(
                "ERROR: candidate generator did not emit expected "
                "generator-owned fixture(s) (regression in generator output set):",
                file=sys.stderr,
            )
            for rel in missing_candidate:
                print(f"  - {rel}", file=sys.stderr)
        if extra_candidate:
            print(
                "ERROR: candidate generator emitted unexpected file(s) "
                "outside the declared generator-owned set:",
                file=sys.stderr,
            )
            for rel in extra_candidate:
                print(f"  ? {rel}", file=sys.stderr)
        if missing_committed:
            print(
                "ERROR: candidate generator produced files that are not "
                "present under conformance/fixtures/:",
                file=sys.stderr,
            )
            for rel in missing_committed:
                print(f"  + {rel}", file=sys.stderr)
        if differing:
            print(
                "ERROR: candidate fixture bytes differ from committed "
                "fixture bytes (manual regeneration required):",
                file=sys.stderr,
            )
            for rel in differing:
                print(f"  ~ {rel}", file=sys.stderr)
        return 1
    except (RuntimeError, FileNotFoundError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    finally:
        if not args.keep_output_dir:
            shutil.rmtree(output_dir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

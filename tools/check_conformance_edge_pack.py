#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

CLAIMED_PRESENT_STATUSES = {"present", "covered", "complete"}
KNOWN_ABSENT_STATUSES = {"absent", "deferred", "not_claimed", "not-applicable", "not_applicable"}


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def load_json(path: Path, *, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} must contain valid JSON: {exc}") from exc


def json_object(value: object, *, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def proof_domain_map(proof_coverage: dict) -> dict[str, dict]:
    domains = proof_coverage.get("edge_property_domains", [])
    if not isinstance(domains, list):
        raise ValueError("proof_coverage.json edge_property_domains must be a list")
    result: dict[str, dict] = {}
    for domain in domains:
        if not isinstance(domain, dict):
            raise ValueError("proof_coverage.json edge_property_domains entries must be objects")
        name = domain.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("proof_coverage.json edge_property_domains entries need non-empty name")
        if name in result:
            raise ValueError(f"proof_coverage.json duplicate edge_property_domain: {name}")
        result[name] = domain
    return result


def coverage_status(value: object, *, field_name: str, field_present: bool) -> tuple[str, str | None]:
    if not field_present:
        return "", None
    if not isinstance(value, dict):
        return "", f"{field_name} must be object"
    if "status" not in value:
        return "", f"{field_name}.status must be present when {field_name} is present"
    status = value.get("status")
    if not isinstance(status, str) or not status.strip():
        return "", f"{field_name}.status must be non-empty string"
    return status, None


def string_list(value: object, *, field_name: str, require_non_empty: bool = False) -> tuple[list[str], str | None]:
    if not isinstance(value, list):
        return [], f"{field_name} must be list"
    if require_non_empty and not value:
        return [], f"{field_name} must be non-empty list"
    strings: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            return [], f"{field_name} entries must be non-empty strings"
        strings.append(item)
    if len(set(strings)) != len(strings):
        return [], f"{field_name} entries must be unique"
    return strings, None


def main() -> int:
    repo_root = Path(".").resolve()
    baseline_path = repo_root / "conformance" / "EDGE_PACK_BASELINE.json"
    fixtures_dir = repo_root / "conformance" / "fixtures"
    proof_coverage_path = repo_root / "proof_coverage.json"

    if not baseline_path.exists():
        return fail("conformance/EDGE_PACK_BASELINE.json not found")
    if not fixtures_dir.exists():
        return fail("conformance/fixtures directory not found")
    if not proof_coverage_path.exists():
        return fail("proof_coverage.json not found")

    try:
        baseline = json_object(load_json(baseline_path, label="EDGE_PACK_BASELINE.json"), label="EDGE_PACK_BASELINE.json")
        proof_coverage = json_object(load_json(proof_coverage_path, label="proof_coverage.json"), label="proof_coverage.json")
        proof_domains = proof_domain_map(proof_coverage)
    except ValueError as exc:
        return fail(str(exc))
    if baseline.get("schema_version") != 1:
        return fail("EDGE_PACK_BASELINE.json schema_version must be 1")

    domains = baseline.get("domains")
    if not isinstance(domains, list) or not domains:
        return fail("EDGE_PACK_BASELINE.json must contain non-empty domains list")

    seen_domain_names: set[str] = set()
    fixture_gate_to_ids: dict[str, set[str]] = {}
    fixture_gate_to_count: dict[str, int] = {}
    for fixture in fixtures_dir.glob("CV-*.json"):
        try:
            fixture_label = str(fixture.relative_to(repo_root))
            data = json_object(load_json(fixture, label=fixture_label), label=fixture_label)
        except ValueError as exc:
            return fail(str(exc))
        gate = data.get("gate")
        vectors = data.get("vectors", [])
        if not isinstance(gate, str) or not gate.strip():
            return fail(f"{fixture.relative_to(repo_root)} has invalid gate")
        if not isinstance(vectors, list):
            return fail(f"{fixture.relative_to(repo_root)} vectors must be a list")
        ids = set()
        for vec in vectors:
            if not isinstance(vec, dict):
                return fail(f"{fixture.relative_to(repo_root)} vector entry must be object")
            vec_id = vec.get("id")
            if not isinstance(vec_id, str) or not vec_id.strip():
                return fail(f"{fixture.relative_to(repo_root)} contains vector with invalid id")
            ids.add(vec_id)
        fixture_gate_to_ids[gate] = ids
        fixture_gate_to_count[gate] = len(vectors)

    failures = 0
    for domain in domains:
        domain_failures_before = failures
        if not isinstance(domain, dict):
            print("ERROR: domain entry must be object", file=sys.stderr)
            failures += 1
            continue

        name = domain.get("name")
        gates = domain.get("gates")
        min_vectors_total = domain.get("min_vectors_total")
        required_vectors_by_gate = domain.get("required_vectors_by_gate", {})
        coverage_accounting = domain.get("coverage_accounting")

        if not isinstance(name, str) or not name.strip():
            print("ERROR: domain name missing/invalid", file=sys.stderr)
            failures += 1
            continue
        if name in seen_domain_names:
            print(f"ERROR: duplicate domain name: {name}", file=sys.stderr)
            failures += 1
            continue
        seen_domain_names.add(name)
        gate_names, gate_names_error = string_list(gates, field_name=f"domain {name} gates", require_non_empty=True)
        if gate_names_error is not None:
            print(f"ERROR: domain {name}: {gate_names_error}", file=sys.stderr)
            failures += 1
            continue
        if not isinstance(min_vectors_total, int) or min_vectors_total < 0:
            print(f"ERROR: domain {name}: min_vectors_total must be non-negative integer", file=sys.stderr)
            failures += 1
            continue
        if not isinstance(required_vectors_by_gate, dict):
            print(f"ERROR: domain {name}: required_vectors_by_gate must be object", file=sys.stderr)
            failures += 1
            continue
        if coverage_accounting is not None and not isinstance(coverage_accounting, dict):
            print(f"ERROR: domain {name}: coverage_accounting must be object", file=sys.stderr)
            failures += 1
            continue

        total = 0
        missing_gates: list[str] = []
        for gate in gate_names:
            if gate not in fixture_gate_to_count:
                missing_gates.append(gate)
                continue
            total += fixture_gate_to_count[gate]

        if missing_gates:
            print(f"FAIL: domain {name}: missing gate fixtures: {', '.join(missing_gates)}", file=sys.stderr)
            failures += 1

        if total < min_vectors_total:
            print(
                f"FAIL: domain {name}: total vectors {total} < min_vectors_total {min_vectors_total}",
                file=sys.stderr,
            )
            failures += 1

        for gate, raw_required_ids in required_vectors_by_gate.items():
            if not isinstance(gate, str) or not gate.strip():
                print(f"ERROR: domain {name}: required_vectors_by_gate keys must be non-empty strings", file=sys.stderr)
                failures += 1
                continue
            if gate not in fixture_gate_to_ids:
                print(f"FAIL: domain {name}: required gate not found: {gate}", file=sys.stderr)
                failures += 1
                continue
            required_ids, required_ids_error = string_list(
                raw_required_ids,
                field_name=f"required_vectors_by_gate[{gate}]",
                require_non_empty=True,
            )
            if required_ids_error is not None:
                print(f"ERROR: domain {name}: {required_ids_error}", file=sys.stderr)
                failures += 1
                continue
            present = fixture_gate_to_ids[gate]
            missing = [rid for rid in required_ids if rid not in present]
            if missing:
                print(
                    f"FAIL: domain {name}: gate {gate} missing required vectors: {', '.join(missing)}",
                    file=sys.stderr,
                )
                failures += 1

        if coverage_accounting is not None:
            proof_domain_name = coverage_accounting.get("proof_coverage_domain")
            if not isinstance(proof_domain_name, str) or not proof_domain_name.strip():
                print(
                    f"ERROR: domain {name}: coverage_accounting.proof_coverage_domain must be non-empty string",
                    file=sys.stderr,
                )
                failures += 1
            elif proof_domain_name not in proof_domains:
                print(
                    f"FAIL: domain {name}: missing proof_coverage edge_property_domain {proof_domain_name}",
                    file=sys.stderr,
                )
                failures += 1
            else:
                proof_domain = proof_domains[proof_domain_name]
                proof_gates, proof_gates_error = string_list(
                    proof_domain.get("conformance_gates"),
                    field_name="proof_coverage conformance_gates",
                )
                if proof_gates_error is not None:
                    print(
                        f"ERROR: domain {name}: {proof_gates_error}",
                        file=sys.stderr,
                    )
                    failures += 1
                elif sorted(proof_gates) != sorted(gate_names):
                    print(
                        f"FAIL: domain {name}: proof_coverage gates do not match EDGE baseline gates",
                        file=sys.stderr,
                    )
                    failures += 1
                proof_vector_ids, proof_vector_ids_error = string_list(
                    proof_domain.get("vector_ids"),
                    field_name="proof_coverage vector_ids",
                )
                if proof_vector_ids_error is not None:
                    print(
                        f"ERROR: domain {name}: {proof_vector_ids_error}",
                        file=sys.stderr,
                    )
                    failures += 1
                else:
                    present_for_domain: set[str] = set()
                    for gate in gate_names:
                        present_for_domain.update(fixture_gate_to_ids.get(gate, set()))
                    missing_proof_ids = [
                        vid
                        for vid in proof_vector_ids
                        if isinstance(vid, str) and vid not in present_for_domain
                    ]
                    if missing_proof_ids:
                        print(
                            f"FAIL: domain {name}: proof_coverage references missing vector IDs: {', '.join(missing_proof_ids)}",
                            file=sys.stderr,
                        )
                        failures += 1
                    for gate, raw_required_ids in required_vectors_by_gate.items():
                        if not isinstance(gate, str) or not gate.strip():
                            continue
                        required_ids, required_ids_error = string_list(
                            raw_required_ids,
                            field_name=f"required_vectors_by_gate[{gate}]",
                            require_non_empty=True,
                        )
                        if required_ids_error is not None:
                            continue
                        missing_from_proof = [rid for rid in required_ids if rid not in proof_vector_ids]
                        if missing_from_proof:
                            print(
                                f"FAIL: domain {name}: proof_coverage missing vector IDs: {', '.join(missing_from_proof)}",
                                file=sys.stderr,
                            )
                            failures += 1

                fuzz_status, fuzz_status_error = coverage_status(
                    proof_domain.get("fuzz"),
                    field_name="proof_coverage fuzz",
                    field_present="fuzz" in proof_domain,
                )
                if fuzz_status_error is not None:
                    print(f"ERROR: domain {name}: {fuzz_status_error}", file=sys.stderr)
                    failures += 1
                elif fuzz_status in CLAIMED_PRESENT_STATUSES:
                    print(
                        f"FAIL: domain {name}: proof_coverage claims fuzz={fuzz_status}; committed fuzz evidence validation is not supported in this edge-pack checker",
                        file=sys.stderr,
                    )
                    failures += 1
                elif fuzz_status and fuzz_status not in KNOWN_ABSENT_STATUSES:
                    print(
                        f"ERROR: domain {name}: unknown fuzz coverage status {fuzz_status}",
                        file=sys.stderr,
                    )
                    failures += 1

                formal_status, formal_status_error = coverage_status(
                    proof_domain.get("formal"),
                    field_name="proof_coverage formal",
                    field_present="formal" in proof_domain,
                )
                if formal_status_error is not None:
                    print(f"ERROR: domain {name}: {formal_status_error}", file=sys.stderr)
                    failures += 1
                elif formal_status in CLAIMED_PRESENT_STATUSES:
                    print(
                        f"FAIL: domain {name}: proof_coverage claims formal={formal_status}; committed formal evidence validation is not supported in this edge-pack checker",
                        file=sys.stderr,
                    )
                    failures += 1
                elif formal_status and formal_status not in KNOWN_ABSENT_STATUSES:
                    print(
                        f"ERROR: domain {name}: unknown formal coverage status {formal_status}",
                        file=sys.stderr,
                    )
                    failures += 1

        if failures == domain_failures_before:
            print(f"OK: domain {name} total_vectors={total} min={min_vectors_total}")

    if failures:
        print(f"FAILED: edge-pack check found {failures} issue(s)", file=sys.stderr)
        return 1

    print("OK: conformance edge-pack baseline satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

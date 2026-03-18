#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha3_256_hex(b: bytes) -> str:
    return hashlib.sha3_256(b).hexdigest()


def normalize_lf(s: str) -> str:
    return s.replace("\r\n", "\n").replace("\r", "\n")


def sha3_256_hex_lf_normalized_bytes(b: bytes) -> str:
    b = b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha3_256(b).hexdigest()


def heading_level(heading: str) -> int:
    m = re.match(r"^(#+)\s", heading)
    if not m:
        raise ValueError(f"invalid heading (expected markdown # prefix): {heading!r}")
    return len(m.group(1))


def extract_section(md: str, heading: str) -> str:
    """
    Extract markdown from exact section heading line to next heading
    of same/higher level; trim; append trailing LF.
    This matches SECTION_HASHES.json canonicalization description.
    """
    md = normalize_lf(md)

    heading_line = heading.strip()
    heading_re = re.escape(heading_line)
    m = re.search(rf"(?m)^{heading_re}\s*$", md)
    if not m:
        raise ValueError(f"heading not found: {heading!r}")

    level = heading_level(heading_line)

    # Next heading of same or higher level: ^#{1,level}\s
    m2 = re.search(rf"(?m)^#{{1,{level}}}\s", md[m.end() :])
    end = (m.end() + m2.start()) if m2 else len(md)

    chunk = md[m.start() : end]
    return chunk.strip() + "\n"


def main() -> int:
    repo_root = Path(".")

    hashes_path = repo_root / "spec" / "SECTION_HASHES.json"
    if not hashes_path.exists():
        print("ERROR: spec/SECTION_HASHES.json not found", file=sys.stderr)
        return 2

    data = json.loads(hashes_path.read_text(encoding="utf-8"))
    default_src_rel = data.get("source_file")
    if not default_src_rel:
        print("ERROR: source_file missing in SECTION_HASHES.json", file=sys.stderr)
        return 2

    default_src_path = repo_root / default_src_rel
    if not default_src_path.exists():
        print(f"ERROR: source_file not found: {default_src_rel}", file=sys.stderr)
        return 2

    algo_raw = data.get("hash_algorithm")
    if not isinstance(algo_raw, str) or not algo_raw.strip():
        print(
            "ERROR: missing required hash_algorithm in SECTION_HASHES.json "
            "(expected one of: sha256, sha3-256)",
            file=sys.stderr,
        )
        return 2
    algo = algo_raw.strip().lower()
    if algo not in {"sha256", "sha3-256"}:
        print(f"ERROR: unsupported hash_algorithm: {algo}", file=sys.stderr)
        return 2

    headings = data.get("section_headings", {})
    expected = data.get("sections", {})
    section_sources = data.get("section_sources", {})
    if not isinstance(headings, dict) or not isinstance(expected, dict):
        print("ERROR: invalid SECTION_HASHES.json structure", file=sys.stderr)
        return 2
    if section_sources and not isinstance(section_sources, dict):
        print("ERROR: invalid section_sources in SECTION_HASHES.json", file=sys.stderr)
        return 2

    source_cache: dict[str, str] = {
        default_src_rel: default_src_path.read_text(encoding="utf-8", errors="strict")
    }

    failures = 0
    for key, heading in headings.items():
        exp = expected.get(key)
        if not exp:
            print(f"ERROR: missing expected hash for section key: {key}", file=sys.stderr)
            failures += 1
            continue

        src_rel = section_sources.get(key, default_src_rel)
        if src_rel not in source_cache:
            src_path = repo_root / src_rel
            if not src_path.exists():
                print(f"ERROR: source_file not found for {key}: {src_rel}", file=sys.stderr)
                failures += 1
                continue
            source_cache[src_rel] = src_path.read_text(encoding="utf-8", errors="strict")

        try:
            chunk = extract_section(source_cache[src_rel], heading)
        except Exception as e:
            print(f"ERROR: cannot extract {key} from {src_rel}: {e}", file=sys.stderr)
            failures += 1
            continue

        payload = chunk.encode("utf-8")
        if algo == "sha3-256":
            got = sha3_256_hex(payload)
        else:
            got = sha256_hex(payload)
        if got != exp:
            print(f"FAIL: section {key} hash mismatch", file=sys.stderr)
            print(f"  heading:   {heading}", file=sys.stderr)
            print(f"  expected:  {exp}", file=sys.stderr)
            print(f"  got:       {got}", file=sys.stderr)
            failures += 1

    if failures:
        return 1

    # Governance merge gate (AM-02): if pinned section hashes change, formal disposition must be updated.
    # Spec CI checks out rubin-protocol tooling; use its in-repo rubin-formal mirror coverage registry.
    formal_cov = repo_root / "rubin-protocol" / "rubin-formal" / "proof_coverage.json"
    if formal_cov.exists():
        try:
            formal_data = json.loads(formal_cov.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"ERROR: cannot parse formal proof_coverage.json: {e}", file=sys.stderr)
            return 2
        formal_exp = formal_data.get("spec_section_hashes_sha3_256")
        if not isinstance(formal_exp, str) or not formal_exp.strip():
            print(
                "FAIL: formal disposition missing spec_section_hashes_sha3_256 "
                f"in {formal_cov.as_posix()}",
                file=sys.stderr,
            )
            return 1
        spec_got = sha3_256_hex_lf_normalized_bytes(hashes_path.read_bytes())
        if formal_exp != spec_got:
            print("FAIL: formal disposition out of date for spec/SECTION_HASHES.json", file=sys.stderr)
            print(f"  expected(formal): {formal_exp}", file=sys.stderr)
            print(f"  got(spec):        {spec_got}", file=sys.stderr)
            print(
                "  fix: update rubin-formal proof_coverage.json field spec_section_hashes_sha3_256 "
                "to match current spec/SECTION_HASHES.json",
                file=sys.stderr,
            )
            return 1

    print("OK: SECTION_HASHES.json matches pinned sections.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

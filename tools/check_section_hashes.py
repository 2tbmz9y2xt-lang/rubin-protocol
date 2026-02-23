#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def normalize_lf(s: str) -> str:
    return s.replace("\r\n", "\n").replace("\r", "\n")


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
    src_rel = data.get("source_file")
    if not src_rel:
        print("ERROR: source_file missing in SECTION_HASHES.json", file=sys.stderr)
        return 2

    src_path = repo_root / src_rel
    if not src_path.exists():
        print(f"ERROR: source_file not found: {src_rel}", file=sys.stderr)
        return 2

    algo = str(data.get("hash_algorithm", "sha256")).lower()
    if algo != "sha256":
        print(f"ERROR: unsupported hash_algorithm: {algo}", file=sys.stderr)
        return 2

    md = src_path.read_text(encoding="utf-8", errors="strict")
    headings = data.get("section_headings", {})
    expected = data.get("sections", {})
    if not isinstance(headings, dict) or not isinstance(expected, dict):
        print("ERROR: invalid SECTION_HASHES.json structure", file=sys.stderr)
        return 2

    failures = 0
    for key, heading in headings.items():
        exp = expected.get(key)
        if not exp:
            print(f"ERROR: missing expected hash for section key: {key}", file=sys.stderr)
            failures += 1
            continue

        try:
            chunk = extract_section(md, heading)
        except Exception as e:
            print(f"ERROR: cannot extract {key}: {e}", file=sys.stderr)
            failures += 1
            continue

        got = sha256_hex(chunk.encode("utf-8"))
        if got != exp:
            print(f"FAIL: section {key} hash mismatch", file=sys.stderr)
            print(f"  heading:   {heading}", file=sys.stderr)
            print(f"  expected:  {exp}", file=sys.stderr)
            print(f"  got:       {got}", file=sys.stderr)
            failures += 1

    if failures:
        return 1

    print("OK: SECTION_HASHES.json matches canonical sections.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


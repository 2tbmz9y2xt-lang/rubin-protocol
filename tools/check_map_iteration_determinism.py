#!/usr/bin/env python3
"""
CI lint: detect non-deterministic map iteration in consensus-critical paths.

Go: `for ... := range <map>` in consensus packages without subsequent sort.
Rust: direct `.iter()` / `.keys()` / `.values()` on HashMap in consensus crate
      (BTreeMap is deterministic and allowed).

Exit 0 = clean, Exit 1 = violations found.

Refs: Q-CI-TXCTX-EXTID-LINT-01, SPEC-TXCTX-01 §5.2 ext_id ordering.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# --- Go consensus packages ---
GO_CONSENSUS_DIRS = [
    REPO_ROOT / "clients" / "go" / "consensus",
]

# Allowlist: files where map iteration is known-safe (e.g. test helpers,
# non-consensus paths, or iteration followed by immediate sort).
GO_ALLOWLIST = {
    # txcontext.go collects into map then sorts — the range is safe
    # because the sorted slice is what gets used downstream.
    "txcontext.go:collectTxContextExtIDs",
}

# Pattern: `for <var> := range <identifier>` where identifier is NOT a slice/array
# Heuristic: we flag `range <name>` where <name> was declared as map[...].
GO_MAP_DECL_RE = re.compile(
    r"^\s*(\w+)\s*:?=\s*(?:make\()?map\[", re.MULTILINE
)
GO_RANGE_RE = re.compile(
    r"for\s+\w+(?:\s*,\s*\w+)?\s*:?=\s*range\s+(\w+)"
)

# --- Rust consensus crate ---
RUST_CONSENSUS_DIRS = [
    REPO_ROOT / "clients" / "rust" / "crates" / "rubin-consensus" / "src",
]

# Allowlist for Rust
RUST_ALLOWLIST = {
    # TxContextBundle.continuing is HashMap but only accessed via .get() —
    # sorted_ext_ids() provides the deterministic view.
    "txcontext.rs:sorted_ext_ids",
}

RUST_HASHMAP_ITER_RE = re.compile(
    r"HashMap.*\.(iter|keys|values|into_iter)\s*\("
    r"|\.iter\(\).*HashMap"
)

# Also catch `for ... in <hashmap_var>` patterns
RUST_FOR_HASHMAP_RE = re.compile(
    r"for\s+.*\s+in\s+(\w+)\.(iter|keys|values|into_iter)\s*\("
)


def check_go(violations: list[str]) -> None:
    for d in GO_CONSENSUS_DIRS:
        if not d.exists():
            continue
        for gofile in sorted(d.glob("*.go")):
            if gofile.name.endswith("_test.go"):
                continue
            text = gofile.read_text(encoding="utf-8")
            # Find all map declarations
            map_vars = set()
            for m in GO_MAP_DECL_RE.finditer(text):
                map_vars.add(m.group(1))
            if not map_vars:
                continue
            # Find range over map vars
            for line_no, line in enumerate(text.splitlines(), 1):
                rm = GO_RANGE_RE.search(line)
                if rm and rm.group(1) in map_vars:
                    loc = f"{gofile.name}:{line_no}"
                    # Check allowlist
                    func_name = _go_enclosing_func(text, line_no)
                    key = f"{gofile.name}:{func_name}" if func_name else loc
                    if key in GO_ALLOWLIST:
                        continue
                    violations.append(
                        f"Go: {gofile.relative_to(REPO_ROOT)}:{line_no}: "
                        f"non-deterministic range over map var '{rm.group(1)}' "
                        f"(in {func_name or 'unknown func'})"
                    )


def _go_enclosing_func(text: str, target_line: int) -> str | None:
    """Find the Go function name enclosing a given line number."""
    func_re = re.compile(r"^func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(")
    current_func = None
    for line_no, line in enumerate(text.splitlines(), 1):
        m = func_re.match(line)
        if m:
            current_func = m.group(1)
        if line_no == target_line:
            return current_func
    return current_func


def check_rust(violations: list[str]) -> None:
    for d in RUST_CONSENSUS_DIRS:
        if not d.exists():
            continue
        for rsfile in sorted(d.rglob("*.rs")):
            # Skip test files
            if "/tests/" in str(rsfile) or rsfile.name.endswith("_test.rs"):
                continue
            text = rsfile.read_text(encoding="utf-8")
            # Find HashMap declarations (field or let binding)
            hashmap_vars: set[str] = set()
            for line in text.splitlines():
                # Field: `name: HashMap<...>`
                fm = re.search(r"(\w+)\s*:\s*HashMap\s*<", line)
                if fm:
                    hashmap_vars.add(fm.group(1))
                # Let binding: `let mut name = HashMap::...` or `let name: HashMap`
                lm = re.search(
                    r"let\s+(?:mut\s+)?(\w+)\s*(?::\s*HashMap|=\s*HashMap)", line
                )
                if lm:
                    hashmap_vars.add(lm.group(1))
            if not hashmap_vars:
                continue

            for line_no, line in enumerate(text.splitlines(), 1):
                # Check for direct iteration over hashmap vars
                for var in hashmap_vars:
                    if re.search(
                        rf"\b{re.escape(var)}\s*\.\s*(iter|keys|values|into_iter)\s*\(",
                        line,
                    ):
                        loc = f"{rsfile.relative_to(REPO_ROOT)}:{line_no}"
                        func_name = _rust_enclosing_fn(text, line_no)
                        key = f"{rsfile.name}:{func_name}" if func_name else loc
                        if key in RUST_ALLOWLIST:
                            continue
                        violations.append(
                            f"Rust: {loc}: "
                            f"non-deterministic iteration over HashMap var '{var}' "
                            f"(in {func_name or 'unknown fn'})"
                        )


def _rust_enclosing_fn(text: str, target_line: int) -> str | None:
    """Find the Rust fn name enclosing a given line number."""
    fn_re = re.compile(r"^\s*(?:pub\s+)?(?:pub\(crate\)\s+)?fn\s+(\w+)")
    current_fn = None
    for line_no, line in enumerate(text.splitlines(), 1):
        m = fn_re.match(line)
        if m:
            current_fn = m.group(1)
        if line_no == target_line:
            return current_fn
    return current_fn


def main() -> int:
    violations: list[str] = []
    check_go(violations)
    check_rust(violations)
    if violations:
        print("FAIL: Non-deterministic map iteration in consensus paths:")
        for v in violations:
            print(f"  - {v}")
        print(f"\nTotal violations: {len(violations)}")
        print(
            "\nFix: use sorted keys/BTreeMap, or add to allowlist with justification."
        )
        return 1
    print("PASS: No non-deterministic map iteration found in consensus paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

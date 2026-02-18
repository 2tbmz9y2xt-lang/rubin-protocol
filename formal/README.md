# formal/

Formal-verification artifacts for RUBIN L1 v1.1.

**Toolchain: Lean 4** (`leanprover/lean4:v4.6.0`, to be pinned at production freeze)

## Contents

| File | Status | Description |
|------|--------|-------------|
| `RUBIN_FORMAL_APPENDIX_v1.1.md` | active | Toolchain rationale, invariant summary, CI plan, known gaps |
| `THEOREM_INDEX_v1.1.md` | active | Full invariant index — 14 theorems stated, 4 pending |
| `README.md` | this file | |

## Status

- Lean 4 proofs: **in progress** (local repo exists; minimum proofs started)
- All theorems in `THEOREM_INDEX_v1.1.md` have spec citations and conformance vector evidence
- T-004, T-005, T-007 are the **minimum required** for production freeze
- Formal repository (local-only, dev): `/Users/gpt/Documents/rubin-formal` (git commit `858db2833e7399adba1d5244222a60a62fb0b87f`)
- Formal repository (GitHub): `https://github.com/2tbmz9y2xt-lang/rubin-formal` (pinned commit in appendix)

## Controller decision

2026-02-16: `formal/` may remain a proof-less placeholder until production freeze,
provided invariants are fully stated with spec references and conformance vector mappings.
That condition is now met as of 2026-02-18.

Before production freeze: this file MUST be updated with a pinned commit to the
formal repository once T-004, T-005, T-007 are `lean4-proven`.

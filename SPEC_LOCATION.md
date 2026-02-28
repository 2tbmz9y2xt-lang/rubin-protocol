# RUBIN Spec Location

Canonical RUBIN specifications were moved to a private repository:

- `https://github.com/2tbmz9y2xt-lang/rubin-spec` (private)

This public repository contains implementation code, conformance fixtures/runner,
and formal verification toolchain only.

## Tooling with external spec root

Some tooling checks need canonical spec files (`RUBIN_L1_CANONICAL.md`, `SECTION_HASHES.json`,
`SPEC_CHANGELOG.md`) from the private spec repository.

Supported methods:

1) environment variable:

```bash
RUBIN_SPEC_ROOT=../rubin-spec-private/spec node scripts/check-section-hashes.mjs
RUBIN_SPEC_ROOT=../rubin-spec-private/spec node scripts/check-spec-invariants.mjs
RUBIN_SPEC_ROOT=../rubin-spec-private/spec python3 tools/check_conformance_ids.py
```

2) explicit flag:

```bash
node scripts/check-section-hashes.mjs --spec-root ../rubin-spec-private/spec
node scripts/check-spec-invariants.mjs --spec-root ../rubin-spec-private/spec
python3 tools/check_conformance_ids.py --spec-root ../rubin-spec-private/spec
```

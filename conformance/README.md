# Conformance (Go reference, Rust parity)

This directory contains machine-executable conformance fixtures and a runner that checks:

1) **Go as reference**: the Go client (`clients/go`) is the reference implementation for parity.
2) **Rust parity**: the Rust client (`clients/rust`) MUST match Go behavior for every executable gate.
3) **Spec compliance**: fixtures encode expected behavior derived from the normative spec; Go is also checked
   against fixture expectations to prevent “both clients drift together”.

Normative authority remains `spec/RUBIN_L1_CANONICAL.md` (consensus validity) and
`spec/RUBIN_COMPACT_BLOCKS.md` (normative P2P). This folder is a testing harness.

## Run

macOS/Homebrew note (operational):

```bash
export PATH=/opt/homebrew/bin:$PATH
```

Run full bundle:

```bash
python3 conformance/runner/run_cv_bundle.py
```

List gates:

```bash
python3 conformance/runner/run_cv_bundle.py --list-gates
```

Run a single gate:

```bash
python3 conformance/runner/run_cv_bundle.py --only-gates CV-COMPACT
```

## Coverage matrix

`conformance/MATRIX.md` is a generated coverage overview (gates/vectors/ops; local-only vs executable).

Regenerate:

```bash
python3 tools/gen_conformance_matrix.py
```

Check (CI):

```bash
python3 tools/gen_conformance_matrix.py --check
```

## Fixture governance (manual-only)

`clients/go/cmd/gen-conformance-fixtures` — **manual-only tool**.

Правила:

1. Генератор **НЕ** запускается из CI (ни в `ci.yml`, ни в других workflow).
2. Регенерация fixtures выполняется вручную локально через reproducible env:
   - `scripts/dev-env.sh -- bash -lc 'cd clients/go && go run ./cmd/gen-conformance-fixtures'`
3. Любое изменение `conformance/fixtures/CV-*.json` обязано сопровождаться обновлением
   `conformance/fixtures/CHANGELOG.md` (что изменили, зачем, каким инструментом).
4. Для точечных deterministic fixtures допускается отдельный генератор:
   - `scripts/dev-env.sh -- python3 tools/gen_cv_da_integrity.py`

Guard-проверка (CI):

```bash
python3 tools/check_conformance_fixtures_policy.py
```

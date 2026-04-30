# Conformance (Go reference, Rust parity)

This directory contains machine-executable conformance fixtures and a runner that checks:

1) **Go as reference**: the Go client (`clients/go`) is the reference implementation for parity.
2) **Rust parity**: the Rust client (`clients/rust`) MUST match Go behavior for every executable gate.
3) **Spec compliance**: fixtures encode expected behavior derived from the normative spec; Go is also checked
   against fixture expectations to prevent “both clients drift together”.

Normative authority remains `spec/RUBIN_L1_CANONICAL.md` (consensus validity) and
`spec/RUBIN_COMPACT_BLOCKS.md` (normative P2P). This folder is a testing harness.

## Run

Run all local commands via `scripts/dev-env.sh` (stable PATH/OpenSSL/Lean toolchain wiring):

Run full bundle:

```bash
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py
```

List gates:

```bash
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py --list-gates
```

Run a single gate:

```bash
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py --only-gates CV-COMPACT
```

## Coverage matrix

`conformance/MATRIX.md` is a generated coverage overview (gates/vectors/ops; local-only vs executable).

Regenerate:

```bash
scripts/dev-env.sh -- python3 tools/gen_conformance_matrix.py
```

Check (CI):

```bash
scripts/dev-env.sh -- python3 tools/gen_conformance_matrix.py --check
```

## Error expectation fields in vectors

Для большинства ops используется поле `expect_err`: это ожидаемый финальный код ошибки,
который вернёт runtime для данного вектора.

Для gate `CV-VALIDATION-ORDER` используется отдельное поле `expect_first_err`: это ожидаемый
**первый** код ошибки по deterministic-order симулятору (nested/conflict cases).  
Итоговый runtime-ошибочный код (`expect_err`) и `expect_first_err` могут отличаться по дизайну.

## Edge-pack baseline (critical domains)

`conformance/EDGE_PACK_BASELINE.json` фиксирует минимально требуемое edge-покрытие
по доменам:

- parse
- weight
- sighash
- covenants
- difficulty
- DA

Проверка (локально/CI):

```bash
scripts/dev-env.sh -- python3 tools/check_conformance_edge_pack.py
```

Gate падает если:

- отсутствует обязательный gate/fixture для домена;
- общее число векторов в домене ниже baseline;
- отсутствуют обязательные edge vector IDs из baseline.

## Fixture governance (manual-only)

`clients/go/cmd/gen-conformance-fixtures` — **manual-only tool**.

Правила:

1. Mutating-режим генератора **НЕ** запускается из CI (ни в `ci.yml`, ни в других workflow).
2. Регенерация fixtures выполняется вручную локально через reproducible env:
   - `scripts/dev-env.sh -- bash -lc 'cd clients/go && go run ./cmd/gen-conformance-fixtures'`
3. Любое изменение `conformance/fixtures/CV-*.json` обязано сопровождаться обновлением
   `conformance/fixtures/CHANGELOG.md` (что изменили, зачем, каким инструментом).
4. Для точечных deterministic fixtures допускается отдельный генератор:
   - `scripts/dev-env.sh -- python3 tools/gen_cv_da_integrity.py`

Guard-проверка (CI):

```bash
scripts/dev-env.sh -- python3 tools/check_conformance_fixtures_policy.py
```

### Check-only `--output-dir` mode

`gen-conformance-fixtures` поддерживает non-mutating режим: при передаче
абсолютного `--output-dir <path>` генератор пишет candidate fixtures
**только** под `<path>`, не трогая `conformance/fixtures/**`. Источник
данных по-прежнему читается из committed `conformance/fixtures/**`.

```bash
scripts/dev-env.sh -- bash -lc \
  'cd clients/go && go run ./cmd/gen-conformance-fixtures --output-dir /tmp/candidate-fixtures'
```

Свойства check-only режима:

- ML-DSA-87 ключи deterministic, embedded под `clients/go/cmd/gen-conformance-fixtures/testdata/keys/*.der`
  (committed conformance test material, не production keys);
- подпись через `(*consensus.MLDSA87Keypair).SignDigest32ForConformanceFixture`
  (FIPS 204 deterministic ML-DSA); package-level caller-grep guard
  в `consensus/openssl_signer_conformance_fixture_test.go` ограничивает
  использование этим генератором;
- два прогона с разными `--output-dir` дают **byte-identical** результат
  (`TestGenerator_DeterministicOutputDir`);
- `--output-dir` обязан быть абсолютным; запрет указывать committed
  `conformance/fixtures` или путь под ним;
- production signing path (`SignDigest32`, hedged ML-DSA) **не** меняется.

Использование: предусмотрено для будущей CI-only drift gate
(`Q-CONF-FIXTURE-DRIFT-CHECK-01`), которая сравнит candidate bytes
с committed bytes без мутации репо.

## Fuzz crash promotion (manual-only)

Nightly fuzz jobs are discovery jobs only. They upload crash artifacts and
metadata for manual triage; CI MUST NOT commit, push, regenerate fixtures, or
open issues automatically.

Each fuzz artifact bundle must include enough metadata to reproduce a crash:

- target name;
- seed, corpus, or crash artifact path;
- exact local command;
- commit SHA;
- workflow run id/attempt when produced by GitHub Actions.

Per-target metadata uses explicit path keys:

- Go metadata includes `corpus_path`, `artifacts_path`, and legacy `seed_path`.
  The Go fuzz engine stores committed corpus inputs and crash/minimized outputs
  under the same target directory, so all three keys point to
  `clients/go/<package>/testdata/fuzz/<FuzzTarget>/`.
- Rust metadata includes `corpus_path` for committed seed promotion and
  `artifacts_path` for crash artifacts under `clients/rust/fuzz/artifacts/`.

Manual promotion flow:

1. Download the failed workflow artifact and read its `run-metadata.env` plus the
   matching `<target>.metadata.env`.
   Metadata files are shell-quoted dotenv files, so they can be inspected as
   text or sourced by a local shell without executing command field contents.
   Go consensus fuzz files are uploaded directly under
   `clients/go/consensus/testdata/fuzz/**`. Go `node/p2p` fuzz files are in
   `.artifacts/fuzz-stage2/go-fuzz-testdata.tgz`; extract that archive before
   following a `clients/go/node/p2p/testdata/fuzz/<FuzzTarget>/` metadata path.
2. Reproduce the crash at the recorded commit SHA using the recorded command.
   For Go targets this is the `go test -run=^$ -fuzz=...` command under
   `clients/go`; for Rust targets this is the `cargo fuzz run ...` command under
   `clients/rust`.
3. Dedup before opening or updating an issue: check existing committed fuzz
   seeds/tests, open issues, and recent nightly failures for the same target and
   crash signature.
4. Promote only a reproduced protocol crash. Add the minimized input as a
   committed regression seed or a focused regression test in the target's normal
   test surface. Do not promote one-off infrastructure flakes.
5. Close the issue only after the PR contains either the committed seed/test that
   fails before the fix and passes after it, or explicit false-positive evidence
   explaining why no protocol regression exists.

Manual seed destinations:

- Go fuzz seeds: `clients/go/<package>/testdata/fuzz/<FuzzTarget>/`
- Rust fuzz seeds: `clients/rust/fuzz/corpus/<target>/`. That corpus directory
  is gitignored by default, so commit selected regression seeds with
  `git add -f clients/rust/fuzz/corpus/<target>/<seed-file>`.

Fuzz artifact upload alone is not a regression closeout. It is only triage
evidence until a human reproduction and seed/test promotion decision exists.

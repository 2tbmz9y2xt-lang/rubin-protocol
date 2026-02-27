# Conformance Fixtures Changelog

Этот файл фиксирует **осознанные** изменения `conformance/fixtures/CV-*.json`.

Policy:
- при любом изменении `CV-*.json` обновление этого файла обязательно;
- указывать причину, инструмент регенерации и список изменённых fixtures;
- генератор `clients/go/cmd/gen-conformance-fixtures` используется только вручную (не CI).

---

## 2026-02-27 — covenant_data cap + vault recursion hardening (Q-AUDIT-COV-01/Q-AUDIT-COV-06)

Причина:
- добавить wire-level cap `covenant_data_len <= 65_536` (норма CANONICAL §5.3) с reject как `TX_ERR_PARSE`;
- запретить vault recursion: tx, который тратит `CORE_VAULT`, не может создавать `CORE_VAULT` outputs.

Инструменты:
- `clients/go/cmd/gen-conformance-fixtures` (manual run) — обновление tx_hex/подписей для затронутых векторов,
- `tools/formal/gen_lean_conformance_vectors.py` + `tools/formal/gen_lean_refinement_from_traces.py` — синхронизация Lean replay.

Изменённые fixtures:
- `CV-HTLC.json`
- `CV-SUBSIDY.json`
- `CV-UTXO-BASIC.json`
- `CV-VAULT.json`

## 2026-02-25 — PR #161 (Q-R017)

Причина:
- перенос end-to-end `verify_sig` на OpenSSL path (Go/Rust parity),
- обновление witness/fixtures под executable conformance после wiring spend-verify.

Инструменты:
- `clients/go/cmd/gen-conformance-fixtures` (manual run),
- `tools/gen_cv_da_integrity.py` (manual deterministic update),
- ручная сверка через `conformance/runner/run_cv_bundle.py`.

Изменённые fixtures:
- `CV-DA-INTEGRITY.json`
- `CV-HTLC.json`
- `CV-SUBSIDY.json`
- `CV-UTXO-BASIC.json`
- `CV-VAULT.json`

## 2026-02-25 — HTLC spec alignment (Q-HTLC-01/Q-HTLC-02)

Причина:
- синхронизация CANONICAL и `RUBIN_CORE_HTLC_SPEC.md` по HTLC creation constraints;
- фиксация error-priority: SLH activation gate (`suite_id=0x02` pre-activation) должен срабатывать
  до вызова `verify_sig(...)`.

Инструменты:
- ручное обновление `CV-HTLC.json`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-HTLC`.

Изменённые fixtures:
- `CV-HTLC.json` (добавлен `CV-HTLC-14`).

## 2026-02-25 — Consolidated relay/vault/htlc hardening coverage

Причина:
- добавить машинно-проверяемое покрытие для engineering-consolidation правил:
  - DA relay determinism (`CV-C-26..CV-C-31`);
  - vault deterministic policy cases (`CV-V-01..CV-V-06`);
  - HTLC ordering policy checks (`CV-H-Ordering`, `CV-H-Structural-first`).

Инструменты:
- ручное обновление fixtures,
- проверка через `conformance/runner/run_cv_bundle.py` (all gates / selective gates).

Изменённые fixtures:
- `CV-COMPACT.json`
- `CV-VAULT-POLICY.json` (new)
- `CV-HTLC-ORDERING.json` (new)

## 2026-02-25 — CV-WEIGHT baseline fixture

Причина:
- добавить отдельный gate `CV-WEIGHT` в общий conformance baseline;
- зафиксировать детерминированные векторы веса для `suite_id=0x00/0x01/0x02`, DA-size и anchor-bytes.

Инструменты:
- ручное добавление `conformance/fixtures/CV-WEIGHT.json`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-WEIGHT`.

Изменённые fixtures:
- `CV-WEIGHT.json` (new)

## 2026-02-26 — DA limit collision ordering vector

Причина:
- закрыть покрытие вектора “`MAX_DA_BATCHES_PER_BLOCK` в норме, но `sum_da_bytes` превышен”;
- зафиксировать приоритет ошибки: first-fail на этапе weight/DA-bytes (`BLOCK_ERR_WEIGHT_EXCEEDED`)
  до проверки cap по числу DA set (`BLOCK_ERR_DA_BATCH_EXCEEDED`).

Инструменты:
- ручное обновление `CV-VALIDATION-ORDER.json`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-VALIDATION-ORDER`.

Изменённые fixtures:
- `CV-VALIDATION-ORDER.json` (добавлен `CV-VO-05`)

## 2026-02-26 — Runner success-output checks for subsidy/connect ops

Причина:
- runner обязан сравнивать success-output для executable ops, иначе возможен silent drift;
- фиксируем parity и добавляем ожидаемые значения для `connect_block_basic` и `block_basic_check_with_fees`.

Инструменты:
- ручное обновление `CV-SUBSIDY.json`,
- ручное обновление `conformance/runner/run_cv_bundle.py`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-SUBSIDY`.

Изменённые fixtures:
- `CV-SUBSIDY.json` (обновлён `CV-SUB-01`, добавлен `CV-SUB-04`)

## 2026-02-26 — Witness Merkle odd-element vectors (promotion rule)

Причина:
- зафиксировать odd-element “promotion (carry-forward)” правило для witness merkle tree (CANONICAL §10.4.1)
  через executable conformance;
- предотвратить дрейф реализаций к “last-leaf duplication/self-pair” по привычке.

Инструменты:
- ручное обновление `CV-MERKLE.json`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-MERKLE`.

Изменённые fixtures:
- `CV-MERKLE.json` (добавлены `WITNESS-MERKLE-01..04`).

## 2026-02-26 — HTLC canonicalization: forbid preimage_len=0 at parse-time

Причина:
- CANONICAL + HTLC spec требуют `1 <= preimage_len <= MAX_HTLC_PREIMAGE_BYTES` для sentinel witness selector;
- фиксируем parse-time canonicalization, чтобы `preimage_len=0` не мог “перебить” error-priority
  относительно UTXO/cursor ошибок.

Инструменты:
- ручное обновление `CV-PARSE.json`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-PARSE`.

Изменённые fixtures:
- `CV-PARSE.json` (добавлен `PARSE-10`)

## 2026-02-27 — Wire-level cap: covenant_data_len upper bound

Причина:
- добавить conformance-вектор на новый wire-level cap `MAX_COVENANT_DATA_PER_OUTPUT`;
- предотвратить DoS-кейсы через сверхдлинные `covenant_data` при парсинге.

Инструменты:
- ручное обновление `CV-PARSE.json`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-PARSE`.

Изменённые fixtures:
- `CV-PARSE.json` (добавлен `PARSE-11`)

## 2026-02-27 — CORE_VAULT: запрет vault→vault рекурсии (circular-reference hardening)

Причина:
- `CORE_VAULT` spend не должен создавать новые `CORE_VAULT` outputs (упрощение модели сейфа, защита от циклов).

Инструменты:
- ручное обновление `CV-VAULT.json`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-VAULT`.

Изменённые fixtures:
- `CV-VAULT.json` (добавлен `VAULT-SPEND-08`)

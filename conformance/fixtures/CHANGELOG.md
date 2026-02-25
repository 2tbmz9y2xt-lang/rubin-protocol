# Conformance Fixtures Changelog

Этот файл фиксирует **осознанные** изменения `conformance/fixtures/CV-*.json`.

Policy:
- при любом изменении `CV-*.json` обновление этого файла обязательно;
- указывать причину, инструмент регенерации и список изменённых fixtures;
- генератор `clients/go/cmd/gen-conformance-fixtures` используется только вручную (не CI).

---

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

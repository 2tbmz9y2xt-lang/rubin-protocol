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

# Conformance Fixtures Changelog

Этот файл фиксирует **осознанные** изменения `conformance/fixtures/CV-*.json`.

Policy:
- при любом изменении `CV-*.json` обновление этого файла обязательно;
- указывать причину, инструмент регенерации и список изменённых fixtures;
- генератор `clients/go/cmd/gen-conformance-fixtures` используется только вручную (не CI).

---

## 2026-02-27 — covenant_data_len cap boundary (Q-AUDIT-COV-01)

Причина:
- зафиксировать consensus-critical cap: `covenant_data_len > 65536` MUST reject as `TX_ERR_PARSE`.

Инструменты:
- ручное обновление `CV-PARSE.json`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-PARSE`,
- синхронизация матрицы: `tools/gen_conformance_matrix.py`,
- синхронизация Lean-векторов: `tools/formal/gen_lean_conformance_vectors.py`.

Изменённые fixtures:
- `CV-PARSE.json` (добавлен `PARSE-11`).

## 2026-02-27 — ML-DSA digest-binding regression vector (Q-AUDIT-COV-03)

Причина:
- зафиксировать semantics `verify_sig` для ML-DSA: подпись валидна только для исходного `digest32`;
- при изменении байта в `tx_nonce` при неизменной witness подписи верификация MUST падать как `TX_ERR_SIG_INVALID`.

Инструменты:
- ручное обновление `CV-SIG.json`,
- расширение runner (`tx_hex_from` + `tx_hex_mutations`) для детерминированных байтовых мутаций без дублирования больших fixtures,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-SIG`.

Изменённые fixtures:
- `CV-SIG.json` (добавлен `CV-SIG-02c`).

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


## 2026-02-28 — Q-CONF-14 / Q-CONF-15 conformance edge vectors

Причина:
- закрыть conformance gap по `chunk_count=0` для DA commit на gate `CV-DA-INTEGRITY`;
- закрыть missing vectors для non-minimal CompactSize (`witness_count`, `da_payload_len`) и retarget floor (`target_new=0x01`) из follow-up к `Q-CONF-09`.

Инструменты:
- ручное обновление `CV-DA-INTEGRITY.json`, `CV-PARSE.json`, `CV-POW.json`;
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-DA-INTEGRITY,CV-PARSE,CV-POW`;
- обновление `conformance/MATRIX.md` через `tools/gen_conformance_matrix.py`.

Изменённые fixtures:
- `CV-DA-INTEGRITY.json` (добавлен `CV-DA-CHUNK-COUNT-ZERO`)
- `CV-PARSE.json` (добавлены `PARSE-14`, `PARSE-15`)
- `CV-POW.json` (добавлен `POW-10`)

## 2026-02-28 — Q-CF-19 SLH witness per-suite budget overflow vector

Причина:
- зафиксировать consensus hardening (вариант B) для per-suite SLH witness budget;
- исключить сценарий с oversized SLH witness payload внутри общего лимита `MAX_WITNESS_BYTES_PER_TX`.

Инструменты:
- ручное обновление `CV-PARSE.json`;
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-PARSE`.

Изменённые fixtures:
- `CV-PARSE.json` (добавлен `PARSE-16`)

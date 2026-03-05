# Conformance Fixtures Changelog

Этот файл фиксирует **осознанные** изменения `conformance/fixtures/CV-*.json`.

Policy:
- при любом изменении `CV-*.json` обновление этого файла обязательно;
- указывать причину, инструмент регенерации и список изменённых fixtures;
- генератор `clients/go/cmd/gen-conformance-fixtures` используется только вручную (не CI).

---

## 2026-03-05 — SLH de-integration conformance closeout (Q-SLH-DEINTEG-04)

Причина:
- закрыть хвосты после удаления `suite_id=0x02` из native consensus:
  - `CV-VAULT-UNKNOWN-SUITE-01` теперь фиксирует reject как non-native suite (`TX_ERR_SIG_ALG_INVALID`),
    а не parse-stage noncanonical;
  - `CV-U-EXT-02` больше не дублирует sentinel-кейс и проверяет pre-active non-native witness;
  - добавлены `CV-U-EXT-04` и `CV-U-EXT-05` для ACTIVE `CORE_EXT` profile:
    - non-native suite + `native_verify_sig` → `TX_ERR_SIG_ALG_INVALID`;
    - non-native suite + `verify_sig_ext_accept` → successful spend.

Инструменты:
- точечные правки fixtures (`tx_hex_from`/`tx_hex_mutations`, `core_ext_profiles`),
- проверка через `conformance/runner/run_cv_bundle.py`,
- синхронизация матрицы: `tools/gen_conformance_matrix.py`.

Изменённые fixtures:
- `CV-UTXO-BASIC.json`
- `CV-VAULT.json`

## 2026-03-03 — Sighash-byte canonicalization outcome rebaseline (Q-RFC-STEALTH-01)

Причина:
- после включения trailing `sighash_type` байта для известных native suites (на сегодня: только `ML-DSA`) parser canonicalization
  требует `sig_length = base_sig_len + 1` (CANONICAL §5.4/§7/§12);
- legacy fixtures без trailing byte начали детерминированно резаться на parse-stage как
  `TX_ERR_SIG_NONCANONICAL` до covenant/UTXO/business-rule веток;
- digest expectations в `CV-SIGHASH` изменились из-за обновлённого preimage (`u8(sighash_type)` включён в digest).

Инструменты:
- ручной rebaseline ожидаемых исходов в `CV-*` по текущей canonicalization семантике,
- пересчёт `CV-SIGHASH` digest через consensus CLI (Go/Rust parity),
- проверка через `conformance/runner/run_cv_bundle.py` (full bundle PASS).

Изменённые fixtures:
- `CV-MULTISIG.json`
- `CV-HTLC.json`
- `CV-PARSE.json`
- `CV-SIG.json`
- `CV-SIGHASH.json`
- `CV-SUBSIDY.json`
- `CV-UTXO-BASIC.json`
- `CV-VAULT.json`
- `CV-WEIGHT.json`

## 2026-03-03 — Stealth conformance coverage closure (Q-RFC-STEALTH-01-COVERAGE)

Причина:
- закрыть gap покрытия для `CORE_STEALTH` после merge RFC-356: добавить отдельный gate `CV-STEALTH`;
- зафиксировать parse/creation и spend-пути для `CORE_STEALTH`:
  - covenant_data length valid/invalid;
  - valid ML-DSA spend;
  - invalid suite (`TX_ERR_SIG_ALG_INVALID`);
  - one_time_key_id mismatch (`TX_ERR_SIG_INVALID`);
  - malformed stealth covenant_data on spend (`TX_ERR_COVENANT_TYPE_INVALID`);
  - reject unknown suite_id (`TX_ERR_SIG_ALG_INVALID`) без вызова verify.

Инструменты:
- базовые tx взяты из `CV-UTXO-BASIC` (`CV-U-06`, `CV-U-16`) через `tx_hex_from`/`tx_hex_mutations`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-STEALTH`,
- синхронизация матрицы: `tools/gen_conformance_matrix.py`.

Изменённые fixtures:
- `CV-STEALTH.json` (new)

## 2026-03-03 — Block-level limit vectors (Q-CONF-21)

Причина:
- закрыть gap по block-level лимитам из triage (F-CV-004/005/006):
  - реальные serialized-block векторы для `BLOCK_ERR_ANCHOR_BYTES_EXCEEDED` и
    `BLOCK_ERR_DA_BATCH_EXCEEDED`;
  - весовой лимит (`BLOCK_ERR_WEIGHT_EXCEEDED`) остаётся покрыт dedicated
    ordering-вектором `CV-VO-05` (DA-bytes cap first-fail).

Инструменты:
- детерминированная генерация block fixtures через Go consensus helpers (no random),
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-BLOCK-BASIC CV-VALIDATION-ORDER`.

Изменённые fixtures:
- `CV-BLOCK-BASIC.json` (added `CV-B-11`, `CV-B-12`)

## 2026-03-02 — Non-minimal WitnessItem CompactSize + burn-to-fee vectors (Q-CONF-16, Q-CONF-17)

Причина:
- F-SPEC-01-CV: закрепить что §7 step 1 (CompactSize minimality) применяется ко ВСЕМ CompactSize полям,
  включая `WitnessItem.pubkey_length` с unknown suite_id.
- F-SPEC-08-CV: закрепить что non-coinbase `output_count=0` (burn-to-fee) валиден на уровне
  UTXO validation (§5, §20 value conservation).

Инструменты:
- PARSE-17: ручное добавление (parse-only, no crypto),
- CV-U-19: генерация через `clients/go/cmd/gen-conformance-fixtures` (real ML-DSA witness),
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-PARSE CV-UTXO-BASIC`.

Изменённые fixtures:
- `CV-PARSE.json` (added `PARSE-17`)
- `CV-UTXO-BASIC.json` (added `CV-U-19`)

## 2026-03-02 — Flag-day / height-activation conformance gate (Q-ACT-FLAGDAY-03)

Причина:
- CANONICAL §23.2 изменён на flag-day (height-only activation): deployment ACTIVE iff `height >= activation_height`;
- version-bit signaling остаётся только как telemetry/readiness и **не влияет** на `consensus_active`.

Инструменты:
- ручное добавление fixtures,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-FLAGDAY`,
- синхронизация матрицы: `tools/gen_conformance_matrix.py`.

Изменённые fixtures:
- `CV-FLAGDAY.json` (new)

## 2026-03-02 — VAULT destination allowlist vector (Q-VAULT-ALLOWLIST-01)

Причина:
- CANONICAL tightened `CORE_VAULT` spends: destination covenant types are allowlisted (`{CORE_P2PK, CORE_MULTISIG, CORE_HTLC}`).
- Добавить regression вектор: даже если `CORE_EXT` output **находится** в vault whitelist, spend MUST reject как `TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED`.

Инструменты:
- локальная генерация `tx_hex` с реальными ML-DSA witness-подписями через Go consensus library (OpenSSL backend profile),
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-VAULT`.

Изменённые fixtures:
- `CV-VAULT.json` (added `VAULT-SPEND-ALLOWLIST-01`)

## 2026-03-01 — CORE_EXT genesis + pre-activation spend vectors (Q-SF-EXT-05)

Причина:
- зафиксировать genesis-known `CORE_EXT (0x0102)` creation constraints и pre-activation sentinel-only spend semantics (CANONICAL §14, §18.2).

Инструменты:
- ручное обновление fixtures,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-COVENANT-GENESIS CV-UTXO-BASIC`,
- синхронизация матрицы: `tools/gen_conformance_matrix.py`.

Изменённые fixtures:
- `CV-COVENANT-GENESIS.json` (добавлены `CV-COV-16..17`)
- `CV-UTXO-BASIC.json` (добавлены `CV-U-EXT-01..03`)

## 2026-03-01 — CORE_EXT pre-activation anyone-can-spend correction (Q-SF-EXT-09)

Причина:
- CANONICAL changed: `CORE_EXT` pre-ACTIVE spends are unconditional anyone-can-spend w.r.t. witness semantics
  (sentinel-only constraint removed).

Инструменты:
- ручное обновление `CV-UTXO-BASIC.json`,
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-UTXO-BASIC`.

Изменённые fixtures:
- `CV-UTXO-BASIC.json` (updated `CV-U-EXT-02` expected `ok=true`).

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
- фиксация error-priority: gate для unknown/non-native suite (`suite_id=0x02` как пример) должен срабатывать
  до вызова `verify_sig(...)` (и `verify_sig` MUST NOT be invoked).

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
- зафиксировать детерминированные векторы веса для `suite_id=0x00/0x01` и unknown suite (`suite_id=0x02` как пример),
  DA-size и anchor-bytes.

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

## 2026-02-28 — Q-CF-19 large unknown-suite witness item (parse-only)

Причина:
- зафиксировать что per-suite SLH witness budget не является консенсусным правилом (SLH не native suite);
- оставить wire-level правило: большой WitnessItem **ниже** `MAX_WITNESS_BYTES_PER_TX` parse-valid,
  а suite semantics — deferred.

Инструменты:
- ручное обновление `CV-PARSE.json`;
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-PARSE`.

Изменённые fixtures:
- `CV-PARSE.json` (добавлен `PARSE-16`)

## 2026-02-28 — Q-C1-1-CONFLICT-VECTOR unknown suite vs wrong-length

Причина:
- зафиксировать детерминированный приоритет ошибки для конфликта:
  unknown/non-native `suite_id` (`0x02` как пример) + witness item с неканоническими длинами.
- требование: `TX_ERR_SIG_ALG_INVALID` MUST win и `verify_sig` MUST NOT be invoked.

Инструменты:
- обновление `CV-HTLC-ORDERING.json`;
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-HTLC-ORDERING`.

Изменённые fixtures:
- `CV-HTLC-ORDERING.json` (добавлен `CV-H-UnknownSuite-WrongLength`)

## 2026-02-28 — SEM-001 non-native suite canonicality cleanup

Причина:
- после де-интеграции SLH как native suite: non-native suites трактуются как unknown (напр. `suite_id=0x02`)
  и не имеют fixed-length canonicality правила на parse-stage;
- `WEIGHT-03` фиксирует поведение weight для unknown suite через unknown sig_cost (без привязки к SLH константам).

Инструменты:
- обновление `CV-SIG.json`, `CV-WEIGHT.json`;
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-SIG,CV-WEIGHT`.

Изменённые fixtures:
- `CV-SIG.json` (добавлен `CV-SIG-02e`)
- `CV-WEIGHT.json` (обновлён `WEIGHT-03`: unknown suite contributes unknown `sig_cost`)

## 2026-03-01 — DET-001 SpendTx conflict precedence vector

Причина:
- зафиксировать явный приоритет `ValidateOutputAtCreation` (Section 18.4 step 2)
  над `TX_ERR_MISSING_UTXO` (step 3), когда обе ошибки присутствуют в одном `SpendTx`.

Инструменты:
- обновление `CV-UTXO-BASIC.json` (explicit mutated `tx_hex`);
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-UTXO-BASIC`.

Изменённые fixtures:
- `CV-UTXO-BASIC.json` (добавлен `CV-U-18`)

## 2026-03-01 — FB-001 Feature-Bits activation framework vectors

Причина:
- зафиксировать детерминированную семантику CANONICAL §23.2 (single-step boundary, state(h)=state(h_b), base-case, bit range).

Инструменты:
- новый gate `CV-FEATUREBITS`;
- проверка через `conformance/runner/run_cv_bundle.py --only-gates CV-FEATUREBITS`.

Изменённые fixtures:
- `CV-FEATUREBITS.json` (новый файл)

## 2026-03-03 — Q-CONF-22..30 pre-freeze conformance closeout

Причина:
- закрыть pre-freeze gaps из cross-audit по consensus error coverage и validation-order semantics;
- добавить отсутствующие HTLC refund-path сценарии (`TX_ERR_TIMELOCK_NOT_MET` + valid refund spend);
- добавить negative coverage для `CV-MULTISIG` (threshold fail, invalid key count, witness count mismatch, duplicate keys);
- синхронизировать `CV-SIGHASH` с нормативным кодом `TX_ERR_SIGHASH_TYPE_INVALID`;
- зафиксировать в docs различие `expect_err` vs `expect_first_err`.

Инструменты:
- точечное обновление `CV-SIGHASH.json`, `CV-HTLC.json`, `CV-MULTISIG.json`, `CV-UTXO-BASIC.json`;
- правки `CV-BLOCK-BASIC.json`, `CV-VALIDATION-ORDER.json`, `CV-FEATUREBITS.json`;
- проверка через `conformance/runner/run_cv_bundle.py` (таргетные gate + полный bundle);
- проверка matrix через `tools/gen_conformance_matrix.py --check`.

Изменённые fixtures:
- `CV-BLOCK-BASIC.json` (добавлен `CV-B-13` для `BLOCK_ERR_COINBASE_INVALID`)
- `CV-FEATUREBITS.json` (`CV-FB-09`: ожидаемый код `BLOCK_ERR_PARSE`)
- `CV-HTLC.json` (добавлены `CV-HTLC-16`, `CV-HTLC-17`)
- `CV-MULTISIG.json` (добавлены `CV-M-02..CV-M-05`)
- `CV-SIGHASH.json` (добавлен `CV-SIGHASH-TYPE-05`)
- `CV-UTXO-BASIC.json` (добавлен `CV-U-COINBASE-IMMATURE-03` с каноническим/валидным witness для `TX_ERR_COINBASE_IMMATURE`)
- `CV-VALIDATION-ORDER.json` (`CV-VO-04`: `TX_ERR_SIG_NONCANONICAL` вместо phantom-code)

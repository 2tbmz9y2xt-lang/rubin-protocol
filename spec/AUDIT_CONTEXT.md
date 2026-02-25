# AUDIT_CONTEXT.md

Статус: non-consensus / audit governance artifact.

## Назначение

Этот файл — единый реестр аудиторского контекста и бэклог открытых векторов, чтобы:

- не проходить повторно уже закрытые векторы;
- фиксировать принятые риски (accepted risk) как отдельные решения;
- держать единый список `OPEN`/`DONE` с ссылками на артефакты.

## Источники истины для triage

1. `spec/RUBIN_L1_CANONICAL.md` (консенсусные правила)
2. `spec/RUBIN_COMPACT_BLOCKS.md` (normative P2P)
3. `spec/RUBIN_NETWORK_PARAMS.md` (reference summary; CANONICAL prevails)
4. `../inbox/QUEUE.md` (операционный статус задач)
5. `../inbox/reports/*.md` (подробные отчёты и решения)

## Formal proof-pack (informational)

- Lean4 proof-pack вендорится в `rubin-formal/` и входит в audit-pack как baseline (`proof_level=toy-model`; `status=proved` означает “proved in toy/model baseline”, а не байтовую/исполняемую эквивалентность CANONICAL).
- Freeze-ready claim для formal verification допускается только после byte-accurate/executable refinement поверх модельного baseline.
- Любые публичные/аудиторские формулировки должны следовать `rubin-formal/proof_coverage.json` (`claims.allowed[]` / `claims.forbidden[]`).

## Правило дедупликации finding’ов

Любой новый finding сначала маппится на один из статусов:

- `ALREADY_FIXED` — закрыт в коде/спеке;
- `ACCEPTED_RISK` — осознанно оставлен (с Risk ID);
- `OPEN` — требует реализации/спек-правки;
- `DEFERRED` — отложено до отдельного этапа.

Если finding уже имеет такой маппинг, повторный аудит не открывает новый тикет.

## Текущий open-backlog (на дату обновления)

Источник: external pack + верификация against `main`.

| ID | Статус | Кратко |
|---|---|---|
| F-03 | ALREADY_FIXED | End-to-end `verify_sig` (PQC подписи) реализован as-spec: OpenSSL EVP verify backend (Go reference + Rust parity) подключён в spend‑пути (`CORE_P2PK`/`CORE_MULTISIG`/`CORE_VAULT`/`CORE_HTLC`) и покрыт executable conformance (fixtures с реальными ML‑DSA подписями). См. `../inbox/reports/2026-02-25_report_q-r006_verify_sig_openssl_done.md`. |
| F-05 | ALREADY_FIXED | Coinbase bound теперь вызывается только из stateful `connect_block`-пути с локально вычисленным `sum_fees` (UTXO apply non-coinbase tx). `already_generated(h)` ведётся в chainstate-счётчике (in-memory reference). Персистентное хранилище chainstate (DB) требуется для “ноды”, но не влияет на консенсусную семантику и вынесено отдельно. |
| F-10 | ALREADY_FIXED | `RUBIN_L1_P2P_AUX.md` содержит минимальные `version`/`verack` поля (`tx_relay`, `pruned_below_height`) на которые ссылается COMPACT. |

## Верификация external multi-model audit (пункты 1–18)

Ниже — разбор утверждений из внешнего “комплексного аудита” (пункты 1–18) по факту текущего `main`.
Цель — отделить **намеренный дизайн / as-spec** от **реальных открытых дыр** и **неподтверждённых/устаревших** утверждений.

Сокращения:
- **Disposition**:
  - `INTENTIONAL` — намеренно и уже нормативно определено в спеке (as-spec).
  - `REAL` — воспроизводится в спеках/коде сейчас.
  - `FALSE` — не подтверждается текущими спеками/кодом (устарело/ошибка отчёта).
- **Статус** (как в triage): `OPEN` / `ALREADY_FIXED` / `ACCEPTED_RISK` / `DEFERRED` / `DOC_FIX`.

| # | Тезис внешнего аудита | Disposition | Статус | Пояснение / якорь |
|---:|---|---|---|---|
| 1 | DA bytes cap маппится на `BLOCK_ERR_WEIGHT_EXCEEDED` | INTENTIONAL | ALREADY_FIXED | Так задано в CANONICAL: `sum_da_bytes(B) ... иначе BLOCK_ERR_WEIGHT_EXCEEDED`. (`spec/RUBIN_L1_CANONICAL.md:419`) |
| 2 | HTLC claim допускает `preimage_len = 0` (нет нижней границы) | REAL | ALREADY_FIXED | Контроллер одобрил консенсусное ужесточение (2026-02-24): `preimage_len MUST be >= 1`. Синхронизировано: spec + Go/Rust + conformance (`CV-HTLC-11`). |
| 3 | HTLC refund: `lock_value = 0` при HEIGHT делает refund немедленным | REAL | ALREADY_FIXED | Контроллер одобрил консенсусное ужесточение (2026-02-24): `lock_value MUST be > 0` (creation rule). Синхронизировано: spec + Go/Rust + conformance (`CV-HTLC-12`). |
| 4 | Witness cursor model не имеет formal proof-pack в репо | FALSE | ALREADY_FIXED | Proof-pack baseline вендорится в `rubin-formal/` и синхронизирован через `tools/check_formal_coverage.py` + CI job `formal`. (`spec/README.md`, `.github/workflows/ci.yml`) |
| 5 | SLH-DSA плохо сочетается с multisig из-за лимита witness bytes | REAL | ALREADY_FIXED | Ограничение явно зафиксировано operational note в `CORE_MULTISIG` semantics (non-consensus), с рекомендацией ML-DSA default и SLH как fallback. (`spec/RUBIN_L1_CANONICAL.md` §14.2) |
| 6 | `batch_sig` до 64KB — unverified blob (DoS) | INTENTIONAL | ALREADY_FIXED | CANONICAL прямо запрещает L1 проверять `batch_sig`; размер ограничен 65,536. (`spec/RUBIN_L1_CANONICAL.md:205`, `:225`) |
| 7 | CORE_VAULT fee-preservation может требовать non-VAULT input | INTENTIONAL | ALREADY_FIXED | Это нормативно описано как “fee must be funded by non-VAULT inputs”. (`spec/RUBIN_L1_CANONICAL.md:880`) |
| 8 | В BlockHeader нет height | INTENTIONAL | ALREADY_FIXED | Height — функция положения в цепи; есть coinbase height-commitment (`locktime = h`). (`spec/RUBIN_L1_CANONICAL.md:426`, `:1054`) |
| 9 | MTP-only timestamp манипулируем (multi-window) | INTENTIONAL | ACCEPTED_RISK | Зафиксировано как `ACCEPTED_RISK_TS_MTP_MULTIWINDOW`. (`spec/RUBIN_L1_CANONICAL.md:1347`, `spec/AUDIT_CONTEXT.md:67`) |
| 10 | Термины DA set/batch/payload непоследовательны | FALSE | ALREADY_FIXED | CANONICAL даёт явные определения и норму “используем DA set для консенсуса”. (`spec/RUBIN_L1_CANONICAL.md:30`) |
| 11 | Ретаргет требует 320-bit/arb-precision, но нет coverage на overflow-края | REAL | ALREADY_FIXED | CV-POW расширен boundary-векторами для floor/truncation и clamp-overflow (`POW-03C`, `POW-03D`, `POW-08A`), выполняется в Go↔Rust parity через `retarget_v1` op. (`conformance/fixtures/CV-POW.json`) |
| 12 | `output_count = 0` не запрещён | INTENTIONAL | ALREADY_FIXED | Sighash задаёт `SHA3-256(\"\")` для `output_count=0`. (`spec/RUBIN_L1_CANONICAL.md:604`) |
| 13 | Feature-bit framework не полностью специфицирован | FALSE | ALREADY_FIXED | FSM `DEFINED→STARTED→LOCKED_IN→ACTIVE/FAILED` описан. (`spec/RUBIN_L1_CANONICAL.md:1402`, `:1425`) |
| 14 | SLH suite до активации может “залочить” funds | FALSE | ALREADY_FIXED | Creation rules гейтят `suite_id=0x02` по высоте. (`spec/RUBIN_NETWORK_PARAMS.md:132`, `clients/go/consensus/covenant_genesis.go:21`) |
| 15 | Непоследовательный стиль перекрёстных ссылок | REAL | ALREADY_FIXED | HTLC spec нормализован на единый формат ссылок `RUBIN_L1_CANONICAL.md §N`; смешанный стиль в audit-critical участках устранён. (`spec/RUBIN_CORE_HTLC_SPEC.md`) |
| 16 | CV-HTLC-10 описан как “unknown spend path (suite_id=0x02)” | REAL | ALREADY_FIXED | Формулировка исправлена на корректную семантику `path_id ∉ {0x00,0x01}` без изменения fixture semantics. (`spec/RUBIN_CORE_HTLC_SPEC.md` §8) |
| 17 | `da_id` uniqueness только per-block, reuse across blocks разрешён | INTENTIONAL | ALREADY_FIXED | Явно задано в CANONICAL. (`spec/RUBIN_L1_CANONICAL.md:1309`) |
| 18 | Нет опубликованных точных genesis bytes/allocations | REAL | DEFERRED | Это не “дыра спеки”, а chain-instance артефакт для Phase‑0 devnet (genesis bytes → `chain_id`). **Пока мы на стадии “только спека” — genesis НЕ генерим и НЕ дефолтим.** Генерация/публикация делается только непосредственно перед devnet bring‑up по коду (иначе будут несогласованные `chain_id`). До devnet bring‑up это считается roadmap-only (не поднимать и не заводить тикеты). Процедура и артефакты: `spec/DEVNET_GENESIS_PUBLISH.md`. (`spec/RUBIN_L1_CANONICAL.md:587`, `spec/RUBIN_NETWORK_PARAMS.md:101`) |

## Already fixed (из прошлых аудитов)

| ID | Статус | Что закрыто |
|---|---|---|
| F-01 | ALREADY_FIXED | `tx_kind` расширен до `{0x00,0x01,0x02}` в Go/Rust парсерах; DA tx-path валиден |
| F-02 | ALREADY_FIXED | Добавлены и заведены `BLOCK_ERR_DA_*` коды в Go/Rust |
| F-DA-ALIGN-01 | ALREADY_FIXED | DA приведён к CANONICAL: `tx_kind=0x01` разрешает manifest в `da_payload`, `DaCommitCoreFields` расширен, payload commitment проверяется через `CORE_DA_COMMIT` output exactly-once; синхронизированы Go(reference)→Rust(parity)→conformance (`CV-DA-INTEGRITY`). (`Q-DA-ALIGN-01 DONE`, см. `../inbox/reports/2026-02-25_report_q-da-align-01_canonical_da_sync.md`) |
| F-03 | ALREADY_FIXED | End-to-end `verify_sig` (Go reference + Rust parity) закрыт как as-spec (CANONICAL §12.1): spend‑путь выполняет реальную PQC крипто‑верификацию через OpenSSL EVP; conformance bundle PASS с валидными ML‑DSA witness items. См. `../inbox/reports/2026-02-25_report_q-r006_verify_sig_openssl_done.md`. |
| F-04 | ALREADY_FIXED | Timestamp/MTP wired в реальный block validation path (Go/Rust) |
| F-08 | ALREADY_FIXED | `RUBIN_NETWORK_PARAMS.md` синхронизирован с CANONICAL по P2PK suite-gating (ML-DSA + SLH post-activation) |
| F-09 | ALREADY_FIXED | Восстановлен `spec/AUDIT_CONTEXT.md`; ссылка из `spec/README.md` больше не битая |
| F-06 | ALREADY_FIXED (audit hygiene) | В исторических отчётах добавлены explicit pointers на актуальный addendum и authoritative `main`-status, исключая повторный triage по устаревшим SHA-привязкам |
| F-07 | ALREADY_FIXED (audit hygiene) | В external-pack добавлен актуальный coverage-boundary и статус-дельта для executable vs local ops, чтобы не трактовать local ops как “full consensus coverage” |
| F-11 | ALREADY_FIXED | DoS hardening по orphan pool выполнен (storm-mode + rollback triggers + conformance vectors; `P2P-04 DONE`) |
| F-12 | ALREADY_FIXED (ops hygiene) | Добавлен operational reproducibility note в `spec/README.md` (PATH/tooling prerequisites) |
| F-14 | ALREADY_FIXED | `RUBIN_NETWORK_PARAMS.md` разделяет consensus-critical и relay/operational параметры через колонку `Class` |
| F-13 | ALREADY_FIXED | Добавлен executable gate `conformance/fixtures/CV-SIG.json`; CANONICAL §12.2 синхронизирован с текущим machine-executable покрытием |
| Q-V04 | ALREADY_FIXED | CORE_VAULT “2FA replacement” без версионности: новый wire+семантика (owner binding через `owner_lock_id`, owner-only fee inputs, one-vault-per-tx, `sum_out >= sum_in_vault`) + новые `TX_ERR_VAULT_*` коды + conformance gate `CV-VAULT`. См. `../inbox/reports/2026-02-25_report_q-v04_core_vault_2fa_replacement_done.md`. |

## Зафиксированные accepted risks

| Risk ID | Статус | Где зафиксировано |
|---|---|---|
| `ACCEPTED_RISK_TS_MTP_MULTIWINDOW` | ACCEPTED_RISK | `RUBIN_L1_CANONICAL.md` §22 (timestamp security note) |
| `ACCEPTED_RISK_FIPS_PROVIDER_NOT_YET_CERTIFIED` | ACCEPTED_RISK | `RUBIN_CRYPTO_BACKEND_PROFILE.md` §4 (FIPS positioning) |

Пояснение `ACCEPTED_RISK_FIPS_PROVIDER_NOT_YET_CERTIFIED`:
- Риск: в репозитории зафиксирован “direct FIPS migration path via OpenSSL providers”, но **FIPS-validated PQC module**
  (FIPS provider с ML-DSA/SLH-DSA) ещё не доступен/не включён как обязательное требование для запуска узлов.
- Факт на текущих dev-машинах/CI может выглядеть так: PQC доступна в `default` provider, а `fips` provider отсутствует
  (нет `fips.*` модуля), либо присутствует, но требует отдельной конфигурации и preflight.
- Импакт: “FIPS-only mode” пока нельзя объявлять как поддерживаемый режим для узла без воспроизводимой проверки
  доступности ML-DSA/SLH-DSA в FIPS provider и строгого соответствия conformance (semantics identical).
- Митигация: до появления/внедрения FIPS provider мы работаем в `default` provider и держим требования в формулировке
  “NIST/FIPS-aligned”. Переход в “FIPS-only mode” возможен только после CI‑подтверждения и опубликованного runbook/preflight.

## Правило обновления

При каждом закрытии open-вектора:

1. Обновить строку в `../inbox/QUEUE.md`.
2. Добавить/обновить отчёт в `../inbox/reports/`.
3. Синхронизировать статус здесь (перенос из open-backlog в `ALREADY_FIXED`/`ACCEPTED_RISK`/`DEFERRED`).

Это обязательный шаг перед меткой “freeze-ready”.

## Full Deep Audit (2026-02-25) — 6-agent pass

Results from 6-domain parallel audit. Report: `../inbox/reports/2026-02-25_report_full_deep_audit.md`

### Findings confirmed ALREADY_FIXED during this audit session

| Finding | Fixed by |
|---|---|
| F-CON-001: Covenant activation cursor semantics | Q-C048 DONE |
| F-CON-002: Vault value rule §14.1 vs §20 ordering | Q-C049 DONE |
| F-CON-003: Arithmetic 320-bit semantics | Q-C049 DONE |
| F-P2P-01/03: MB/s unit ambiguity | P2P-05 DONE |
| F-P2P-06: Short_id collision threshold | P2P-07 DONE |
| WitnessSlots Go/Rust divergence | Q-R018, Q-R019 DONE |
| HTLC preimage_len=0 / lock_value=0 creation flaws | Q-C047 DONE |

### New OPEN findings (2026-02-25 audit)

| Q-ID | Severity | Finding |
|---|---|---|
| Q-SEC-01 | HIGH | PQ key size not validated in verify_sig() before OpenSSL (ML-DSA=2592B, SLH-DSA=64B) |
| Q-CONF-07 | CRITICAL | DA chunk_count=0 spec text §5.2 vs §21.3 contradiction + missing conformance vector |
| Q-CONF-08 | CRITICAL | SLH-DSA activation boundary: 3 conformance vectors missing at height=1,000,000 |
| Q-CONF-09 | HIGH | Batch conformance gaps: vault arithmetic, replay nonce, retarget min, CompactSize, cursor |
| Q-CODE-01 | HIGH | JSON CLI PascalCase (Go) vs snake_case (Rust) — parity bug in field naming |
| Q-CODE-02 | MEDIUM | DA unit test coverage: 0 DA-specific unit tests in Go+Rust clients |
| Q-TOOLING-02 | MEDIUM | make_audit_pack.py uses str\|None syntax (Python 3.10+), fails on Python 3.9 |
| Q-TOOLING-03 | HIGH | check_section_hashes.py: unsafe SHA256 fallback if hash_algorithm field missing |
| Q-TOOLING-04 | HIGH | spec-checks.yml: no-op smoke test (echo only), no real spec validation |
| Q-TOOLING-05 | HIGH | gen_conformance_matrix.py: no fixture schema/completeness validation |
| Q-SPEC-02 | MEDIUM | Batch spec gaps: coinbase maturity §17, target endianness §10.3, feature-bit stall, P2P version mismatch |
| Q-HYGIENE-01 | LOW | clients/rust/.DS_Store committed to git |

### Status for F-P2P-02 (Orphan TTL under storm mode)

Partially addressed by P2P-04 DONE (storm-mode triggers, commit-first bias) and Q-C050 DONE (relay determinism clarifications). The specific interaction of DA_ORPHAN_TTL_BLOCKS with storm-mode eviction order and wall-clock vs block-based 60s timer was clarified in Q-C050. Status: **PARTIALLY_ADDRESSED** — no remaining OPEN task; acceptable for Phase-0.

## Tracked completion reports (auto-triage exclusion list)

Отчёты ниже полностью закрыты и не требуют авто-triaging:

- `2026-02-22_report_cv_compact_execution_and_context_sync.md` — CV-COMPACT executable gate; linked Q-G013 DONE; remaining vectors (CV-C-02, CV-C-05..C-18) closed via Q-CONF-01.
- `2026-02-25_report_full_deep_audit.md` — comprehensive 6-agent audit; all ALREADY_FIXED findings triaged above; open findings tracked under Q-SEC-01, Q-CONF-07..09, Q-CODE-01..02, Q-TOOLING-02..05, Q-SPEC-02, Q-HYGIENE-01.

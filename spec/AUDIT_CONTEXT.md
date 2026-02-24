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

- Lean4 proof-pack вендорится в `rubin-formal/` и входит в audit-pack как baseline (`status=proved` на модельном уровне).
- Freeze-ready claim для formal verification допускается только после byte-accurate/executable refinement поверх модельного baseline.

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
| F-03 | ALREADY_FIXED | End-to-end `verify_sig` wired в executable spend path (Go/Rust) + conformance vectors (`Q-R006 DONE`, см. `../inbox/reports/2026-02-24_report_q-r006_f-03_closeout.md`). |
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
| 2 | HTLC claim допускает `preimage_len = 0` (нет нижней границы) | REAL | OPEN | В HTLC spec есть только `<= MAX`; в Go/Rust проверок `>= 1` нет. (`spec/RUBIN_CORE_HTLC_SPEC.md:115`, `clients/go/consensus/htlc.go:75`) **Консенсусное ужесточение ⇒ НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА.** |
| 3 | HTLC refund: `lock_value = 0` при HEIGHT делает refund немедленным | REAL | OPEN | Правило `block_height >= lock_value` делает `0` тривиально истинным. (`spec/RUBIN_CORE_HTLC_SPEC.md:161`, `clients/go/consensus/htlc.go:100`) **Консенсусное ужесточение ⇒ НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА.** |
| 4 | Witness cursor model не имеет formal proof-pack в репо | FALSE | ALREADY_FIXED | Proof-pack baseline вендорится в `rubin-formal/` и синхронизирован через `tools/check_formal_coverage.py` + CI job `formal`. (`spec/README.md`, `.github/workflows/ci.yml`) |
| 5 | SLH-DSA плохо сочетается с multisig из-за лимита witness bytes | REAL | ALREADY_FIXED | Ограничение явно зафиксировано operational note в `CORE_MULTISIG` semantics (non-consensus), с рекомендацией ML-DSA default и SLH как fallback. (`spec/RUBIN_L1_CANONICAL.md` §14.2) |
| 6 | `batch_sig` до 64KB — unverified blob (DoS) | INTENTIONAL | ALREADY_FIXED | CANONICAL прямо запрещает L1 проверять `batch_sig`; размер ограничен 65,536. (`spec/RUBIN_L1_CANONICAL.md:205`, `:225`) |
| 7 | CORE_VAULT fee-preservation может требовать non-VAULT input | INTENTIONAL | ALREADY_FIXED | Это нормативно описано как “fee must be funded by non-VAULT inputs”. (`spec/RUBIN_L1_CANONICAL.md:880`) |
| 8 | В BlockHeader нет height | INTENTIONAL | ALREADY_FIXED | Height — функция положения в цепи; есть coinbase height-commitment (`locktime = h`). (`spec/RUBIN_L1_CANONICAL.md:426`, `:1054`) |
| 9 | MTP-only timestamp манипулируем (multi-window) | INTENTIONAL | ACCEPTED_RISK | Зафиксировано как `ACCEPTED_RISK_TS_MTP_MULTIWINDOW`. (`spec/RUBIN_L1_CANONICAL.md:1347`, `spec/AUDIT_CONTEXT.md:67`) |
| 10 | Термины DA set/batch/payload непоследовательны | FALSE | ALREADY_FIXED | CANONICAL даёт явные определения и норму “используем DA set для консенсуса”. (`spec/RUBIN_L1_CANONICAL.md:30`) |
| 11 | Ретаргет требует 320-bit/arb-precision, но нет coverage на overflow-края | REAL | OPEN | Требование есть, но conformance требует расширения на boundary-продукты/транкейт. (`spec/RUBIN_L1_CANONICAL.md:997`, `conformance/fixtures/CV-POW.json:1`) |
| 12 | `output_count = 0` не запрещён | INTENTIONAL | ALREADY_FIXED | Sighash задаёт `SHA3-256(\"\")` для `output_count=0`. (`spec/RUBIN_L1_CANONICAL.md:604`) |
| 13 | Feature-bit framework не полностью специфицирован | FALSE | ALREADY_FIXED | FSM `DEFINED→STARTED→LOCKED_IN→ACTIVE/FAILED` описан. (`spec/RUBIN_L1_CANONICAL.md:1402`, `:1425`) |
| 14 | SLH suite до активации может “залочить” funds | FALSE | ALREADY_FIXED | Creation rules гейтят `suite_id=0x02` по высоте. (`spec/RUBIN_NETWORK_PARAMS.md:132`, `clients/go/consensus/covenant_genesis.go:21`) |
| 15 | Непоследовательный стиль перекрёстных ссылок | REAL | ALREADY_FIXED | HTLC spec нормализован на единый формат ссылок `RUBIN_L1_CANONICAL.md §N`; смешанный стиль в audit-critical участках устранён. (`spec/RUBIN_CORE_HTLC_SPEC.md`) |
| 16 | CV-HTLC-10 описан как “unknown spend path (suite_id=0x02)” | REAL | ALREADY_FIXED | Формулировка исправлена на корректную семантику `path_id ∉ {0x00,0x01}` без изменения fixture semantics. (`spec/RUBIN_CORE_HTLC_SPEC.md` §8) |
| 17 | `da_id` uniqueness только per-block, reuse across blocks разрешён | INTENTIONAL | ALREADY_FIXED | Явно задано в CANONICAL. (`spec/RUBIN_L1_CANONICAL.md:1309`) |
| 18 | Нет опубликованных точных genesis bytes/allocations | REAL | OPEN | Спека требует, чтобы сеть опубликовала exact genesis bytes для derivation `chain_id`, но репо не содержит chain-instance genesis pack. (`spec/RUBIN_L1_CANONICAL.md:587`, `spec/RUBIN_NETWORK_PARAMS.md:101`) |

## Already fixed (из прошлых аудитов)

| ID | Статус | Что закрыто |
|---|---|---|
| F-01 | ALREADY_FIXED | `tx_kind` расширен до `{0x00,0x01,0x02}` в Go/Rust парсерах; DA tx-path валиден |
| F-02 | ALREADY_FIXED | Добавлены и заведены `BLOCK_ERR_DA_*` коды в Go/Rust |
| F-03 | ALREADY_FIXED | End-to-end `verify_sig` wired (Go/Rust OpenSSL backend) + executable CV gate (`../inbox/reports/2026-02-24_report_q-r006_f-03_closeout.md`) |
| F-04 | ALREADY_FIXED | Timestamp/MTP wired в реальный block validation path (Go/Rust) |
| F-08 | ALREADY_FIXED | `RUBIN_NETWORK_PARAMS.md` синхронизирован с CANONICAL по P2PK suite-gating (ML-DSA + SLH post-activation) |
| F-09 | ALREADY_FIXED | Восстановлен `spec/AUDIT_CONTEXT.md`; ссылка из `spec/README.md` больше не битая |
| F-06 | ALREADY_FIXED (audit hygiene) | В исторических отчётах добавлены explicit pointers на актуальный addendum и authoritative `main`-status, исключая повторный triage по устаревшим SHA-привязкам |
| F-07 | ALREADY_FIXED (audit hygiene) | В external-pack добавлен актуальный coverage-boundary и статус-дельта для executable vs local ops, чтобы не трактовать local ops как “full consensus coverage” |
| F-11 | ALREADY_FIXED | DoS hardening по orphan pool выполнен (storm-mode + rollback triggers + conformance vectors; `P2P-04 DONE`) |
| F-12 | ALREADY_FIXED (ops hygiene) | Добавлен operational reproducibility note в `spec/README.md` (PATH/tooling prerequisites) |
| F-14 | ALREADY_FIXED | `RUBIN_NETWORK_PARAMS.md` разделяет consensus-critical и relay/operational параметры через колонку `Class` |
| F-13 | ALREADY_FIXED | Добавлен executable gate `conformance/fixtures/CV-SIG.json`; CANONICAL §12.2 синхронизирован с текущим machine-executable покрытием |

## Зафиксированные accepted risks

| Risk ID | Статус | Где зафиксировано |
|---|---|---|
| `ACCEPTED_RISK_TS_MTP_MULTIWINDOW` | ACCEPTED_RISK | `RUBIN_L1_CANONICAL.md` §22 (timestamp security note) |

## Правило обновления

При каждом закрытии open-вектора:

1. Обновить строку в `../inbox/QUEUE.md`.
2. Добавить/обновить отчёт в `../inbox/reports/`.
3. Синхронизировать статус здесь (перенос из open-backlog в `ALREADY_FIXED`/`ACCEPTED_RISK`/`DEFERRED`).

Это обязательный шаг перед меткой “freeze-ready”.

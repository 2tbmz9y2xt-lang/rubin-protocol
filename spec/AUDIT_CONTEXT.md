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
| F-03 | OPEN | Нет end-to-end crypto `verify_sig` в consensus path (задача `Q-R006`) |
| F-05 | OPEN | Coinbase subsidy bound (`subsidy + fees`) не вшит в block validation |
| F-10 | OPEN | COMPACT ссылается на `version`-поля, P2P_AUX не описывает их wire |

## Already fixed (из прошлых аудитов)

| ID | Статус | Что закрыто |
|---|---|---|
| F-01 | ALREADY_FIXED | `tx_kind` расширен до `{0x00,0x01,0x02}` в Go/Rust парсерах; DA tx-path валиден |
| F-02 | ALREADY_FIXED | Добавлены и заведены `BLOCK_ERR_DA_*` коды в Go/Rust |
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

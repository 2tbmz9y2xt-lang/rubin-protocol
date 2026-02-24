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
| F-06 | OPEN/INFO | Исторические freeze-ready SHAs в старых отчётах не совпадают с текущим HEAD |
| F-07 | OPEN/PARTIAL | Conformance содержит local ops, нужен явный label coverage-boundary |
| F-10 | OPEN | COMPACT ссылается на `version`-поля, P2P_AUX не описывает их wire |
| F-12 | OPEN/OPS | Воспроизводимость зависит от `PATH` (go/node вне базового PATH) |
| F-13 | OPEN | В CANONICAL есть `CV-SIG-*`, но нет gate/fixture `CV-SIG` |

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

# AUDIT CONTEXT — RUBIN PROTOCOL

Прикладывай этот файл к каждому аудит-сеансу вместе со спекой.

---

## KNOWN-CLOSED FINDINGS (не поднимать повторно)

Следующие проблемы уже исправлены в текущей версии спецификации.
Если видишь что-то похожее — сначала проверь текст явно, прежде чем репортить.

| # | Описание | Где проверить |
|---|---|---|
| KC-01 | `tx_count`: единственное правило — `tx_count MUST be >= 1`. НЕТ правила "MUST be 1". | CANONICAL §9, строка 546 |
| KC-02 | Parsing limits: все через `<=` (`MUST be <= MAX_TX_INPUTS` и т.д.). НЕТ "MUST equal MAX". | CANONICAL §7, строки 227-231 |
| KC-03 | VAULT fee-preservation: единственная формула `sum_out MUST be >= sum_in_vault` (три места). НЕТ конфликта == vs >=. | CANONICAL §14.1, §20 |
| KC-04 | `CORE_TIMELOCK` (0x0001): удалён, статус UNASSIGNED. | CANONICAL §14, NETWORK_PARAMS §10 |
| KC-05 | `CORE_HTLC` (0x0100): активен с genesis block 0. НЕ RESERVED. | CANONICAL §14, HTLC_SPEC §1 |
| KC-06 | `MAX_VAULT_KEYS = 12`, `MAX_MULTISIG_KEYS = 12`. | CANONICAL §4 |
| KC-07 | `MAX_DA_CHUNK_COUNT = 61` (derived constant: `floor(32_000_000 / 524_288)`). | CANONICAL §4 |
| KC-08 | DA commitment: ровно один `CORE_DA_COMMIT` output в DA commit tx. Явный reject при 0 или >1. | CANONICAL §21 |
| KC-09 | HTLC witness format: `spend_path_item` через canonical WitnessItem с `SUITE_ID_SENTINEL`. Wire согласован с §5.4. | HTLC_SPEC §5.1 |
| KC-10 | SLH-DSA gate в HTLC: присутствует в §5.2 rule 5 и §5.3 rule 5. | HTLC_SPEC §5.2, §5.3 |
| KC-11 | addU64 overflow: ошибки не игнорируются. | CANONICAL §20 |
| KC-12 | Clamped timestamps: `ts'` — чистая функция для §15, §22 без изменений. | CANONICAL §15 (Q-C013 OPEN, патч ещё не применён) |

---

## OPEN FINDINGS (уже в трекере — не дублировать, только уточнять)

| ID | Приоритет | Описание |
|---|---|---|
| Q-C013 | P1 | Clamped timestamps для retarget (§15) — патч ещё не применён |
| Q-C014 | P1 | CORE_P2PK потерял SLH-DSA spend path при рефакторинге — регрессия |
| Q-C015 | P1 | `chunk_count = 0` не запрещён — пустой DA-сет проходит парсинг |
| Q-C016 | P1 | Anchor byte limit: нет единой нормативной формулы (CORE_ANCHOR + CORE_DA_COMMIT) |
| Q-C017 | P2 | `verify_sig` вызовы в §14.1/14.2 используют 2-параметровый shorthand vs 4-параметровое определение в §12.1 |
| Q-C018 | P2 | `da_payload_len = 0` не запрещён для `tx_kind = 0x02` (пустой chunk) |
| Q-C019 | P2 | SLH playbook: отсутствуют численные SLO и rollback-триггеры |
| HTLC BUG-1 | HIGH | Порядок SLH gate в HTLC_SPEC §5.2/§5.3: gate должен быть до sig verify, а не после |
| HTLC BUG-2 | MEDIUM | CV-HTLC-10 описание некорректно (`suite_id = 0x02` вместо `path_id = 0x02`) |

---

## ИНСТРУКЦИЯ ДЛЯ АУДИТОРА

1. Перед тем как репортить находку — проверь таблицу KNOWN-CLOSED выше.
2. Перед тем как репортить находку — проверь таблицу OPEN: если уже есть, только уточни если видишь новое измерение.
3. Цитируй конкретную строку/секцию из файла, а не пересказывай по памяти.
4. Для каждой новой находки указывай: секцию, строку, точную цитату, почему это проблема, предложение фикса.

---

_Последнее обновление: 2026-02-23_

# Formal Audit Report

Date: 2026-02-16 (run 10:05:27)
Scope: `RUBIN_PROTOCOL_v1.0_MASTER_COMPLETE_MONOLITH.md` (каталоги `spec/`, `formal/`, `operational/` отсутствуют)

## Executive Summary
Спецификация содержит критические неопределенности в канонических байтовых представлениях (Tx/Block) и прямой конфликт по `anchor_commitment` (SHA3-256 vs SHA3). В текущем виде независимые реализации почти наверняка разойдутся по `txid`, `block_hash`, форк‑тайбрейку и/или правилам состояния, что является риском consensus‑split.

## Findings
- Конфликт хэша L2-якоря: `anchor_commitment = SHA3-256(anchor_data)` (Section II) vs `anchor_commitment = SHA3(anchor_data)` (Appendix O).
- Не определены wire-форматы базовых примитивов и правил каноничности: `CompactSize` (минимальность), `u32le` и общий байтовый порядок/диапазоны.
- Не определены структуры `inputs[]`, `outputs[]`, `Witness` и связанные консенсусные поля (outpoint/индексы/значения/ковенанты), хотя они используются в `Spent(T)`, `Created(T)`, расчете комиссий и `TxNoWitnessBytes(T)`.
- Не определены канонические байтовые входы хеширования/подписей: `TxNoWitnessBytes(T)`, `TxSigPreimage`, `BlockHeaderBytes(B)`, `template_serialization`, `anchor_data`, а также `signing_message` для RETL.
- Не определена схема заголовка блока (поля/порядок/размеры), но используются `block_hash`, `target(B)`, `b.version` (VERSION_BITS), а также упоминаются `timestamp/nonce/prev hash/merkle root` без формализации.
- Консенсус‑константы/функции не параметризованы: `Subsidy(h)` (и genesis), `START_HEIGHT`, `SIGNAL_WINDOW`, `THRESHOLD`, параметры PoW/difficulty update (кроме clamp-отношения), `MIN_RETL_BOND`, `chain_id`.
- Дрейф терминов/ссылок: `spec/CONTROLLER_DECISIONS.md` (Section XVI) vs `CONTROLLER_DECISIONS` (Section XIX); соответствующего файла/каталога в репозитории нет.
- RETL: одновременно заявлено «RETL batch signatures required for public domains» и «L1 does not verify sequencer sig» — неясно, это консенсус, мемпул‑политика или чисто операционное требование.
- Тайбрейк форка: `smaller block_hash lex wins` без определения представления (байтовый порядок/hex‑строка) и сравнения.

## Consensus-Split Risks
- Разные реализации могут вычислять разные `anchor_commitment` из-за SHA3-256 vs SHA3.
- Разные реализации могут вычислять разные `txid/block_hash` из-за отсутствия канонических `TxNoWitnessBytes/BlockHeaderBytes` и неопределенного `CompactSize`/endianness.
- Разные реализации могут расходиться на форк‑тайбрейке из-за неопределенного лексикографического сравнения `block_hash`.
- Разные реализации могут трактовать `Created(T)` по‑разному из-за отсутствия списка «non-spendable covenant types».

## Recommendations
1. NUTS: CONTROLLER APPROVAL REQUIRED — устранить конфликт `anchor_commitment` (выбрать единственный хэш и закрепить во всех разделах + векторах соответствия).
2. NUTS: CONTROLLER APPROVAL REQUIRED — специфицировать канонический wire‑энкодинг: `CompactSize`, примитивы (`u32le` и др.), структуры TxIn/TxOut/Witness, и точные байтовые определения `TxNoWitnessBytes`, `TxSigPreimage`, `BlockHeaderBytes`, правило сравнения `block_hash`.
3. NUTS: CONTROLLER APPROVAL REQUIRED — задать консенсус‑константы и функции: genesis, `Subsidy(h)`, параметры VERSION_BITS (`START_HEIGHT/SIGNAL_WINDOW/THRESHOLD`), PoW target/difficulty update.
4. NUTS: CONTROLLER APPROVAL REQUIRED — формализовать ковенанты: перечисление `covenant_type`, критерий non-spendable, и как `covenant_data` кодируется в TxOut/UTXO.
5. Уточнить статус RETL‑подписей: если L1 их не проверяет, оформить как операционное/клиентское требование; если проверяет — это NUTS и нужен полный wire‑энкодинг `signing_message`.
6. Привести к одному имени/пути `CONTROLLER_DECISIONS` и добавить отсутствующий файл (минимум как заглушку‑реестр решений).

## Notes & Limitations
- В репозитории отсутствуют `spec/`, `formal/`, `operational/`; аудит выполнен по одному монолитному документу.
- Межфайловую проверку терминологического дрейфа выполнить невозможно; отмечены только внутренние противоречия/ссылки на несуществующие файлы.

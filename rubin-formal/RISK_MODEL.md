# Formal risk model (Phase‑0 / devnet)

Цель: дать **воспроизводимую, машинно‑проверяемую** оценку того, *что именно* покрыто формальным пакетом (`rubin-formal/`),
и как это влияет на “готовность” для разных стадий (Phase‑0/devnet vs внешний аудит vs freeze).

Важно: это **не** про изменение консенсуса. Это про **коммуникацию рисков** и предотвращение overclaim.

## Входные данные (source of truth)

- `rubin-formal/proof_coverage.json`
  - `proof_level`; `package_maturity`: уровни строгости и текущего доверенного состояния пакета
  - `coverage[]`: pinned‑секции из `spec/SECTION_HASHES.json` и их статусы
  - `claims.allowed` / `claims.forbidden`: рамка допустимых публичных формулировок (обязательно)

## Source rebind: 116 original → 102 active (4 `DROP_RETIRED_GENERATED_SOURCE` + 3 `DROP_RETIRED_SOURCE` + 7 `DROP_STALE_SOURCE`; `CoreExtRefinement.lean` is separately `SEMANTIC_THEOREM_RECONCILIATION`-retired)

## Термины

- **Pinned section**: секция из `spec/SECTION_HASHES.json`, которая hash‑pin’ится и должна быть синхронна со спекой.
- `status=proved`: утверждения для pinned‑секции доказаны в рамках текущего `proof_level`.
- `status=proved_with_axiom`: утверждения доказаны, но proof опирается на один или более явно названных допущений. Для hash/commitment-секций это обычно означает reduction к collision resistance, а не аксиомо-свободную невозможность коллизии.
- `status=stated`: резервный статус для будущих registry rows без machine-checked доказательства. В текущем registry таких строк нет.
- `status=deferred`: резервный статус для сознательно не покрытой секции. В текущем registry таких строк нет.
- `evidence_level`: главный truth-correction field для честного public claim ceiling. Он отделяет universal, behavioral, assumption-backed и contract-level entries даже когда registry status уже `proved`.

## Уровни доказательств (`proof_level`)

- `toy-model`: модельный baseline (ранняя форма инвариантов). **Не** байтовая и **не** эквивалентность с Go/Rust.
- `spec-model`: модель уже явно отражает ключевые определения из CANONICAL (ещё не bit‑exact wire).
- `byte-model`: доказательства привязаны к byte‑accurate wire/serialization формулам.
- `refinement`: есть слой уточнения “модель → исполняемая семантика”.
  В текущем `rubin-formal` это op-scoped bridge map из `rubin-formal/refinement_bridge.json`:
  часть ops закрыта Go-trace / CV replay, часть — LIVE/BRIDGE theorem surface
  на Lean transcription с explicit parity boundary к Go/Rust. Это **не**
  uniform machine-checked equivalence между Lean и Go/Rust по всему critical-op
  surface.

## Профили готовности (CI gate)

В protocol repository gate-логика реализована в
`tools/check_formal_risk_gate.py` и
`tools/check_formal_coverage.py`.

### `phase0` (по умолчанию)

Для Phase‑0/devnet достаточно:
- baseline существует и консистентен;
- **нет** pinned‑секций со `status=deferred`;
- `claims.allowed/forbidden` присутствуют (anti‑overclaim).

`proof_level=toy-model` разрешён (как baseline).

### `devnet`

То же что `phase0`. (Профиль выделен, чтобы позже ужесточить без ломки tooling.)

### `audit`

При текущем `package_maturity=experimental_pending_reverification` профиль
fail-closed. Для прохождения нужен отдельно авторизованный переход
re-verification/maturity; это не меняет действующие правила `phase0`/`devnet`,
которые могут проходить.

### `freeze`

При текущем `package_maturity=experimental_pending_reverification` профиль
fail-closed. Для прохождения также нужен отдельно авторизованный переход
re-verification/maturity.

## Текущая truth snapshot

На текущем refinement-срезе registry содержит:

- `28` rows со статусом `proved`;
- `4` rows со статусом `proved_with_axiom`;
- `27` universal entries;
- `4` assumption-backed entries;
- `1` model-level entry;
- `0` stated rows;
- `0` deferred rows.

Это сильнее старого bootstrap narrative, но всё ещё не даёт права заявлять universal proof of full CANONICAL semantics.

Отдельно по Lean ↔ Go/Rust bridge ceiling:

- источник истины: `rubin-formal/refinement_bridge.json`
- ceiling op-scoped, не repo-wide
- допустимы mixed ceilings (`machine_checked_universal`,
  `machine_checked_assumption_backed`, `machine_checked_behavioral`,
  `machine_checked_contract`)
- недопустима формулировка, будто весь critical-op layer uniformly backed by
  Go-trace refinement или machine-checked Lean↔Go/Rust equivalence

## Risk scoring (информативно)

`tools/formal_risk_score.py` вычисляет простой монотонный score и tier (LOW/MEDIUM/HIGH) для прозрачного статуса.
Это **не** консенсус‑гейт; используется для отчётов и dashboard.

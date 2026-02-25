# Formal risk model (Phase‑0 / devnet)

Цель: дать **воспроизводимую, машинно‑проверяемую** оценку того, *что именно* покрыто формальным пакетом (`rubin-formal/`),
и как это влияет на “готовность” для разных стадий (Phase‑0/devnet vs внешний аудит vs freeze).

Важно: это **не** про изменение консенсуса. Это про **коммуникацию рисков** и предотвращение overclaim.

## Входные данные (source of truth)

- `rubin-formal/proof_coverage.json`
  - `proof_level`: уровень строгости/реализма семантики доказательств
  - `coverage[]`: pinned‑секции из `spec/SECTION_HASHES.json` и их статусы
  - `claims.allowed` / `claims.forbidden`: рамка допустимых публичных формулировок (обязательно)

## Термины

- **Pinned section**: секция из `spec/SECTION_HASHES.json`, которая hash‑pin’ится и должна быть синхронна со спекой.
- `status=proved`: утверждения для pinned‑секции доказаны в рамках текущего `proof_level`.
- `status=stated`: утверждения сформулированы как леммы/аксиомы, но доказательства не добавлены.
- `status=deferred`: секция сознательно не покрыта формально на данном этапе.

## Уровни доказательств (`proof_level`)

- `toy-model`: модельный baseline (ранняя форма инвариантов). **Не** байтовая и **не** эквивалентность с Go/Rust.
- `spec-model`: модель уже явно отражает ключевые определения из CANONICAL (ещё не bit‑exact wire).
- `byte-model`: доказательства привязаны к byte‑accurate wire/serialization формулам.
- `refinement`: есть слой уточнения “модель → исполняемая семантика” (в идеале — привязка к reference implementation).

## Профили готовности (CI gate)

Реализовано в `tools/check_formal_risk_gate.py`.

### `phase0` (по умолчанию)

Для Phase‑0/devnet достаточно:
- baseline существует и консистентен;
- **нет** pinned‑секций со `status=deferred`;
- `claims.allowed/forbidden` присутствуют (anti‑overclaim).

`proof_level=toy-model` разрешён (как baseline).

### `devnet`

То же что `phase0`. (Профиль выделен, чтобы позже ужесточить без ломки tooling.)

### `audit`

Для внешнего аудита claims о “formal verification” недопустимы при `proof_level=toy-model`.
Требование:
- нет `deferred`;
- `proof_level != toy-model`.

### `freeze`

Минимальный “freeze‑adjacent” профиль:
- `proof_level ∈ {byte-model, refinement}`;
- `stated=0` и `deferred=0`.

## Risk scoring (информативно)

`tools/formal_risk_score.py` вычисляет простой монотонный score и tier (LOW/MEDIUM/HIGH) для прозрачного статуса.
Это **не** консенсус‑гейт; используется для отчётов и dashboard.


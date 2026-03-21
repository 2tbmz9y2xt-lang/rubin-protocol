# RUBIN Formal (Lean4) — mirror/bootstrap (in-repo)

Этот каталог содержит in-repo formal proof-pack baseline для RUBIN.
**Источник истины (authoritative formal baseline)** — standalone репозиторий `rubin-formal`:
`https://github.com/2tbmz9y2xt-lang/rubin-formal`.

Этот in-repo каталог используется как:

- зеркальный bootstrap для CI в `rubin-protocol`,
- воспроизводимый “пин” для replay/refinement поверх conformance fixtures,
- удобная точка входа для разработчиков, но **не** как canonical formal SOT.

Machine-readable summary contract:

- `rubin-formal/proof_coverage.json` в standalone repo — authoritative source of truth;
- `rubin-protocol/rubin-formal/proof_coverage.json` — documented in-repo summary subset для CI и
  tooling в `rubin-protocol`;
- summary MUST carry the same `proof_level`, `claim_level`, and `spec_section_hashes_sha3_256` as
  authoritative standalone file, but MAY omit entries that the in-repo tooling does not model.

## Что есть сейчас

- Lean4-пакет `RubinFormal`
- `proof_coverage.json` с machine-readable summary registry для pinned section keys, которые
  текущее protocol tooling реально моделирует
- summary entries со статусами `proved` / `stated` и явными `notes` / `limitations`, если
  authoritative standalone registry уже ограничивает claim scope

## Граница claims (критично)

Этот proof-pack — executable replay/refinement coverage для conformance-фикстур (CV-*.json) и baseline-слой
для дальнейшей формализации. Он нужен для воспроизводимого "якоря", но **не** является универсальной
формальной верификацией CANONICAL.
Текущий machine-readable статус: `proof_level=refinement`, `claim_level=refined`.

Разрешённые формулировки (OK):

- "Lean executable semantics replay all conformance fixtures (CV-*.json)"
- "Go(reference) → Lean refinement is checked for critical ops over conformance fixture set"

Запрещённые формулировки (NOT OK):

- "formal verification of RUBIN consensus / CANONICAL"
- "bit-exact wire/serialization proven"
- "universal mechanized equivalence between spec text and Go/Rust implementations"

Источник истины по границе claims — standalone `rubin-formal/proof_coverage.json`.
Summary в этом каталоге не является отдельным formal SOT и не должен overclaim-ить по отношению к standalone файлу.
Дополнительно используется `claim_level` (`toy|byte|refined`) с CI-валидацией консистентности относительно `proof_level`.

## Risk model / CI gate

- Док: `rubin-formal/RISK_MODEL.md`
- Скрипты:
  - `tools/formal_risk_score.py`
  - `tools/check_formal_risk_gate.py --profile phase0`
  - `tools/check_formal_refinement_bridge.py`
  - `tools/check_formal_claims_lint.py`

## Что это значит

- Это **не** полный freeze-ready пакет уровня "универсальная байтовая модель wire + state transition для всех секций".
- Консенсусные правила не меняются.
- In-repo summary registry покрывает тот поднабор pinned section keys, который текущее tooling
  `rubin-protocol` реально валидирует.
- Если standalone `rubin-formal` усиливает или ослабляет claim boundary, summary обязан обновиться
  так, чтобы не противоречить authoritative файлу.

## Локальный запуск

```bash
scripts/dev-env.sh -- bash -lc 'cd rubin-formal && lake env lean --version'
scripts/dev-env.sh -- bash -lc 'cd rubin-formal && lake build'
```

## Дальше

1. Держать summary `proof_coverage.json` в синхроне с authoritative standalone файлом по `proof_level`, `claim_level`, `spec_section_hashes_sha3_256` и смысловой границе claims.
2. Расширить protocol tooling так, чтобы summary можно было сужать всё меньше, а не держать вечный split-brain.
3. Углубить универсальные теоремы beyond-fixtures поверх текущего refinement слоя.

# RUBIN Spec Governance (NON-CONSENSUS)

Статус: **NON-CONSENSUS / governance artifact**.

Цель: правила сопровождения спеки/реестров/fixtures, чтобы обеспечить:

- стабильность публичных ID (error codes, covenant registry, conformance gates/vectors);
- воспроизводимость аудита (freeze-ready дисциплина);
- отсутствие “тихих” breaking-изменений.

Нормативное первенство не меняется: source-of-truth для консенсуса — `RUBIN_L1_CANONICAL.md`.

## 1) Неподвижность ID (stability contract)

### 1.1 Error codes (`TX_ERR_*`, `BLOCK_ERR_*`)

- Любой error code — публичный контракт.
- Запрещено:
  - переиспользовать код с другой семантикой;
  - “тихо” менять приоритет/порядок валидации так, чтобы менялся код ошибки.
- Разрешено:
  - добавлять новые коды (через CANONICAL + conformance coverage + Go/Rust parity);
  - deprecate (не удаляя и не переиспользуя).

### 1.2 Covenant registry (`covenant_type`)

- Значения и смысл фиксируются в CANONICAL.
- Запрещено менять смысл уже занятых значений.
- Расширение registry — только через spec + fixtures + Go + Rust.

## 2) SECTION_HASHES discipline

- Любое изменение pinned-секций CANONICAL **MUST** сопровождаться rehash:

```bash
scripts/dev-env.sh -- node scripts/gen-section-hashes.mjs
scripts/dev-env.sh -- node scripts/check-section-hashes.mjs
```

- Изменение pinned scope/canonicalization — это breaking для audit-pack и требует записи в changelog.

## 3) Conformance fixtures governance

Для каждого `conformance/fixtures/<GATE>.json`:

- поле `gate` **MUST** совпадать с именем файла без расширения;
- внутри `vectors[]` каждый `vector.id` **MUST** быть уникален;
- gate ID и vector IDs считаются частью публичного контракта; rename = breaking.

Политика breaking:

- вместо rename/удаления: добавляем новый вектор с новым ID;
- старый ID не переиспользуем;
- все breaking изменения фиксируем в `spec/SPEC_CHANGELOG.md`.

## 4) Changelog policy

Файл: `spec/SPEC_CHANGELOG.md` (**NON-CONSENSUS**).

Требуется для:

- изменений registry (error codes / covenant types);
- изменений SECTION_HASHES (scope/canonicalization);
- любых изменений conformance ID (gate/vector) и их semantics.

## 5) Lints

Инструмент: `tools/check_conformance_ids.py`

Запуск:

```bash
scripts/dev-env.sh -- python3 tools/check_conformance_ids.py
```

Проверяет:

- корректность `gate` (совпадает с именем файла),
- уникальность gate/vector ID,
- наличие changelog с датированным заголовком.


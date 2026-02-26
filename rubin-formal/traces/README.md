# Formal refinement traces (Go(reference) → Lean)

Эта папка содержит **детерминированные трассы** выполнения критических операций в Go(reference) клиенте.
Трассы используются refinement-слоем формалки: Lean вычисляет результат на тех же входах и сравнивает с Go.

## Формат

- JSONL (1 объект на строку)
- Первая строка: `type="header"` (reproducibility snapshot)
- Остальные строки: `type="entry"` (по одному вектору/операции)

Схема: `schema_v1.json`

## Генерация

```bash
scripts/dev-env.sh -- go run ./clients/go/cmd/formal-trace \
  --fixtures-dir conformance/fixtures \
  --out rubin-formal/traces/go_trace_v1.jsonl
```


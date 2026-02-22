# RUBIN Orchestration Scripts

Цель: минимизировать потерю контекста между агентами и удерживать roadmap/спеку в синхроне.

## Что здесь

- `state.mjs` — хранение и валидация рабочего состояния (`STATE.json`)
- `check-spec-drift.mjs` — проверка дрейфа констант и ссылок между `CANONICAL/COMPACT/NETWORK_PARAMS`
- `guard-branch.mjs` — защита от работы в сломанном git-состоянии
- `preflight.mjs` — единый прогон guard + drift + tests + conformance + spec tooling
- `sync-inbox-queue.mjs` — обновление `QUEUE.md` + запись в `INBOX.md`

## Быстрый запуск

```bash
# Инициализация и валидация state
node scripts/orchestration/state.mjs init
node scripts/orchestration/state.mjs validate

# Проверка ветки/состояния git
node scripts/orchestration/guard-branch.mjs

# Проверка синхронизации спецификаций
node scripts/orchestration/check-spec-drift.mjs

# Полный preflight (локально, до пуша)
node scripts/orchestration/preflight.mjs --allow-dirty
```

## Синхронизация очереди и инбокса

```bash
node scripts/orchestration/sync-inbox-queue.mjs \
  --task-id Q-C001 \
  --status CLAIMED \
  --subject "Q-C001 взят в работу" \
  --report reports/2026-02-22_report_qc001_claimed.md \
  --from Codex
```

## Переменные окружения

- `RUBIN_INBOX_DIR` — путь к директории инбокса (по умолчанию: `../inbox` относительно корня репо)
- `RUBIN_STATE_PATH` — явный путь к `STATE.json` (если нужно хранить state не в инбоксе)

## Примечания

- `guard-branch.mjs` по умолчанию блокирует dirty-worktree и работу на `main`.
- `preflight.mjs` в CI автоматически разрешает detached HEAD и проверяет тот же набор шагов.

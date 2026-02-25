# RUBIN Protocol Migration Playbook (NON-CONSENSUS)

Статус: **NON-CONSENSUS / operational playbook**.

Назначение: единая процедура rollout/rollback для изменений протокола и клиентов
в Phase‑0/devnet режиме.

## 1) Когда нужно одобрение контроллера

**НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА**, если изменение:

- меняет `valid/invalid` для tx/blocks;
- меняет validation order/priority/error mapping;
- меняет лимиты, suite gating, activation boundaries;
- вводит/меняет новые error codes;
- меняет wire/serialization, TXID/WTXID preimage, sighash.

## 2) Release train (обязательный порядок)

1) Spec (`spec/*`) + SECTION_HASHES (если менялись pinned секции CANONICAL).
2) Fixtures (`conformance/fixtures/*`) — фиксируем поведение машинно.
3) Go reference (`clients/go/*`).
4) Rust parity (`clients/rust/*`) — ровняется к Go.
5) CI green (Actions).
6) Audit pack (если нужно freeze-ready).

## 3) Минимальный локальный чеклист (перед push/PR)

Все команды запускать только через `scripts/dev-env.sh`:

```bash
scripts/dev-env.sh -- python3 tools/check_readme_index.py
scripts/dev-env.sh -- python3 tools/check_section_hashes.py
scripts/dev-env.sh -- python3 tools/check_conformance_ids.py
scripts/dev-env.sh -- node scripts/check-spec-invariants.mjs
scripts/dev-env.sh -- node scripts/check-section-hashes.mjs
scripts/dev-env.sh -- python3 conformance/runner/run_cv_bundle.py
scripts/dev-env.sh -- bash -c 'cd clients/go && go test ./...'
scripts/dev-env.sh -- bash -c 'cd clients/rust && cargo test --workspace'
```

## 4) Rollback policy (Phase‑0/devnet)

- До запуска сети rollback = git revert + обновление fixtures/conformance.
- После поднятия devnet:
  - consensus-critical rollback делается только через согласованное governance-решение
    (новая активация или перезапуск devnet с новым genesis), иначе риск split.
  - non-consensus rollback допускается обычным revert PR.

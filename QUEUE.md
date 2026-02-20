# RUBIN Protocol — Task Queue

Status tracking for active and pending work items.  
Priority: P0 (blocker) → P1 (pre-devnet) → P2 (pre-mainnet) → P3 (post-mainnet)

---

## P0 — Блокеры devnet / security bugs

| ID | Task | Owner | Effort | Status |
|---|---|---|---|---|
| Q-A01 | Заполнить deployment table §8.1 (`slh_dsa_p2pk_v1`, `htlc_anchor_v1`) | — | 1d | TODO |
| Q-A10 | **Go difficulty panic**: `maxTarget = targetOld*4` без cap на MAX_TARGET → `FillBytes([32]byte)` паникует при `targetOld` близком к `0xFFFF...`. Rust безопасен (`u256_shl2_saturating`). Фикс: добавить `if maxTarget.Cmp(maxTargetBig) > 0 { maxTarget = maxTargetBig }` перед clamp. | — | 2h | TODO |
| Q-A13 | **VAULT spend_delay overflow (Go + Rust)**: `chainHeight < prevCreationHeight + spendDelay` — unchecked u64 addition. Если атакующий создаёт VAULT с `spend_delay = 2^64 - creationHeight`, сумма wraps в 1 → timelock обходится немедленно. Rust release-mode тоже wraps (нет overflow-checks в Cargo.toml). Фикс Go: заменить `prevCreationHeight+spendDelay` на `addUint64(prevCreationHeight, spendDelay)` и вернуть ошибку при overflow. Фикс Rust: `prev_creation_height.checked_add(spend_delay).ok_or(...)`. | — | 1h | TODO |

## P1 — Pre-devnet (обязательно)

| ID | Task | Owner | Effort | Status |
|---|---|---|---|---|
| Q-A02 | Добавить `-race` флаг в CI `ci.yml` для Go тестов | — | 30m | TODO |
| Q-A03 | Зафиксировать Go version в CI (`actions/setup-go@v5` + `go-version: '1.22.x'`) | — | 30m | TODO |
| Q-A04 | Настроить fuzzing: `cargo fuzz` targets для block/tx/witness (Rust) | — | 1w | TODO |
| Q-A05 | Генерация SBOM (`cargo-sbom`, `syft`) + `cargo audit` / `govulncheck` в CI | — | 1d | TODO |
| Q-A11 | P2P шифрование: TLS 1.3 + опциональный PQ KEM transport | — | 1w | TODO |
| Q-A12 | Threat Model документ: Eclipse, reorg-race, key leakage, supply chain | — | 2d | TODO |
| Q-A14 | **parseInput: нет лимита на script_sig size** — `readExact(scriptSigLen)` аллоцирует произвольно. P2P ограничен `MaxRelayMsgBytes=8MB`, но `ParseBlockBytes` в non-P2P контексте (тест, RPC, file import) уязвим к OOM. Фикс: добавить `if scriptSigLen > MAX_SCRIPT_SIG_BYTES (32) { return error }` в parseInput (Go и Rust). | — | 30m | TODO |
| Q-A15 | **Go TxWeight: `base = base * 4` без overflow check** — Rust использует `checked_mul(4)`. На 64-bit Go практически невозможен overflow, но расхождение с Rust паттерном. Фикс: привести к единому стилю checked arithmetic. | — | 30m | TODO |

## P2 — Pre-mainnet (желательно)

| ID | Task | Owner | Effort | Status |
|---|---|---|---|---|
| Q-A06 | Lean4: доказать `value_conservation` theorem | — | 1-2w | TODO |
| Q-A07 | Lean4: доказать `deterministic_apply` theorem | — | 1-2w | TODO |
| Q-A08 | Документация: DEPLOYMENT_GUIDE.md, MINING_GUIDE.md, WALLET_INTEGRATION.md | — | 3d | TODO |
| Q-A09 | HTLC wallet policy: документировать `K_CONFIRM_L1=8` ожидание перед refund | — | 1h | TODO |

## Backlog / Ideas

| ID | Task | Notes |
|---|---|---|
| Q-B01 | Параметры блока: рассмотреть 300s/16MB + WITNESS_DISCOUNT_DIVISOR=4 | см. сессию 2026-02-20 |
| Q-B02 | L2 Payment Channels spec (RUBIN_L2_PAYMENT_CHANNELS_v1.0.md) | HTLC примитив уже есть |

---
*Обновлено: 2026-02-20*

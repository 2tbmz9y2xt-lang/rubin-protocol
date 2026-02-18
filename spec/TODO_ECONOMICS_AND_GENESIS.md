# TODO: Economics + Genesis plan (controller-intent)

Status: DRAFT (non-normative)
Last updated: 2026-02-18
Owner: controller

This file records the intended economics + genesis design discussed in the project.
It is not yet reflected in the canonical consensus spec or chain-instance profiles.

## Target economics (intent)

- Total supply target: **100,000,000 RBN**.
- Premine: **1,000,000 RBN** allocated to a developer foundation fund.
- Divisibility intent: **1 RBN = 100,000,000 base units** (Bitcoin-like).
- Emission intent: **linear issuance over 25 years**, **no halving**, **no tail** (subsidy becomes 0 after the schedule).
  - Mined issuance target: **99,000,000 RBN** (total minus premine).

НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА:
- Это будет оформлено как новая каноническая ревизия (рекомендуемо: `v1.2`) или переписываем `v1.1`?
- Основа констант для перевода "месяц/год" -> "блоки": фиксируем `365` или `365.25` дней/год?

## Genesis (intent)

Current v1.1 chain-instance profiles include a genesis coinbase with **0 outputs**
(`output_count = 0`) which implies **no premine at height 0** and emission begins at block 1.

Note: CANONICAL v1.1 includes a genesis exception for the coinbase output bound at height 0
(genesis allocations are fixed by published genesis bytes; see `spec/RUBIN_L1_CANONICAL_v1.1.md §4.5`).

Intent is to move to a genesis that includes outputs (i.e., `output_count > 0`) to support:

- A developer fund premine output(s) totaling **1,000,000 RBN**.
- Developer distribution: split across **100 outputs**, each with its own **height-based vesting**.
- (Optional) additional **1,000 unspendable outputs** included in genesis (reserved / intentionally unspendable).

Timelock mode preference:
- Use **height-based locks**, not timestamps.

### Premine locking mechanism (selected)

Selected: **`CORE_VAULT_V1`** (vault-style delayed spend), not `CORE_TIMELOCK_V1`.

Reason (pragmatic):
- Vault дает "один и тот же" UTXO-формат для preminе и для обычных программируемых фондов, и позволяет держать
  owner/recovery ключи (операционная безопасность), при этом задержка расходования задается в **высотах блоков**.

Vesting intent:
- Total premine: `1_000_000 RBN`.
- Outputs: `100` шт.
- Per-output value: `10_000 RBN`.
- Vesting duration: `48 месяцев` (4 года).

Height schedule (deterministic mapping):
- Let `TARGET_BLOCK_INTERVAL = 600s` (10 minutes).
- Let `blocks_per_year = floor((days_per_year * 24 * 60 * 60) / 600)`.
- Let `blocks_per_month = floor(blocks_per_year / 12)`.

Concrete defaults (if `days_per_year = 365.25`):
- `blocks_per_year = 52_596`
- `blocks_per_month = 4_383`

Unlock rule (proposal):
- Output i is spendable only if `height >= unlock_height_i`.
- `unlock_height(m) = m * blocks_per_month`, for `m in [1..48]`.

Distribution across months (proposal, fits exactly 100 outputs):
- Months 1..4: `3 outputs/month` (12 outputs total)
- Months 5..48: `2 outputs/month` (88 outputs total)

НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА:
- Подтвердить `days_per_year` константу для переводов в блоки (иначе vesting "поплывет" между реализациями).
- Подтвердить, оставляем ли "1,000 unspendable outputs" как обязательный пункт или выкидываем.

## Required spec/profile changes (future work)

- Decide whether this is a new canonical revision (recommended: `v1.2`) or a rewrite of `v1.1` profiles.
- Add a deterministic genesis builder:
  - generate `genesis_tx_bytes`
  - compute `chain_id`
  - compute `genesis_block_hash`
- Update:
  - `spec/RUBIN_L1_COINBASE_AND_REWARDS_*.md` (economics constants/schedule)
  - `spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_MAINNET_*.md` (+ testnet/devnet as needed)
  - conformance vectors that depend on genesis-derived values (if any).

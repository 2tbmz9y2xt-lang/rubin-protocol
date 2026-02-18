# TODO: Economics + Genesis plan (controller-intent)

Status: DRAFT (non-normative)
Last updated: 2026-02-18
Owner: controller

This file records the intended economics + genesis design discussed in the project.
It is not yet reflected in the canonical consensus spec or chain-instance profiles.

## Target economics (intent)

- Total supply target: **100,000,000 RBN**.
- Premine: **1,000,000 RBN** allocated to a developer foundation fund.
- Emission schedule: to be specified (must be consistent with total supply target).

## Genesis (intent)

Current v1.1 chain-instance profiles include a genesis coinbase with **0 outputs**
(`output_count = 0`) which implies **no premine at height 0** and emission begins at block 1.

Intent is to move to a genesis that includes outputs (i.e., `output_count > 0`) to support:

- A developer fund premine output(s) totaling **1,000,000 RBN**.
- Developer distribution: split across **100 addresses**, each with its own **height-based timelock**.
- An additional **1,000 unspendable outputs** included in genesis (reserved / intentionally unspendable).

Timelock mode preference:
- Use **height-based locks**, not timestamps.

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


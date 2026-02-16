# RUBIN L1 Chain Instance Profile: MAINNET v1.1 (TEMPLATE)

Status: DRAFT (NON-CONSENSUS)
Date: 2026-02-16
Scope: Mainnet chain instance binding (placeholder values for integration alignment)

Status interpretation: see `operational/RUBIN_OPERATIONAL_SECURITY_v1.1.md §1.1`.
Transition governance: `operational/RUBIN_L1_FREEZE_TRANSITION_POLICY_v1.1.md`.

Governance status: placeholder chain-instance values are fixed for this integration release stage.
- `network_magic`, genesis bytes, and derived `chain_id`/`genesis_block_hash` are set to deterministic placeholder values for chain bring-up compatibility.
- A final mainnet ceremony must replace these placeholder values and re-derive chain identity before production launch.

This file is **not a production freeze** and does not by itself authorize a mainnet claim.
It is an integration stage artifact used to align tooling before chain-init ceremony.

Required before any production/mainnet release claim:
  1) concrete genesis hex values,
  2) deterministic genesis checksum publication,
  3) controller-level approval.
   4) operational freeze transition gate completed (`Section 4` in freeze policy).

## 0. Mainnet Genesis Fill-in (chain-deployment artifact)

This section defines the exact inputs for `chain_id` derivation and block-0 hash.

Set these two concrete fields during chain-deployment ceremony:

- `genesis_header_bytes`: <hex, BlockHeaderBytes(genesis_header)>
- `genesis_tx_bytes`: <hex, TxBytes(genesis_coinbase_tx)>

Then compute:

```
serialized_genesis_without_chain_id_field =
  ASCII("RUBIN-GENESIS-v1") ||
  genesis_header_bytes ||
  CompactSize(1) ||
  genesis_tx_bytes

chain_id = SHA3-256(serialized_genesis_without_chain_id_field)
genesis_block_hash = SHA3-256(genesis_header_bytes)
```

Deployment artifact values must be published in this exact order:

1. `genesis_header_bytes`
2. `genesis_tx_bytes`
3. `chain_id`
4. `genesis_block_hash`

Цель этого файла: зафиксировать структуру выпуска mainnet‑профиля и требования к данным.
Основная генерация mainnet genesis для v1.1 выполняется отдельным chain‑deployment процессом.

## 1. Identity

- `network_name`: `rubin-mainnet`
- `network_magic`: `0x524d4149`  (ASCII "RMAI")
- `protocol_version`: `1` (u32)

## 2. Genesis (concrete values required before mainnet launch)

- `genesis_header_bytes`: `01000000000000000000000000000000000000000000000000000000000000000000000024687b35a5bef7ae62cd384e711c835ca57814f6f9730d2a9a2e7fcb280f58a500f1536500000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000001`

- `genesis_tx_bytes`: `010000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff000000000000`

Derivation:

```
serialized_genesis_without_chain_id_field =
  ASCII("RUBIN-GENESIS-v1") ||
  genesis_header_bytes ||
  CompactSize(1) ||
  genesis_tx_bytes

chain_id = SHA3-256(serialized_genesis_without_chain_id_field)
```

- `chain_id`: `b71f012bdfacaf2ef127d909c43caf2de7d24a13066f746c9b47112c43170773`

- `genesis_block_hash`: `6e31d98c19d6d457944d4cd7d101482e108a16cef7c85239d6b1d50b87c3c33b`

## 3. Consensus constant profile

- `TARGET_BLOCK_INTERVAL = 600` seconds
- `MAX_FUTURE_DRIFT = 7_200` seconds
- `WINDOW_SIZE = 2_016` blocks

## 4. Activation schedule

Mainnet deployment schedule is chain-instance specific:

- If any FEATURE deployments are active on mainnet, publish
  `RUBIN_L1_DEPLOYMENTS_MAINNET_v1.1.md` using schema in
  `RUBIN_L1_CANONICAL_v1.1.md §8.1`.
- Until this file is fully populated, mainnet launch is not complete.

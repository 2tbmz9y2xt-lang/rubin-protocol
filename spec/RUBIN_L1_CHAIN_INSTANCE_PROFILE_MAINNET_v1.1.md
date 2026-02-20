# RUBIN L1 Chain Instance Profile: MAINNET v1.1

Status: DRAFT (NON-CONSENSUS)
Date: 2026-02-16
Scope: Mainnet chain instance binding (concrete draft values for integration alignment)

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

- `010000000000000000000000000000000000000000000000000000000000000000000000de73e02cc3f22fcbb8ecf92fd13ec584ae6077cb170c144958ac0cf1cc758b7500f1536500000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000001`: <hex, BlockHeaderBytes(genesis_header)>
- `02000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff00000000000000`: <hex, TxBytes(genesis_coinbase_tx)>

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

Goal of this file: pin the mainnet profile release structure and required data.
Mainnet genesis generation for v1.1 is performed by a separate chain-deployment process.

## 1. Identity

- `network_name`: `rubin-mainnet`
- `network_magic`: `0x524d4149`  (ASCII "RMAI")
- `protocol_version`: `2` (u32)

## 2. Genesis (concrete values required before mainnet launch)

- `genesis_header_bytes`: `010000000000000000000000000000000000000000000000000000000000000000000000de73e02cc3f22fcbb8ecf92fd13ec584ae6077cb170c144958ac0cf1cc758b7500f1536500000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000001`

- `genesis_tx_bytes`: `02000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff00000000000000`

Derivation:

```
serialized_genesis_without_chain_id_field =
  ASCII("RUBIN-GENESIS-v1") ||
  genesis_header_bytes ||
  CompactSize(1) ||
  genesis_tx_bytes

chain_id = SHA3-256(serialized_genesis_without_chain_id_field)
```

- `chain_id`: `24648de54a451871d45dd917c4ae9845996b3af4e018067dce5554fd285e804c`

- `genesis_block_hash`: `d182418e6f6316a02365b4a92f45b9af8a81c2de4053bcc84eda7824529d2dc2`

## 3. Consensus constant profile

- `TARGET_BLOCK_INTERVAL = 600` seconds
- `MAX_FUTURE_DRIFT = 7_200` seconds
- `WINDOW_SIZE = 2_016` blocks

## 4. Activation schedule

Mainnet deployment schedule is chain-instance specific:

- If any FEATURE deployments are active on mainnet, publish
  `spec/RUBIN_L1_DEPLOYMENTS_MAINNET_v1.1.md` using schema in
  `spec/RUBIN_L1_CANONICAL_v1.1.md §8.1`.
- Until this file is fully populated, mainnet launch is not complete.

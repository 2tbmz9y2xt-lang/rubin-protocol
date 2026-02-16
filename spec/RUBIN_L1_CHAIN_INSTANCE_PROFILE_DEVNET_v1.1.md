# RUBIN L1 Chain Instance Profile: DEVNET v1.1

Status: DEVELOPMENT (NON-CONSENSUS)
Date: 2026-02-16
Purpose: publish deterministic chain-instance fields for local/dev deployments while preserving core consensus compatibility with v1.1.

Status interpretation: see `operational/RUBIN_OPERATIONAL_SECURITY_v1.1.md §1.1`.
Transition governance: `operational/RUBIN_L1_FREEZE_TRANSITION_POLICY_v1.1.md`.

This file defines a single chain instance. It does not modify consensus rules in `spec/RUBIN_L1_CANONICAL_v1.1.md`.

This file is **not** a production freeze and does not authorize any testnet/mainnet claim.

## 1. Identity

- `network_name`: `rubin-devnet`
- `network_magic`: `0x44455654`  (ASCII "DEVT")
- `protocol_version`: `1` (u32)

## 2. Devnet Genesis (deterministic development values)

These values are for local development and CI parity checks. Public networks MUST publish their own concrete chain-instance profile.

- `genesis_header_bytes` (hex, `BlockHeaderBytes(genesis_header)`):
  `01000000000000000000000000000000000000000000000000000000000000000000000024687b35a5bef7ae62cd384e711c835ca57814f6f9730d2a9a2e7fcb280f58a500f1536500000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000002`

- `genesis_tx_bytes` (hex, `TxBytes(genesis_coinbase_tx)`):
  `010000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff000000000000`

Derivation:

```text
serialized_genesis_without_chain_id_field =
  ASCII("RUBIN-GENESIS-v1") ||
  genesis_header_bytes ||
  CompactSize(1) ||
  genesis_tx_bytes

chain_id = SHA3-256(serialized_genesis_without_chain_id_field)
genesis_block_hash = SHA3-256(genesis_header_bytes)
```

Derived outputs (for operator convenience; not input):

- `chain_id`: `9e9878bf30ba6c37c5f7314dbc99314339275df231a9b8ee1275b7eda24cf317`
- `genesis_block_hash`: `951c1ac88944e778d99fd9dca4fd09a13a3d7da78dce64bed49f8f4ad4607438`

## 3. Activation schedule

If devnet activates any feature, publish:

- `spec/RUBIN_L1_DEPLOYMENTS_DEVNET_v1.1.md` per `spec/RUBIN_L1_CANONICAL_v1.1.md §8.1`.

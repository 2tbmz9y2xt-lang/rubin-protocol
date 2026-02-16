## RUBIN L1 Chain Instance Profile: TESTNET v1.1

Status: DRAFT (NON-CONSENSUS)
Date: 2026-02-16  
Purpose: publish concrete chain-instance fields for the RUBIN testnet deployment when available, while preserving core consensus compatibility with v1.1.

Status interpretation: see `operational/RUBIN_OPERATIONAL_SECURITY_v1.1.md §1.1`.
Transition governance: `operational/RUBIN_L1_FREEZE_TRANSITION_POLICY_v1.1.md`.

This file defines a single chain instance. It does not modify consensus rules in `spec/RUBIN_L1_CANONICAL_v1.1.md`.

This file is **not a production freeze** and does not authorize any mainnet freeze claim.

## 1. Identity

- `network_name`: `rubin-testnet`
- `network_magic`: `0x54455354`  (ASCII "TEST")
- `protocol_version`: `1` (u32)

## 2. Testnet Genesis (chain-deployment artifact)

Set these two fields during the testnet genesis ceremony:

- `genesis_header_bytes` (hex, `BlockHeaderBytes(genesis_header)`): `01000000000000000000000000000000000000000000000000000000000000000000000024687b35a5bef7ae62cd384e711c835ca57814f6f9730d2a9a2e7fcb280f58a500f1536500000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000`

- `genesis_tx_bytes` (hex, `TxBytes(genesis_coinbase_tx)`): `010000000000000000000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff000000000002`

Then compute:

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

- `chain_id`: `abb57bd1efb9f114ed060ef0c633d87fc6b35c737f1d70b66864a5557d46757d`

- `genesis_block_hash`: `2577dca80125dacfde2f0ed90a121442c857accb11176b0f0d5d35ab03056388`

## 3. Testnet Notes

1. Until this section is fully populated, testnet launch is not considered network-complete.
2. Testnet MAY use looser operational parameters internally, but these must be explicitly documented in a release-specific deployment profile and announced by controller.
3. Any script or binary relying on `chain_id` MUST use this exact file (or a chain-specific replacement) before connecting to rubin-testnet.

## 4. Consensus constants

Unless explicitly changed by a future canonical revision, testnet uses:

- `TARGET_BLOCK_INTERVAL = 600` seconds (canonical)
- `MAX_FUTURE_DRIFT = 7_200` seconds (canonical)
- `WINDOW_SIZE = 2_016` blocks (canonical)

## 5. Activation schedule

If testnet activates any feature, publish:

- `spec/RUBIN_L1_DEPLOYMENTS_TESTNET_v1.1.md` per `spec/RUBIN_L1_DEPLOYMENTS_TEMPLATE_v1.1.md`.

If no deployments are active, publish an explicit empty deployment artifact (non-normative).

# RUBIN L1 Chain Instance Profile: TEMPLATE v1.1

Status: TEMPLATE (NON-CONSENSUS)  
Date: 2026-02-16

Purpose: provide a template for chain-instance publications. Profiles bind a specific network instance by publishing concrete genesis bytes and derived identifiers.

Normative derivations are defined in `spec/RUBIN_L1_CANONICAL_v1.1.md §1.1`.
Status label taxonomy is defined in `operational/RUBIN_OPERATIONAL_SECURITY_v1.1.md §1.1`.

## 1. Identity

- network_name: `<string>`
- network_magic: `<u32be hex, 8 chars, with 0x prefix>`
- protocol_version: `1`

## 2. Genesis

Required fields:

- genesis_header_bytes: `<hex>`
- genesis_tx_bytes: `<hex>`

Derived fields (must be recomputed from the published bytes):

- chain_id: `<hex32>`
- genesis_block_hash: `<hex32>`

## 3. Deployments

Link the corresponding deployments registry:

- `spec/RUBIN_L1_DEPLOYMENTS_<network>_v1.1.md`

This deployments file is the chain-instance specific VERSION_BITS activation schedule (§8 in CANONICAL).
If the deployments file is absent or empty, nodes MUST treat all deployments as `DEFINED` / not ACTIVE
(and any deployment-gated spends will return `TX_ERR_DEPLOYMENT_INACTIVE`).

## 4. Premine / Initial Distribution (Non-consensus, required disclosure)

The initial distribution is committed to by `genesis_tx_bytes`. This section is a required disclosure
for operator and tooling interoperability. It MUST be consistent with the published `genesis_tx_bytes`.

Recommended fields:

- premine_total: `<u64>` (coins, not base-units)
- premine_outputs: `<text summary>` (how many outputs, what covenant types, any vesting/spend_delay)
- premine_security_posture: `<string>` (e.g., unspendable placeholder for devnet/testnet; or vault-based vesting for mainnet)

Mainnet note:
- If the premine requires key material (e.g., `CORE_VAULT_V1` owner/recovery keys), it MUST be produced
  as part of the genesis ceremony, not generated ad-hoc by operators after launch.

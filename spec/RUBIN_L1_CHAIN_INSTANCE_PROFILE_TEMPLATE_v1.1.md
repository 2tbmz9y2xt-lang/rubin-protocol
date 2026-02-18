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

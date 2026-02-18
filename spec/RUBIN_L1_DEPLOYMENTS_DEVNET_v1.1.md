# RUBIN L1 Deployments: DEVNET v1.1

Status: DEVELOPMENT (NON-CONSENSUS)
Date: 2026-02-18

This file is a chain-instance publication artifact for rubin-devnet.
It does not modify consensus rules and does not authorize any production/mainnet claim.

## Deployment Table (v1.1)

Devnet policy note: thresholds are relaxed vs canonical THRESHOLD=1916 (95%) for fast
feature testing without miner coordination. Devnet uses ≥50% (1008/2016).
Testnet and mainnet MUST use canonical THRESHOLD=1916.

| deployment_id | bit | start_height | timeout_height | signal_window | threshold | state_machine | feature_summary |
|---|---:|---:|---:|---:|---:|---:|---|
| `htlc_anchor_v1` | 0 | 100 | 50000 | 2016 | 1008 | v1.1-fsm | Enables CORE_HTLC_V2 (0x0102). Preimage delivered on-chain via CORE_ANCHOR envelope (prefix `RUBINv1-htlc-preimage/`, 54 bytes). Conformance: CV-HTLC-ANCHOR. |
| `sig_slh_dsa_p2pk_v1` | 1 | 200 | 50000 | 2016 | 1008 | v1.1-fsm | Enables suite_id=0x02 (SLH-DSA-SHAKE-256f) for CORE_P2PK, CORE_HTLC_V1, CORE_VAULT_V1 spends. Conformance: CV-DEP DEP-01/DEP-05. |

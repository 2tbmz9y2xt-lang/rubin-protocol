# Spec Index

## Consensus-Critical

- `./RUBIN_L1_CANONICAL.md`
  - L1 canonical transaction wire (single genesis format)
  - TXID/WTXID, weight, block header, PoW, difficulty retarget
  - covenant registry and error code registry (genesis profile)

## Program Control (Local-Only)

Execution baseline/control files are maintained locally and are intentionally not tracked in this public repository.

## Non-Consensus / AUX

- `./RUBIN_L1_P2P_AUX.md`
  - P2P notes (compact blocks shortid MUST be derived from WTXID)
- `./RUBIN_SLH_FALLBACK_PLAYBOOK.md`
  - Operational activation/rollback runbook for SLH fallback mode

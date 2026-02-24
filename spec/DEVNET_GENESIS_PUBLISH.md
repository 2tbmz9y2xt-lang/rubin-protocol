# RUBIN Phase‑0 Devnet — genesis publish (v1)

Status: non-consensus / operational spec adjunct.

Goal: publish **byte-exact genesis** for the Phase‑0 devnet so that:
- all implementations derive the same `chain_id`;
- audits and test runs are reproducible (byte-for-byte);
- any genesis changes are explicit (diffable hex changes).

This is **not mainnet ceremony**. For Phase‑0 devnet, engineering keys and simple allocations are acceptable.

## Required artifacts

1) `genesis_header_bytes_hex`
2) `genesis_tx_bytes_hex`:
   - `TxBytes(genesis_txs[0]) || ... || TxBytes(genesis_txs[n-1])`
3) Derived:
   - `chain_id_hex` (CANONICAL §11)
   - `genesis_block_hash_hex` (CANONICAL §10.3)

## Where to publish (recommended)

Publish pack (in-repo):
- `spec/DEVNET_GENESIS_BYTES.json` (hex + minimal metadata)
- `spec/DEVNET_CHAIN_ID.txt` (single-line hex)

## Change policy

- Any change to genesis bytes changes consensus identity (`chain_id`) and is a **devnet reset**.
- While Phase‑0 is in active development, resets are allowed, but each reset MUST:
  - update the publish pack,
  - document the reason,
  - communicate the new `chain_id` clearly.

## Minimal procedure

1) Construct the genesis candidate:
   - header fields (version/prev_hash/merkle_root/timestamp/target/nonce)
   - genesis txs in exact `TxBytes` form
2) Compute:
   - `chain_id` per CANONICAL §11
   - `genesis_block_hash` per CANONICAL §10.3
3) Save artifacts in the publish pack.
4) Run sanity:
   - `python3 conformance/runner/run_cv_bundle.py` (should not depend on devnet genesis)
   - tooling (if present) to derive `chain_id` from the published bytes and compare against the published value.


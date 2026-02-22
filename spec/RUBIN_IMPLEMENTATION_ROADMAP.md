# RUBIN Implementation Roadmap (Execution Baseline)

**Status:** Active (pre-freeze, controller pre-approved)  
**Date:** 2026-02-22

This document defines the implementation sequence for `rubin-protocol` so that
all agents execute in the same order and with the same acceptance criteria.

## 1. Source-of-Truth Order

If documents disagree, use this precedence:

1. `RUBIN_L1_CANONICAL.md` (consensus validity)
2. `RUBIN_COMPACT_BLOCKS.md` (normative P2P relay behavior)
3. `RUBIN_NETWORK_PARAMS.md` (reference parameters and operator guidance)
4. `RUBIN_L1_P2P_AUX.md` (auxiliary notes only)

Any consensus semantic change requires explicit controller approval.

## 2. Baseline Snapshot (Current)

- Genesis uses one canonical transaction wire format.
- DA tx kinds (`0x00/0x01/0x02`) are in canonical wire.
- DA set integrity rules are defined in CANONICAL section 21.
- Compact short-id policy is SipHash-2-4 on WTXID.
- Conformance gate `CV-COMPACT` is executable in bundle.
- Relay cap baseline is `MAX_RELAY_MSG_BYTES = 96_000_000` bytes.
- Spec is approved for implementation work, but not frozen.

## 3. Phase Plan

## 3.1 Phase S0 - Spec Stabilization Gate

Goal: eliminate cross-file ambiguity before deeper code expansion.

Scope:

- Cross-file constant sync for CANONICAL / COMPACT / NETWORK_PARAMS.
- Section numbering and cross-reference consistency.
- DA commitment semantics consistency across sections.

Exit criteria:

1. No conflicting constant values across spec files.
2. No contradictory DA commitment formulas.
3. No broken section references in normative statements.

## 3.2 Phase C1 - Consensus Block Core (Go + Rust parity)

Goal: both clients perform the same block-level core checks.

Scope:

- Full `BlockBytes` parse and structural validation.
- Header linkage, PoW, target, merkle checks.
- Block validation order aligned with CANONICAL.

Prerequisite: Q-V01 (vault spec approval) and Q-C001 (CANONICAL rewrite) must be complete.
CORE_VAULT_V1 is a consensus-native covenant active from genesis — Q-R001 onwards must reflect full registry.

Mapped queue items:

- `Q-R001`

Exit criteria:

1. `go test ./...` passes.
2. `cargo test --workspace` passes.
3. Conformance gate for block basic validation passes in both clients.

## 3.3 Phase C2 - Covenant and UTXO Core (Go + Rust parity)

Goal: deterministic covenant/UTXO behavior parity including vault.

Scope:

- `CORE_P2PK`, `CORE_TIMELOCK_V1`, `CORE_ANCHOR`, `CORE_DA_COMMIT` checks.
- `CORE_VAULT_V1` — consensus-native, full CheckBlock rules (spend_delay, whitelist_root, recovery_key, partial_spend, early_close fee).
- Non-spendable output handling.
- Basic UTXO apply paths and deterministic error mapping.
- `BLOCK_ERR_UNKNOWN_COVENANT_TYPE` for RESERVED slots (0x0100, 0x0102).

Mapped queue items:

- `Q-R002`
- `Q-R003`

Exit criteria:

1. Cross-client parity for positive and negative covenant/UTXO vectors including vault.
2. Error code parity for all covered failure classes.
3. CV-VAULT conformance gate green on both clients.

## 3.4 Phase C3 - Conformance Expansion

Goal: make parity enforceable by fixtures, not by manual review.

Scope:

- Extend runner ops for block/covenant/utxo workflows.
- Add dedicated fixture groups and gate bundle coverage.
- Keep strict `ok/err/output` parity contract.

Mapped queue items:

- `Q-R004`
- `Q-R005`

Exit criteria:

1. New gates are wired in `run_cv_bundle.py`.
2. Fixture corpus covers all implemented consensus branches.
3. Bundle run is green on both clients.

## 3.5 Phase 2 - P2P Protocol Spec + Implementation

Goal: P2P protocol fully specified and implemented in both clients. No node binary yet — transport layer only.

Scope:

- P2P message framing, handshake, `MAX_RELAY_MSG_BYTES` enforcement (spec + code).
- Compact block send/receive logic in Go and Rust (no running node required).
- DA mempool (512 MiB) and orphan pool (64 MiB / 3-block TTL) — in-process, not networked.
- Conformance gates for P2P relay behavior (CV-P2P-* bundle).
- SipHash-2-4 short-id generation parity Go↔Rust.

Note: node binary and actual networking between processes belong to Phase 3 (Devnet).

Exit criteria:

1. P2P message encoding/decoding passes Go↔Rust parity vectors.
2. Compact block relay logic passes CV-COMPACT full matrix (all 18 gates).
3. DA mempool accept/evict logic is unit-tested in both clients.

## 3.7 Phase 3 - Devnet

Goal: functional chain running between ≥2 independent nodes.

Scope:

- Node binary (Go or Rust) capable of mining, broadcasting, and validating blocks.
- P2P handshake and compact block relay operational.
- DA relay functional end-to-end.
- genesis block produced from deterministic test parameters (not mainnet ceremony).

Exit criteria:

1. ≥2 nodes reach consensus on the same chain tip.
2. Full block relay and compact block relay both functional.
3. DA set arrives and passes CheckBlock on receiving node.

## 3.8 Phase 4 - Testnet

Goal: public testnet with external participants, 30-day stability window.

Scope:

- Testnet genesis ceremony (non-mainnet keys).
- PREFETCH parameter validation via telemetry.
- Public faucet and block explorer.
- `orphan_recovery_success_rate ≥ 99.5%` sustained.
- Independent security audit engagement.

Exit criteria:

1. 30 days continuous operation without consensus divergence.
2. `shortid_collision_count` within expected bounds.
3. `miss_rate_bytes_DA < 0.5%` at tip under normal conditions.
4. Audit report received and critical findings resolved.

## 3.9 Phase 5 - Mainnet

Goal: mainnet launch.

Scope:

- Mainnet genesis ceremony (B-01, B-02, B-03).
- `chain_id` derived and published.
- Spec frozen (FREEZE tag on all four spec documents).
- Final audit sign-off.

Exit criteria:

1. B-01 genesis_header_bytes_hex — ceremony complete.
2. B-02 genesis_tx_bytes_hex — ceremony complete.
3. B-03 chain_id_hex + genesis_block_hash_hex — derived and published.
4. All spec documents tagged FREEZE.
5. Independent audit sign-off on consensus layer.

## 4. Global Delivery Rules

1. No implementation phase may bypass earlier phase gates.
2. Any consensus change must be implemented in Go and Rust in the same phase.
3. Every normative rule introduced in spec must have at least one conformance vector.
4. "Spec says X, code says Y" is a release blocker.
5. No direct pushes to `main`; use reviewable branch + PR flow.

## 5. Required Validation Commands

Run from repository root unless noted:

```bash
( cd clients/go && go test ./... )
( cd clients/rust && cargo test --workspace )
python3 conformance/runner/run_cv_bundle.py
```

If a phase adds new gates, include targeted gate runs in the phase report.

## 6. Deliverables Per Completed Task

Each completed task must produce:

1. PR with focused diff (no unrelated file changes).
2. Test evidence (commands + pass/fail).
3. Explicit list of implemented spec rules.
4. Remaining risks / deferred items.

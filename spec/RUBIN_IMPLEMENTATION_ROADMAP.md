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

Mapped queue items:

- `Q-R001`

Exit criteria:

1. `go test ./...` passes.
2. `cargo test --workspace` passes.
3. Conformance gate for block basic validation passes in both clients.

## 3.3 Phase C2 - Covenant and UTXO Core (Go + Rust parity)

Goal: deterministic covenant/UTXO behavior parity.

Scope:

- `CORE_P2PK`, `CORE_TIMELOCK_V1`, `CORE_ANCHOR`, `CORE_DA_COMMIT` checks.
- Non-spendable output handling.
- Basic UTXO apply paths and deterministic error mapping.

Mapped queue items:

- `Q-R002`
- `Q-R003`

Exit criteria:

1. Cross-client parity for positive and negative covenant/UTXO vectors.
2. Error code parity for all covered failure classes.

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

## 3.5 Phase C4 - Vault Integration (after approval)

Goal: integrate finalized vault semantics without destabilizing previous gates.

Scope:

- Integrate approved vault spec into CANONICAL.
- Implement Go/Rust parity and CV coverage.

Mapped queue item:

- `Q-V01`

Exit criteria:

1. Controller approval on vault semantics exists.
2. Go and Rust parity is proven by dedicated vectors.

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

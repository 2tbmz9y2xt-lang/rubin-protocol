# POLICY: Rubin Genesis Mempool Admission

**Status:** NON-CONSENSUS / relay-mempool policy
**Date:** 2026-04-29
**Revision:** post-review rc3 (overlay landing in `rubin-protocol`)
**Applies to:** devnet, testnet candidate, mainnet release baseline unless superseded
**Canonical precedence:** `RUBIN_L1_CANONICAL.md` remains the only source of consensus validity.

This policy defines what a production node admits to its mempool. It does
not change block validity. A block containing a transaction rejected by
this policy can still be consensus-valid if it satisfies
`RUBIN_L1_CANONICAL.md`.

## 0. Normative Parent and Scope Boundary

This file is a protocol-side admission **overlay**. It MUST NOT be used
as the only mempool implementation source.

The precise mempool source-of-truth for ordered checks and deterministic
behavior is the merged `rubin-spec` baseline:

```text
spec/RUBIN_MEMPOOL_POLICY.md
```

(in the private `rubin-spec` repository — see `SPEC_LOCATION.md` in
this repo for the cross-repo convention; all `spec/...` references in
this document refer to that private spec repo, not in-repo paths),
merged via `rubin-spec` PR #239 at commit
`dfcb97ae30d074a9483e04061019cc758580d811` ("spec: define standard
mempool policy baseline (#239)"). That parent document controls at
least:

- ordered admission checks;
- duplicate `txid` / `wtxid` handling;
- standard mempool eviction;
- rolling local floor behavior;
- deterministic reorg requeue ordering;
- any first-reason ordering that affects cross-client behavior.

This document adds genesis policy defaults and protocol-side enforcement
surfaces: fee floor, dust floor, locktime gate, `CORE_EXT` pre-activation
gate, DA / anchor anti-abuse gate, and telemetry names.

If this file and `spec/RUBIN_MEMPOOL_POLICY.md` conflict on
ordering, eviction, rolling floor, duplicate checks, or reorg requeue
behavior, the spec parent wins.

### 0.1 Implementation Authorization Boundary

This document does NOT authorize implementation by itself. Execution
ownership is split across the implementation issues listed in §9; this
file is policy text only and changes no code. Specifically:

- No Go mempool implementation is added or modified by this file.
- No Rust parity is added or modified by this file.
- No conformance vectors are added by this file.
- No miner template runtime change is enacted by this file.
- No telemetry counter is registered by this file beyond declaring the
  names a future implementation MAY/SHOULD expose.

Any implementation slice MUST cite the relevant follow-up issue from §9
and MUST land in a separate PR.

## 1. Policy Decision

Rubin uses a strict, first-seen mempool at genesis:

- No replace-by-fee.
- No package relay.
- No child-pays-for-parent admission.
- No predictive dynamic fee market.
- Per-transaction admission only.
- DA set relay remains governed by `RUBIN_COMPACT_BLOCKS.md`.

The goal is to keep Phase-0/devnet admission deterministic, cheap to
reason about, and audit-clean.

## 2. Admission Overlay Gates

A node SHOULD apply the parent `spec/RUBIN_MEMPOOL_POLICY.md`
admission order first. The gates below are overlay requirements that
must be placed into that ordered flow without changing the parent
ordering semantics.

### Stage A — Wire and Structural Precheck

Reject as non-standard if any of the following holds:

1. Transaction bytes do not parse canonically.
2. `tx_kind` is not one of `0x00`, `0x01`, `0x02`.
3. Transaction exceeds canonical parser or witness limits.
4. Non-minimal `CompactSize` encoding is present.
5. Transaction uses an invalid or malformed covenant encoding.
6. Transaction has `tx_nonce = 0`, except coinbase.
7. Transaction uses `sequence > 0x7fffffff`.

This stage mirrors consensus parser constraints, but the result is a
mempool rejection, not a consensus error.

### Stage B — UTXO-Resolved Check

After referenced inputs are available, reject as non-standard if any of
the following holds:

1. Any referenced input is missing from the local UTXO set.
2. Any referenced input is non-spendable.
3. Any referenced coinbase output is immature.
4. Covenant spend validation would fail under current chain state.
5. Value conservation would fail.
6. The transaction conflicts with any already-admitted mempool
   transaction by spending the same outpoint.

Conflict handling is first-seen. The later conflicting transaction is
rejected. There is no fee-based replacement.

**Spec follow-up note:** if `spec/RUBIN_MEMPOOL_POLICY.md`
does not yet list coinbase maturity as an explicit admission check, that
addition belongs in the spec parent and is a follow-up there. This file
may enforce it immediately as policy because immature coinbase spends
cannot be mined into a valid block at the current height. This document
does not edit the spec parent.

### Stage C — Fee Gate

Let:

```text
fee(tx) = sum_inputs - sum_outputs
relay_fee_floor(tx) = weight(tx) * current_mempool_min_fee_rate
da_fee_floor(tx)    = da_payload_len(tx) * min_da_fee_rate
required_fee(tx)    = max(relay_fee_floor(tx),
                          da_fee_floor(tx) + da_surcharge(tx))
```

Where:

```text
da_surcharge(tx) = da_payload_len(tx) * PolicyDaSurchargePerByte
```

Reject as non-standard if:

```text
fee(tx) < required_fee(tx)
```

This means a DA transaction must satisfy both the base relay-fee floor
and the DA-specific floor, with any DA surcharge applied only to DA
bytes.

`current_mempool_min_fee_rate` is the rolling local floor defined and
maintained by the parent `spec/RUBIN_MEMPOOL_POLICY.md` §10
(raise after capacity eviction, decay on connected-block events). The
parent guarantees the invariant
`current_mempool_min_fee_rate >= MIN_RELAY_FEE_RATE`, so the formula
above is always at least as strict as the base relay-fee floor and is
strictly stricter whenever the rolling floor is above the default.
This overlay does NOT redefine raise/decay behavior; it only points
implementers to the parent rolling floor as the effective gate.

Default / base parameters (constants are sourced from the documents
named below; this overlay does not redefine any of them):

```text
MIN_RELAY_FEE_RATE       = 1   # base/default floor; parent §10 owns
                                #   the effective rolling floor
                                #   current_mempool_min_fee_rate
min_da_fee_rate          = 1
PolicyDaSurchargePerByte = 0
```

Sources:

- `current_mempool_min_fee_rate` (effective admission floor; raise/decay
  rules): `spec/RUBIN_MEMPOOL_POLICY.md` §6.2 check 10
  (admission gate) and §10 (rolling local floor invariants and
  raise/decay).
- `MIN_RELAY_FEE_RATE` constant default value:
  `spec/RUBIN_L1_CANONICAL.md` §4; relay-policy summary:
  `spec/RUBIN_NETWORK_PARAMS.md` §12.6.
- `min_da_fee_rate`: `spec/RUBIN_NETWORK_PARAMS.md` §12.4.
- `PolicyDaSurchargePerByte`: `POLICY_DA_ANCHOR_ANTI_ABUSE.md` (this
  repository, root).

Notes:

- `current_mempool_min_fee_rate` and `MIN_RELAY_FEE_RATE` are relay
  policy only.
- `min_da_fee_rate` is relay policy only.
- Blocks with underpaying transactions remain consensus-valid if they
  satisfy consensus rules.

### Stage D — Dust Gate

Reject as non-standard if any spendable output has:

```text
value < MIN_RELAY_OUTPUT_VALUE
```

Default:

```text
MIN_RELAY_OUTPUT_VALUE = 8_000 base units
```

`MIN_RELAY_OUTPUT_VALUE` source: `spec/RUBIN_NETWORK_PARAMS.md`
§12.5 (dust threshold).

Spendable covenant types (subject to dust gate):

```text
CORE_P2PK
CORE_HTLC
CORE_VAULT
CORE_MULTISIG
CORE_STEALTH
CORE_EXT
```

Exempt non-spendable covenant types (dust gate does not apply):

```text
CORE_ANCHOR
CORE_DA_COMMIT
```

### Stage E — Locktime Anti-Fee-Sniping Gate

Reject as non-standard if:

```text
locktime > current_height + 1
```

`locktime = 0` remains allowed. Wallets SHOULD set:

```text
locktime = current_height
```

This is relay-only. Consensus does not assign general transaction-level
locktime semantics outside the coinbase height commitment and HTLC
rules.

### Stage F — CORE_EXT Pre-Activation Gate

Reject as non-standard if the transaction creates or spends a
`CORE_EXT` output whose profile is not `ACTIVE` at the candidate
admission height.

Strict mode is ON by default for production nodes.

A node MAY expose an unsafe test-only override, but it MUST:

1. Be disabled by default.
2. Emit a structured warning event at startup.
3. Be forbidden in release-profile configuration.
4. Be excluded from miner templates unless explicitly enabled for
   controlled tests.

This overlay is consistent with the existing
`POLICY_CORE_EXT_PREACTIVATION.md` (this repository, root) guardrail
and is restated here for cross-doc continuity. This overlay does NOT
authorize or name the runtime implementation owner for the Stage F
guardrail; per §9 the overlay is policy text only and any concrete
runtime/implementation work for Stage F remains under whatever
separate, independently-approved implementation tracks the project may
already have or may open in the future.

### Stage G — Anchor and DA Anti-Abuse Gate

Reject as non-standard if a non-coinbase transaction creates a
`CORE_ANCHOR` output.

For DA-carrying transactions:

1. Admit only if the Stage C fee gate passes.
2. Enforce template DA byte budget separately during mining (see §3).
3. Keep DA relay set-state rules under `RUBIN_COMPACT_BLOCKS.md`.

This overlay is consistent with `POLICY_DA_ANCHOR_ANTI_ABUSE.md` (this
repository, root). The duplicate-DA-commit rule and DA pool semantics
remain governed by `RUBIN_COMPACT_BLOCKS.md`.

## 3. Mining Template Policy

A policy-compliant miner template MUST exclude:

- mempool conflicts;
- under-fee transactions;
- dust outputs;
- non-coinbase `CORE_ANCHOR` outputs;
- pre-activation `CORE_EXT` creates/spends;
- DA payloads exceeding `PolicyMaxDaBytesPerBlock` for the candidate
  block.

Default:

```text
PolicyMaxDaBytesPerBlock = MAX_DA_BYTES_PER_BLOCK / 4
```

`PolicyMaxDaBytesPerBlock` source: `POLICY_DA_ANCHOR_ANTI_ABUSE.md`
(this repository, root). `MAX_DA_BYTES_PER_BLOCK` is the consensus DA
cap defined by `spec/RUBIN_L1_CANONICAL.md`.

This template cap is policy, **not** consensus. A block above the
policy cap remains consensus-valid if it is within
`MAX_DA_BYTES_PER_BLOCK`.

## 4. No Replacement Semantics

Mempool replacement is disabled.

A transaction is a replacement attempt if it spends any outpoint
already spent by a mempool transaction. Such a transaction MUST be
rejected as non-standard regardless of fee.

This rule applies to:

- standard transactions;
- DA commit transactions;
- DA chunk transactions;
- vault spends;
- HTLC spends;
- multisig spends;
- stealth spends;
- `CORE_EXT` spends.

DA duplicate commits remain governed by the stricter relay rule in
`RUBIN_COMPACT_BLOCKS.md`: the first-seen commit for a `da_id` is
retained; later duplicate commits are discarded and fee-based
replacement is forbidden.

This overlay does not introduce RBF, CPFP, or package relay.

## 5. Deterministic Eviction and Reorg Requeue

This policy does not redefine eviction or reorg requeue order.

Implementation MUST defer to `spec/RUBIN_MEMPOOL_POLICY.md`
for:

```text
standard eviction algorithm
rolling local floor raise and decay
candidate comparison with virtual admission_seq where specified
reorg requeue in canonical block-body order
no hash-map iteration in ordering-sensitive paths
```

The policy intent is cross-client convergence, not local optimization.

## 6. Operational Telemetry

When implemented, nodes SHOULD expose these counters. This overlay
declares the logical telemetry surface; concrete Prometheus exports
MUST remain in the existing `rubin_node_` namespace/prefix used by
the Go and Rust nodes, so this overlay does not introduce a second,
conflicting metric namespace. The specific metric names listed below
are the required names for future exports of this telemetry surface
when implemented; the implementation locus is the issues in §9, not
this file:

```text
rubin_node_mempool_admit_total
rubin_node_mempool_reject_total
rubin_node_mempool_reject_fee_total
rubin_node_mempool_reject_dust_total
rubin_node_mempool_reject_conflict_total
rubin_node_mempool_reject_core_ext_preactivation_total
rubin_node_mempool_reject_anchor_nonstandard_total
rubin_node_mempool_reject_locktime_future_total
rubin_node_mempool_reject_da_underfee_total
rubin_node_mempool_reorg_requeue_total
rubin_node_mempool_min_fee_rate
rubin_node_mempool_min_da_fee_rate
rubin_node_mempool_min_relay_output_value
```

Every rejection SHOULD include:

```text
reason
wtxid, if parse-valid
peer_id, if relay-originated
height
policy_version
```

Do not log private key material, raw seed material, or full witness
bytes at `INFO`, `WARN`, or `ERROR` level.

## 7. Review Triggers

Review this policy after any of the following:

1. Devnet DA fill exceeds 80% over a 144-block window.
2. Mempool rejection by fee exceeds 50% over 24 hours.
3. Sustained compact-block miss rate exceeds 0.5% at tip.
4. Operators request a coordinated `MIN_RELAY_FEE_RATE` change.
5. Governance approves RBF, CPFP, or package relay for active design.

## 8. Explicit Non-Goals

This policy does not define:

- consensus minimum fees;
- consensus dust limits;
- RBF;
- CPFP;
- package relay;
- base-fee burn;
- priority-fee markets;
- EIP-1559-style dynamics.

Structured logging events for mempool admission (e.g.
`mempool.reorg_requeue`) are intended to be defined by a future
`POLICY_STRUCTURED_LOGGING_MINIMUM.md`, owned by `rubin-protocol#1345`.
Until that policy is merged, implementations SHOULD use the rejection
fields in §6 as the structured-logging surface.

## 9. Implementation Follow-Ups (Non-Authorizing)

This file is policy text. The implementation execution path is owned
by the following follow-up issues (titles taken verbatim from
`gh issue view` at the time of writing); this PR does not authorize
implementation by itself:

- `rubin-protocol#1335` —
  `[Q-GO-MEMPOOL-ENTRY-INDEX-FOUNDATION-01] Add Go standard mempool
  policy metadata and indexes`.
- `rubin-protocol#1336` —
  `[Q-GO-MEMPOOL-FEE-EVICTION-ROLLING-FLOOR-01] Implement Go standard
  mempool fee/weight eviction and rolling floor`. This is the home of
  the rolling local fee-floor raise/decay behavior referenced from
  Stage C and §5.
- `rubin-protocol#1337` —
  `[Q-GO-MEMPOOL-REORG-REQUEUE-POLICY-01] Add Go best-effort standard
  mempool reorg requeue policy`. This is the home of the reorg requeue
  ordering referenced from §5.
- `rubin-protocol#1338` —
  `[Q-GO-MEMPOOL-POLICY-TELEMETRY-01] Expose Go standard mempool policy
  telemetry`. This is the home of the §6 counter / rejection-field
  surface.
- `rubin-protocol#1339` —
  `[Q-RUST-MEMPOOL-POLICY-PARITY-01] Implement Rust parity for standard
  mempool policy`.
- `rubin-protocol#1340` —
  `[Q-CONF-MEMPOOL-POLICY-VECTORS-01] Add executable Go/Rust CV-MEMPOOL
  policy vectors`.

This overlay does NOT itself open a separate "miner template
enforcement" or "operator config / safety-rail" tracking issue, and it
does NOT claim a specific implementation owner for Stage F's
`CORE_EXT` pre-activation guardrail or Stage G's anchor / DA
anti-abuse guardrail. Those guardrails are recorded in pre-existing
protocol-side policy documents — `POLICY_CORE_EXT_PREACTIVATION.md`
and `POLICY_DA_ANCHOR_ANTI_ABUSE.md` (this repository, root) — and
this overlay restates them only for cross-doc continuity. Any concrete
runtime/implementation work for Stage F or Stage G remains owned by
whatever separate, independently-approved implementation tracks the
project may already have or may open in the future; this overlay does
not authorize, name, or relax review requirements for that work.

Each of the issues above remains the canonical owner of its execution
work and lands in a separate PR. Citing this overlay does not relax
the review or evidence requirements on those PRs.

## 10. Cross-References

- `spec/RUBIN_MEMPOOL_POLICY.md` — normative parent (PR #239,
  merge `dfcb97ae30d074a9483e04061019cc758580d811`).
- `spec/RUBIN_L1_CANONICAL.md` — consensus validity
  precedence; `MIN_RELAY_FEE_RATE` and `MAX_DA_BYTES_PER_BLOCK`
  constants.
- `spec/RUBIN_NETWORK_PARAMS.md` — relay-policy parameter
  homes (`min_da_fee_rate` §12.4; `MIN_RELAY_OUTPUT_VALUE` §12.5;
  `MIN_RELAY_FEE_RATE` summary §12.6).
- `spec/RUBIN_COMPACT_BLOCKS.md` — DA relay set-state rules
  and DA duplicate-commit handling.
- `POLICY_DA_ANCHOR_ANTI_ABUSE.md` (this repository, root) —
  `PolicyDaSurchargePerByte`, `PolicyMaxDaBytesPerBlock`, non-coinbase
  `CORE_ANCHOR` rule.
- `POLICY_CORE_EXT_PREACTIVATION.md` (this repository, root) —
  `CORE_EXT` pre-activation guardrail (consistent with Stage F).
- `POLICY_STRUCTURED_LOGGING_MINIMUM.md` — future, owned by
  `rubin-protocol#1345`.
- `rubin-protocol#1341` — this overlay's tracking issue.
- `rubin-protocol#1335` … `rubin-protocol#1340` — implementation
  follow-ups (see §9).

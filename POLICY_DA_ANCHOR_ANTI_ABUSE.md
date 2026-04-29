# POLICY: DA/anchor anti-abuse

**Status:** NON-CONSENSUS / policy-only relay and mining guardrail
**Date:** 2026-04-28
**Revision:** post-review rc3
**Applies to:** mempool, relay, miner template builder
**Tracking issue:** `rubin-protocol#1343` (current rc3 replacement task; historical context: `rubin-protocol#353`)
**Canonical precedence:** `spec/RUBIN_L1_CANONICAL.md` remains the only source of consensus validity.

## 0. Merge Strategy

This file intentionally keeps the existing repository filename:

```text
rubin-protocol/POLICY_DA_ANCHOR_ANTI_ABUSE.md
```

Do not add a parallel file named `POLICY_DA_ANCHOR_ABUSE_ENFORCEMENT.md`.
The single-file invariant for this policy is absolute; any future
split requires explicit controller / governance approval, not a
self-certified migration.

This document is an expanded replacement for the existing policy file, not a sibling document.

All `spec/...` references in this document point to files in the
private `rubin-spec` repository (see `SPEC_LOCATION.md` in this repo
for the cross-repo convention), not in-repo paths.

### 0.1 Implementation Authorization Boundary

This document does NOT authorize implementation by itself. It is
policy text only and changes no code. Specifically:

- No Go DA/anchor relay implementation is added or modified by this file.
- No Rust parity is added or modified by this file.
- No conformance vectors are added by this file.
- No miner template runtime change is enacted by this file.
- No telemetry counter is registered by this file beyond declaring
  the names a future implementation MAY/SHOULD expose.

Any implementation slice MUST land in a separate PR scoped to the
specific code/conformance surface; this overlay only fixes the policy
contract.

### 0.2 Terminology

The terms below are used by this overlay but defined elsewhere; this
file does not redefine them:

- `tx_kind`, `weight(tx)`, `MAX_DA_BYTES_PER_BLOCK`,
  `MIN_RELAY_FEE_RATE`: `spec/RUBIN_L1_CANONICAL.md`.
- `min_da_fee_rate`, `MIN_RELAY_OUTPUT_VALUE`: `spec/RUBIN_NETWORK_PARAMS.md`
  §12.4 / §12.5.
- `current_mempool_min_fee_rate` (rolling local floor):
  `spec/RUBIN_MEMPOOL_POLICY.md` §10.
- `da_id`, `da_payload_len(tx)`, `DA_COMMIT_TX`, `DA_CHUNK_TX`,
  `COMPLETE_SET`, `STAGED_COMMIT`, DA orphan-pool parameters:
  `spec/RUBIN_COMPACT_BLOCKS.md` (DA relay state machine + parameters
  table).
- `CORE_ANCHOR`, `CORE_DA_COMMIT` covenant outputs:
  `spec/RUBIN_L1_CANONICAL.md` covenant-type definitions.

## 1. Decision

Production policy applies the following default guardrails:

```text
NonCoinbaseCoreAnchor = NON_STANDARD
# implemented in Go as `PolicyRejectNonCoinbaseAnchorOutputs = true`
# (clients/go/node/miner.go, clients/go/node/mempool.go); Rust parity
# `policy_reject_non_coinbase_anchor_outputs = true`
# (clients/rust/crates/rubin-node/src/txpool.rs,
#  clients/rust/crates/rubin-node/src/miner.rs)
PolicyMaxDaBytesPerBlock = MAX_DA_BYTES_PER_BLOCK / 4
# `MAX_DA_BYTES_PER_BLOCK` is the consensus DA cap defined by
# `spec/RUBIN_L1_CANONICAL.md`; this overlay does not redefine it.
PolicyDaSurchargePerByte = 0
min_da_fee_rate = 1
# normative spec/network-params constant
# (`spec/RUBIN_NETWORK_PARAMS.md` §12.4); NOT currently a separate
# implementation knob in the public Go/Rust nodes. DA-byte fee
# enforcement uses `PolicyDaSurchargePerByte` (above) as the entire
# per-byte DA fee floor (see §4 formula). An implementation that
# wants a non-zero per-byte DA fee floor MUST raise
# `PolicyDaSurchargePerByte` to a value at least `min_da_fee_rate`,
# not introduce a parallel knob.
```

These are policy controls only. They do not change consensus validity.

## 2. CORE_ANCHOR Policy

Reject as non-standard any non-coinbase transaction creating a `CORE_ANCHOR` output.

The coinbase witness commitment remains allowed and required by consensus.

## 3. CORE_DA_COMMIT Policy

A `CORE_DA_COMMIT` output is standard only inside `tx_kind = 0x01` DA commit transactions.

A DA commit transaction is standard only if:

1. It passes canonical parse.
2. It contains exactly one `CORE_DA_COMMIT` output.
3. It passes fee policy.
4. Its associated set can be handled by DA relay state rules.

Commitment matching to chunks is checked when a complete set is available for template inclusion or block validation. A lone relay commit without chunks is not rejected solely because payload commitment cannot yet be matched.

## 4. DA Fee Policy

For every DA-carrying transaction, the per-byte DA fee floor is:

```text
da_required_fee(tx) = da_payload_len(tx) * PolicyDaSurchargePerByte
```

When `PolicyDaSurchargePerByte = 0` (the §1 default), no DA-byte fee
floor is enforced. This matches the Go and Rust node implementations
(`clients/go/node/policy_da_anchor.go` and
`clients/rust/crates/rubin-node/src/txpool.rs`), which short-circuit
their DA fee check when the surcharge is zero.

The full admission fee formula is:

```text
required_fee(tx) = max(weight(tx) * current_mempool_min_fee_rate, da_required_fee(tx))
```

Reject as non-standard if:

```text
fee(tx) < required_fee(tx)
```

`current_mempool_min_fee_rate` is the rolling local floor maintained
by parent `spec/RUBIN_MEMPOOL_POLICY.md` §10 (raise after capacity
eviction, decay on connected-block events). The parent guarantees the
invariant `current_mempool_min_fee_rate >= MIN_RELAY_FEE_RATE`, so the
formula above is always at least as strict as the base relay-fee floor
and strictly stricter when the rolling floor is above the default.
This overlay does NOT redefine raise/decay behavior; it only points
implementers to the parent rolling floor as the effective gate. This
matches the sibling `POLICY_MEMPOOL_ADMISSION_GENESIS.md` Stage C fee
gate so both overlays share one fee contract.

`min_da_fee_rate` is the spec-side lower bound for any future
`PolicyDaSurchargePerByte` setting (`spec/RUBIN_NETWORK_PARAMS.md`
§12.4); an implementation that wants to enforce a non-zero per-byte DA
floor MUST raise `PolicyDaSurchargePerByte` to a value at least
`min_da_fee_rate`. The §4 formula does not add `min_da_fee_rate` as
an independent term, so the doc and the current node implementations
agree byte-for-byte.

Defaults / base parameters (constants are sourced from the documents
named below; this overlay does not redefine any of them):

```text
MIN_RELAY_FEE_RATE       = 1   # base/default floor; parent §10 owns
                                #   the effective rolling floor
                                #   current_mempool_min_fee_rate
min_da_fee_rate          = 1   # spec-side lower bound for
                                #   PolicyDaSurchargePerByte; not a
                                #   separate runtime knob
PolicyDaSurchargePerByte = 0   # operator-tunable per-byte DA fee
                                #   floor; 0 = disabled
```

Blocks with underpaying DA transactions remain consensus-valid if they satisfy consensus rules.

## 5. DA Template Budget

The miner template builder MUST enforce:

```text
Σ da_payload_len(tx) for tx in template <= PolicyMaxDaBytesPerBlock
```

`da_payload_len(tx)` is the same wire field used in the §4 fee
formulas (a byte count, see `spec/RUBIN_L1_CANONICAL.md` definition);
the §5 budget is the sum across all DA-carrying transactions selected
into the candidate template.

Default (matches the §1 defaults block; see §1 for the
`MAX_DA_BYTES_PER_BLOCK` source citation):

```text
PolicyMaxDaBytesPerBlock = MAX_DA_BYTES_PER_BLOCK / 4
```

This is intentionally below the consensus cap to reduce early-network abuse.

## 6. DA Set Replacement

Fee replacement of duplicate DA commits is forbidden.

For a given `da_id`:

1. First-seen commit is retained.
2. Later duplicate commits are discarded.
3. Higher fee does not replace the first commit.
4. Duplicate sender receives a peer-score penalty (the magnitude of
   the penalty is governed by the relay-policy peer-score system; this
   overlay does not redefine it).

## 7. DA Set Eviction

For `COMPLETE_SET` eviction:

```text
total_fee(da_id) = fee(DA_COMMIT_TX) + Σ fee(DA_CHUNK_TX[i])
```

Eviction key:

```text
total_fee(da_id) / total_bytes(da_id)
```

Eviction MUST be atomic by `da_id`.

## 8. Orphan Pool Policy

Use `spec/RUBIN_COMPACT_BLOCKS.md` orphan-state rules (values reproduced
verbatim from the parent-spec parameters table; this overlay does not
redefine them):

```text
DA_ORPHAN_POOL_SIZE = 64 MiB
DA_ORPHAN_POOL_PER_PEER_MAX = 4 MiB
DA_ORPHAN_POOL_PER_DA_ID_MAX = 8 MiB
DA_ORPHAN_TTL_BLOCKS = 3
```

Storm mode enters immediately when:

```text
orphan_pool_fill_pct > 90%
```

Storm mode exits after:

```text
orphan_pool_fill_pct < 70% for 3 consecutive accepted blocks
```

The exit hysteresis is expressed in block units (matching
`DA_ORPHAN_TTL_BLOCKS`) rather than wall-clock seconds so that storm
exit semantics remain deterministic across implementations and do not
depend on a specific monotonic time source.

## 9. Telemetry

When implemented, nodes SHOULD expose these metrics (a mix of
counters and gauges — counters end in `_total`; gauges are the
`_fill_pct`, `_bytes`, `_active` entries). This overlay declares the
logical telemetry surface; concrete Prometheus exports
MUST remain in the existing `rubin_node_` namespace/prefix used by
the Go and Rust nodes, so this overlay does not introduce a second,
conflicting metric namespace. The specific metric names listed below
are the required names for future exports of this telemetry surface
when implemented; this file does not authorize implementation:

```text
rubin_node_da_mempool_fill_pct
rubin_node_da_template_bytes
rubin_node_da_template_policy_cap_bytes
rubin_node_da_duplicate_commit_reject_total
rubin_node_da_orphan_pool_fill_pct
rubin_node_da_orphan_pool_per_peer_reject_total
rubin_node_da_orphan_pool_per_da_id_reject_total
rubin_node_da_storm_mode_active
```

Mempool-rejection metric names for the DA-underfee and non-coinbase
anchor rejection events are owned by
`POLICY_MEMPOOL_ADMISSION_GENESIS.md` §6
(`rubin_node_mempool_reject_da_underfee_total`,
`rubin_node_mempool_reject_anchor_nonstandard_total`); this file does
not duplicate them.

## 10. Escalation

The `144-block window` and `24 hours` thresholds in this section
describe operator-facing observation / escalation cadence, not
consensus-affecting hysteresis. Consensus-affecting timing in this
overlay — e.g., the §8 storm-mode exit hysteresis — is expressed in
block units instead.

For purposes of §10, **DA fill** is defined as the rolling average of
`rubin_node_da_template_bytes / PolicyMaxDaBytesPerBlock` (the
template-side fill against the policy cap; both metrics are exposed
in §9). Tying the threshold to the policy cap rather than the
consensus cap `MAX_DA_BYTES_PER_BLOCK` keeps two correctly-implemented
operators on the same trigger level and is consistent with the §10
mitigation actions (which all operate on policy-cap surfaces).

If DA fill exceeds 80% over a rolling 144-block window, nodes SHOULD emit a warning.

If DA fill exceeds 95% over 24 hours, operators SHOULD consider:

1. Raising `PolicyDaSurchargePerByte` locally — the operator-tunable
   per-byte DA fee floor (per §4: `da_required_fee(tx) =
   da_payload_len(tx) * PolicyDaSurchargePerByte`). Setting the
   surcharge to `S` enforces an `S`/byte DA fee floor; setting it to
   `0` (the §1 default) disables the DA-byte fee floor entirely.
   `min_da_fee_rate` itself is a normative spec/network-params
   constant — see §1 defaults block — not a separate implementation
   knob; an implementation that wants a non-zero floor MUST raise the
   surcharge to a value at least `min_da_fee_rate`.
2. Coordinating a network-wide relay policy update.
3. Reducing `PolicyMaxDaBytesPerBlock` temporarily.
4. Investigating peer-level DA abuse patterns.

No consensus change is required for these actions.

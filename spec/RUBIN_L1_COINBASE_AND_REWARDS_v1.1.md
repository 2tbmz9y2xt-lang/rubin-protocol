# RUBIN L1 Coinbase and Rewards v1.1 (auxiliary)

Status: NON-CONSENSUS (auxiliary notes)  
Date: 2026-02-16

This document collects auxiliary notes about coinbase construction, subsidy schedule, and long-term security budget design.

Normative consensus rules remain in:
- `spec/RUBIN_L1_CANONICAL_v1.1.md`

## Subsidy schedule

RUBIN v1.1 uses the subsidy function defined in CANONICAL (§4.5). Implementations MUST match the canonical definition and its integer arithmetic behavior at epoch boundaries.

## Long-term security budget: design rationale

### The problem

After block `N` (`SUBSIDY_DURATION_BLOCKS`), `block_subsidy() = 0` and miner revenue consists entirely of transaction fees. Whether fee revenue alone can sustain an adequate security budget is an open question — no major PoW chain has operated in this regime at scale.

Two prior approaches:

| Chain   | Approach | Tradeoff |
|---------|----------|----------|
| Bitcoin | Hard cap, fee-only after ~2140 | Clean supply guarantee; fee-security viability unproven |
| Monero  | Hardcoded perpetual tail emission (~0.6 XMR/block) | Guaranteed miner incentive; permanently inflationary, no community override |

### RUBIN's approach: deferred consensus decision

RUBIN v1.1 ships with a hard cap (`MAX_SUPPLY = 100,000,000 RBN`). Tail emission is not hardcoded — it is an option the network can activate through its standard governance mechanism.

If, after the emission window closes, the community determines that fee revenue is insufficient, a `tail_emission_v1` deployment can be proposed under VERSION_BITS (CANONICAL §8):

```
deployment_id:   tail_emission_v1
bit:             <assigned at proposal time>
start_height:    <any height ≥ N>
threshold:       1512  # 75% of WINDOW_SIZE=2016
feature_summary: "tail emission: block_subsidy() returns TAIL_CONSTANT after height N"
```

Activation flow: miners signal in block headers → 75% threshold over a 2016-block window → `LOCKED_IN` → next window `ACTIVE` → `block_subsidy()` returns `TAIL_CONSTANT` instead of 0.

This is a hardfork — all nodes must upgrade to follow the new subsidy rule. But the signaling threshold, activation height, and `TAIL_CONSTANT` value are published and measurable on-chain before activation, not a surprise flag day.

### Key distinction

Bitcoin cannot do this without an uncoordinated hardfork. Monero does not need to because the decision was made at launch. RUBIN makes the decision available to the network at the time it becomes relevant, using the same VERSION_BITS mechanism already present in v1.1 for all other consensus upgrades.

The founding team does not preset the answer. The default is a clean hard cap.

## Coinbase transaction

Coinbase maturity and coinbase-specific validation rules are defined in CANONICAL. This file is not a consensus source.


# RUBIN Theorem / Invariant Index v1.1 (placeholder)

Status: NON-NORMATIVE (pre-freeze placeholder)  
Date: 2026-02-16  
Audience: implementers + auditors

This index records consensus-critical invariants and their primary evidence sources (spec section + conformance vectors).

## T-001 — Sighash output_count=0 edge case

- Spec: `spec/RUBIN_L1_CANONICAL_v1.1.md` (§4.2, hashOutputs rule)
- Evidence: `conformance/fixtures/CV-SIGHASH.yml` (SIGHASH-06)

## T-002 — Difficulty retarget arithmetic width

- Spec: `spec/RUBIN_L1_CANONICAL_v1.1.md` (§6.4, ≥320-bit intermediate products)
- Evidence: `conformance/fixtures/CV-BLOCK.yml` (BLOCK-09)

## T-003 — VERSION_BITS boundary transition ordering

- Spec: `spec/RUBIN_L1_CANONICAL_v1.1.md` (§8, transition evaluation order)
- Evidence: `conformance/fixtures/CV-DEP.yml` (DEP-05)


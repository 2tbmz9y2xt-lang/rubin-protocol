# Rubin CORE_EXT Synthetic Conformance TZ

Status: follow-up implementation specification (separate track from parallel validation docs)  
Linked queue item: `Q-CONF-CORE-EXT-CV-01` (canonical queue lives in `rubin-orchestration-private/inbox/QUEUE.md`)

## 1) Purpose

Define a complete synthetic/conformance/parity package for `CORE_EXT` deployment profiles,
including activation boundaries, deterministic error mapping, parity behavior, and governance-grade release evidence.

This document is **consensus-sensitive test/specification guidance** for implementation and conformance lanes.

## 2) Scope Boundary

### In scope

- `CV-EXT-*` synthetic fixture families;
- executable conformance gates for Go and Rust;
- deterministic error-priority coverage;
- activation/pre-activation split validation;
- descriptor/genesis coherence checks;
- bounded formal refinement for deterministic branches;
- release evidence requirements for profile rollout.

### Out of scope

- redesign of native covenants;
- protocol throughput claims;
- consensus rollback automation;
- replacing consensus fixtures with policy-only checks.

## 3) Baseline Assumptions

1. `CORE_EXT` is a genesis-known covenant type.
2. Envelope format is canonical:

```text
ext_id:u16le || ext_payload_len:CompactSize || ext_payload:bytes[ext_payload_len]
```

3. Pre-activation spend path is witness-permissive (subject to structural validity).
4. Post-activation enforcement must apply `allowed_suite_ids`, `verification_binding`,
   canonical payload interpretation, and deterministic error mapping.
5. Duplicate ACTIVE profile resolution for the same `ext_id` at a height must reject deterministically.
6. Go is reference client; Rust is parity client.

## 4) Fixture Families (Required)

Minimum required families:

- `ENV`: envelope parse/length/value/max-size boundaries
- `ACT`: activation height transitions (`H-1`, `H`, `H+1`, undeclared profile)
- `PRE`: pre-activation permissive path behavior
- `ENF`: ACTIVE enforcement (`allowed_suite_ids`, binding, verifier outcomes)
- `PAY`: canonical payload interpretation and schema boundaries
- `ERR`: deterministic error mapping / error priority
- `DUP`: duplicate ACTIVE profile conflict semantics

Additional required families when `activation_height = 0` profile is used:

- `GEN`: genesis-active profile coherence and spend behavior

Parity family:

- `PAR`: Go vs Rust parity outcomes for valid/invalid/error-index equivalence

Optional policy-only family (kept separate from consensus validity):

- `POL`

## 5) Minimal Vector Schema

Each vector should include deterministic expectations:

```json
{
  "id": "CV-EXT-ERR-01",
  "gate": "CV-EXT",
  "family": "ERR",
  "op": "ext_spend",
  "height": 500000,
  "ext_id": 4096,
  "input": "...",
  "expect_ok": false,
  "expect_err": "TX_ERR_COVENANT_TYPE_INVALID"
}
```

Recommended extra fields:

- `deployment_state`
- `activation_height`
- `profile_name`
- `expect_first_invalid_tx_index`
- `genesis_ref`
- `descriptor_ref`

## 6) Determinism / Governance Rules

- Fixture IDs are globally unique and stable.
- Renaming an existing fixture ID is a breaking change.
- Changes to expected error behavior require changelog entry.
- Policy checks must not be mixed into consensus validity decisions.
- Any Go/Rust parity drift in `CV-EXT-*` is release-blocking.

## 7) Required Artifacts

Minimum expected artifacts:

- `conformance/fixtures/CV-EXT.json`
- `conformance/MATRIX.md` updates
- Go fixture routing/tests
- Rust parity routing/tests
- formal refinement artifacts for deterministic branches
- CI lane coverage for `CV-EXT` execution and parity

Recommended optional artifacts:

- `CV-EXT-GENESIS.json`
- `CV-EXT-POLICY.json`
- `CV-EXT-PERF.json`

## 8) CI and Validation Gates

Core gates:

- conformance bundle pass on `CV-EXT-*`;
- Go and Rust parity pass;
- descriptor/genesis coherence checks;
- deterministic error-priority checks;
- formal refinement lane for deterministic branches.

Coverage policy for new code in this track:

- **floor: `>=85%`**
- target: `>=95%`

If a branch is unreachable from public/runtime surface, explicitly document rationale.

## 9) Acceptance Criteria

Merge for this track is allowed only when all are true:

1. Required `CV-EXT` families are present.
2. Go conformance is green.
3. Rust parity is green.
4. Deterministic error-priority conflicts are resolved.
5. Formal refinement package for deterministic branches is green.
6. Coverage floor for new code is met (`>=85%`).
7. Descriptor/genesis coherence evidence is present.
8. Required approvals for consensus-impacting changes are recorded.

## 10) Blocker Taxonomy

### P0 (immediate stop)

- Go/Rust consensus-visible split;
- inconsistent activation decision;
- duplicate ACTIVE profile conflict not rejected deterministically;
- same vector producing different canonical error outcomes.

### P1 (promotion blocked)

- missing required fixture family;
- coverage below `85%` floor;
- no formal refinement lane for deterministic branch;
- missing descriptor/genesis coherence checks.

### P2 (tracked debt)

- missing operator narrative docs;
- incomplete benchmark corpus;
- incomplete telemetry narrative.

## 11) Work Breakdown Reference

Suggested work package (example):

- approve fixture taxonomy
- implement `CV-EXT` base set
- wire Go/Rust fixture execution
- add deterministic error-priority tests
- add descriptor/genesis coherence checks
- add parity CI lane
- add bounded formal refinement package
- assemble release signoff evidence

## 12) Separation Contract

This document is intentionally separate from parallel validation documentation.
It should be developed and merged as a dedicated CORE_EXT conformance track
without coupling to PV rollout doc updates.

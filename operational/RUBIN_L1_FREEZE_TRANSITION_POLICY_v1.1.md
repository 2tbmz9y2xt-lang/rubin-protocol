# RUBIN L1 Freeze Transition Policy (v1.1)

Status: NON-CONSENSUS  
Purpose: define how chain-instance profiles move from development artifacts to production-freeze eligibility.

**НУЖНО ОДОБРЕНИЕ КОНТРОЛЕРА:** production freeze and any mainnet-claim are only valid after explicit controller sign-off.

## 1) Scope

This policy applies to chain-instance documents in:

- `spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md`
- `spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_TESTNET_v1.1.md`
- `spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_MAINNET_v1.1.md`
- `spec/RUBIN_L1_DEPLOYMENTS_<network>_v1.1.md`
- `spec/RUBIN_L1_CONFORMANCE_MANIFEST_v1.1.md`
- `conformance/fixtures/RUBIN_L1_CONFORMANCE_BUNDLE_v1.1.yaml`

It does not change consensus rules.

## 2) State interpretation (non-consensus)

Use the status taxonomy from `operational/RUBIN_OPERATIONAL_SECURITY_v1.1.md §1.1`:

- `DEVELOPMENT (NON-CONSENSUS)`
- `DRAFT (NON-CONSENSUS)`
- `TEMPLATE (NON-CONSENSUS)`

For mainnet/testnet, `DRAFT` means:
1) integration-ready chain-profile,
2) explicit non-production status,
3) no freeze claim.

## 3) Transition procedure

### Phase A — DRAFT lock and publication package

Before any production claim, required artifacts must be available:

1. Canonical chain-instance profile with concrete, deterministic genesis bytes.
2. Deployment schedule file for chain instance (or explicit empty deployment statement).
3. Conformance bundle with all core gates `PASS`.
4. Closeout or governance note indicating non-production intent.
5. Formal methods posture:
   - Pre-freeze: `formal/` may be a placeholder (controller-approved 2026-02-16).
   - Freeze-eligible: `formal/` MUST contain real artifacts or a pointer to the authoritative formal repository + stable revision identifier.

### Phase B — Operational dry-run

Required checks:

1. Test run of both Go and Rust clients on reference build profile.
2. Witness of deterministic metrics pipeline and observer reproducibility.
3. No unresolved blockers from consensus/operational appendices in `DRAFT`.

### Phase C — Controller review

Controller review packet includes:

1. Status of conformance gates.
2. Verified genesis checksum publication.
3. Risk snapshot (`γ_obs`, `p_stale^{obs}`, orphan trend, incident triggers).
4. Explicit statement of no production freeze intent at this stage.

Only после этого controller may approve `RELEASE-READINESS`.

## 4) Release-Readiness conditions

`DRAFT` may be treated as production-freeze-eligible only when:

1. All Phase A + Phase B checks are complete.
2. At least two independent implementations run compatibility matrix.
3. No unresolved operational incidents at `P0/P1` severity from current-cycle audit.
4. Controller records a signed/public release decision with timestamp.

## 5) Rollback and downgrade

If any post-transition issue appears:

1. Controller can withdraw release decision immediately.
2. Network operators continue under `DRAFT` assumptions.
3. Incident response follows `operational/RUBIN_OPERATIONAL_SECURITY_v1.1.md` and `operational/RUBIN_RETL_INTEROP_FREEZE_CHECKLIST_v1.1.md` where applicable.

## 6) Current policy in this cycle

Current status remains `DEVELOPMENT/DRAFT (NON-CONSENSUS)` only:

- `DEVNET`: DEVELOPMENT
- `TESTNET`: DRAFT
- `MAINNET`: DRAFT
- Production freeze remains inactive.

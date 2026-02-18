# RUBIN L1 Conformance Manifest v1.1 (non-consensus)

Status: NON-CONSENSUS
Date: 2026-02-18
Updated: 2026-02-18

Purpose: define the conformance "release gate" bundle for deterministic cross-client behavior.

Source of truth for the bundle list:
- `conformance/fixtures/RUBIN_L1_CONFORMANCE_BUNDLE_v1.1.yaml`

## Gate Summary

| Gate | Required | Status | Vectors | Scope |
|------|----------|--------|---------|-------|
| CV-COMPACTSIZE | ✓ | PASS | — | consensus |
| CV-PARSE | ✓ | PASS | — | consensus |
| CV-SIGHASH | ✓ | PASS | — | consensus |
| CV-SIGCHECK | ✓ | PASS | — | consensus |
| CV-BIND | ✓ | PASS | — | consensus |
| CV-UTXO | ✓ | PASS | — | consensus |
| CV-DEP | ✓ | PASS | — | consensus |
| CV-BLOCK | ✓ | PASS | — | consensus |
| CV-REORG | ✓ | PASS | — | consensus |
| CV-FEES | ✓ | PASS | 3 | consensus |
| CV-HTLC | ✓ | PASS | 6 | consensus |
| CV-HTLC-ANCHOR | ✓ | PASS | 10 | consensus |
| CV-VAULT | ✓ | PASS | 9 | consensus |
| CV-WEIGHT | ✓ | PASS | 3 | consensus |
| CV-ANCHOR-RELAY | — | PENDING | 8 | policy-only |

**14 consensus gates — all PASS. 1 policy gate — PENDING (runner support needed).**

## What "PASS" means

A gate marked `PASS` means:
1. The fixture file exists in `conformance/fixtures/`.
2. All test vectors in it have been validated against the canonical spec.
3. At least one conforming runner (Go or Python) produces the expected outcomes.

A gate marked `PENDING` means the fixture file is complete but no automated runner
covers it yet (manual validation only).

## Runner Coverage

- `conformance/runner/run_cv_bundle.py` — primary Python runner (covers most consensus gates)
- `conformance/runner/run_cv_block.py` — Go-side CV-BLOCK runner
- CV-SIGHASH, CV-SIGCHECK: partial runner coverage (manual validation for cryptographic vectors)
- CV-ANCHOR-RELAY: policy vectors require relay-layer runner (not yet implemented)

## Release Gate Policy

Production freeze requires all **required=true** gates at **PASS**. Optional gates (CV-ANCHOR-RELAY)
must be at PASS or explicitly waived by controller before mainnet launch.

See also:
- `operational/RUBIN_L1_FREEZE_TRANSITION_POLICY_v1.1.md` — freeze gate criteria
- `operational/RUBIN_NODE_POLICY_DEFAULTS_v1.1.md §3.1` — anchor relay policy (CV-ANCHOR-RELAY source)

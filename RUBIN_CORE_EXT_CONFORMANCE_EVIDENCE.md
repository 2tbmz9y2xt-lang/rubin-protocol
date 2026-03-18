# RUBIN CORE_EXT Conformance Release Evidence Pack

Status: COMPLETE
Milestone: core-ext-conformance-v1
Date: 2026-03-18

## 1. Fixture Coverage

| Family | Vectors | Description | Status |
|--------|---------|-------------|--------|
| ENV | 4 | Envelope parse: valid, malformed, payload variants | PASS |
| ACT | 3 | Activation boundary: pre-activation, at-activation, undeclared | PASS |
| PRE | 3 | Pre-activation permissive: keyless, non-keyless, no profiles | PASS |
| ENF | 4 | ACTIVE enforcement: allowed/disallowed suite, sentinel, ext binding | PASS |
| PAY | 2 | Payload interpretation: 32-byte blob, empty | PASS |
| ERR | 3 | Error priority: parse-before-suite, too-short, suite error | PASS |
| DUP | 2 | Duplicate profile: same ext_id reject, different accept | PASS |
| GEN | 2 | Genesis-active (activation_height=0) enforcement | PASS |
| PAR | 2 | Go/Rust parity checks | PASS |
| **Total** | **25** | | **ALL PASS** |

Fixture file: `conformance/fixtures/CV-EXT.json`

## 2. Code Coverage

### New CORE_EXT code paths
- `clients/go/consensus/core_ext.go`: HasSuiteExported — covered by TestHasSuiteExported
- `clients/go/cmd/rubin-consensus-cli/runtime.go`: ext ops routing — covered by TestCVExtConformanceVectors (25/25)
- `clients/rust/crates/rubin-consensus-cli/src/main.rs`: ext ops routing — covered by run_cv_bundle.py parity

### Coverage gate
- Floor: >=85% (HARD GATE)
- Target: >=95%
- Status: PASS (CI codacy-coverage green on all PRs)

## 3. Deterministic Error-Priority Evidence

Error priority mapping (from CoreExtRefinement.lean):
1. ParseError (TX_ERR_COVENANT_TYPE_INVALID) — highest priority
2. SuiteDisallowed (TX_ERR_SIG_ALG_INVALID)
3. SigInvalid (TX_ERR_SIG_INVALID) — lowest priority

Proven properties:
- `parse_before_suite`: ParseError < SuiteDisallowed
- `suite_before_sig`: SuiteDisallowed < SigInvalid
- `parse_always_wins`: ParseError always wins against any error
- `error_selection_commutative`: deterministic regardless of check order

Evidence vectors: CV-EXT-ERR-01 (parse wins), CV-EXT-ERR-02 (parse wins), CV-EXT-ERR-03 (suite wins when parse ok)

## 4. Descriptor/Genesis Coherence

- Genesis-active profile (activation_height=0): CV-EXT-GEN-01 (accept), CV-EXT-GEN-02 (enforce reject)
- Formal: `genesis_active_at_zero` theorem proves Active state at height 0
- Duplicate profile rejection: CV-EXT-DUP-01 (reject), formal `duplicate_detected` theorem

## 5. Formal Refinement

Repository: rubin-formal (authoritative SOT)
File: `RubinFormal/CoreExtRefinement.lean`
PR: rubin-formal#152 (merged 9795e2c7)

Theorems (all proved, no sorry):
- Activation: active_at_activation, pre_active_before, activation_monotone, genesis_active_at_zero
- Error priority: parse_before_suite, suite_before_sig, error_selection_commutative, parse_always_wins
- Duplicate: duplicate_detected, no_duplicate_different_ids
- Suite auth, pre-activation permissive path

lake build: PASS

## 6. CI Gates

| Gate | Status | Evidence |
|------|--------|----------|
| gen_conformance_matrix.py --check | PASS | CV-EXT in MATRIX.md (25 vectors) |
| run_cv_bundle.py (Go) | PASS | 25/25 vectors |
| run_cv_bundle.py (Rust parity) | PASS | Go/Rust match on all vectors |
| check_formal_coverage.py | PASS | 43 fixtures covered |
| check_formal_refinement_bridge.py | PASS | 4 critical ops |
| check_lean_conformance_staleness.py | PASS | 28 files checked |
| lake build (rubin-formal) | PASS | CoreExtRefinement.lean compiled |
| Codacy coverage | PASS | New code >=85% |

## 7. PR Chain

| # | QID | PR | Status |
|---|-----|----|--------|
| 1 | Q-CONF-CORE-EXT-CV-01 | rubin-protocol#750 | MERGED |
| 2 | Q-CONF-CORE-EXT-CV-02 | rubin-protocol#753 | MERGED |
| 3 | Q-CONF-CORE-EXT-RUNNER-01 | rubin-protocol#755 | MERGED |
| 4 | Q-CONF-CORE-EXT-MATRIX-CI-01 | evidence (PRs 750/753/755) | DONE |
| 5 | Q-FORMAL-CORE-EXT-01 | rubin-formal#152 | MERGED |
| 6 | Q-CONF-CORE-EXT-EVIDENCE-01 | this document | DONE |

## 8. Signoff Checklist

- [x] Required CV-EXT families present (9/9)
- [x] Go conformance green (25/25)
- [x] Rust parity green (25/25)
- [x] Deterministic error-priority conflicts resolved (formal proof)
- [x] Formal refinement package green (lake build PASS)
- [x] Coverage floor met (>=85%)
- [x] Descriptor/genesis coherence evidence present
- [x] CI gates all green
- [x] MATRIX.md up to date
- [x] Release-blocking in validator gate

## 9. Cross-Repo Closure Bundle

Per CROSS_REPO_CLOSURE_POLICY.md:
- Spec: N/A (CORE_EXT conformance, no spec changes)
- Implementation: PRs #750, #753, #755 in rubin-protocol
- Conformance: CV-EXT.json (25 vectors, 9 families)
- Formal: rubin-formal#152 (CoreExtRefinement.lean)
- Closeout report: this document
- QUEUE.md: all Q-CONF-CORE-EXT-* → DONE

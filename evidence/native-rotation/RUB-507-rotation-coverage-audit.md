# RUB-507 Native Rotation Coverage Audit

Status: evidence artifact only.

Issue: RUB-507.

Protocol repository inspected: `rubin-protocol` at
`2aa15ff31bdbbed2ac8da249a8ae78a8fc514614`.

Normative source inspected: `2tbmz9y2xt-lang/rubin-spec`,
`origin/main` at `167efa60d39a1a69c0d253f79def461fd307fa4b`,
`spec/RUBIN_NATIVE_CRYPTO_ROTATION_SPEC_v1.md`.

Non-goals for this audit:

- No Go implementation changes.
- No Rust implementation changes.
- No conformance fixture changes.
- No formal artifact regeneration.
- No activation or governance decision.

## Method

This report maps each observed normative rule in
`RUBIN_NATIVE_CRYPTO_ROTATION_SPEC_v1` to implementation and coverage evidence
in the protocol repository. Rows marked `COVERED` have a direct implementation
and at least one test, fixture, or formal replay artifact. Rows marked `GAP`
have no observed direct implementation, no observed executable coverage, or an
observed drift between evidence sources.

## Coverage Map

| Rule | Spec evidence | Go evidence | Rust evidence | Test / vector evidence | Status |
| --- | --- | --- | --- | --- | --- |
| Rotation introduces `NATIVE_CREATE_SUITES(h)` and `NATIVE_SPEND_SUITES(h)`. | Spec lines 66-79. | `clients/go/consensus/suite_registry.go:100-224`; `clients/go/consensus/rotation_descriptor.go:135-165`. | `clients/rust/crates/rubin-consensus/src/suite_registry.rs:98-169`; `clients/rust/crates/rubin-consensus/src/suite_registry.rs:228-257`. | `clients/go/consensus/suite_registry_test.go`; `clients/rust/crates/rubin-consensus/src/tests/suite_registry.rs`. | COVERED. |
| Descriptor carries old suite, new suite, H1, H2, optional H4; H1 < H2; if H4 is present, H4 > H2. | Spec lines 82-92, 401-421. | `clients/go/consensus/rotation_descriptor.go:5-76`. | `clients/rust/crates/rubin-consensus/src/suite_registry.rs:171-220`. | `conformance/fixtures/CV-NATIVE-ROTATION-DESCRIPTOR.json:1-214`; Go/Rust descriptor tests. | COVERED. |
| v1 production profile requires finite H4 for mainnet/testnet. | Spec lines 94-107, 178-197, 347-349. | `clients/go/consensus/rotation_production.go:8-69`; `clients/go/node/production_rotation_schedule.go:153-177`. | `clients/rust/crates/rubin-consensus/src/suite_registry.rs:326-411`; `clients/rust/crates/rubin-node/src/production_rotation_schedule.rs:86-153`. | `clients/go/consensus/rotation_production_test.go`; `clients/go/node/production_rotation_schedule_test.go`; `clients/rust/crates/rubin-node/src/production_rotation_schedule.rs:274-584`. | COVERED for validation path. Production activation descriptor coverage is deferred until a controller-approved non-empty schedule exists. |
| Production lifecycle keeps live native suite universe capped to old/new. | Spec lines 101-106. | `clients/go/consensus/suite_registry.go:100-160`; `clients/go/consensus/rotation_descriptor.go:124-165`. | `clients/rust/crates/rubin-consensus/src/suite_registry.rs:98-145`; `clients/rust/crates/rubin-consensus/src/suite_registry.rs:260-265`. | Suite-set cardinality tests in Go/Rust; descriptor conformance vectors. | COVERED. |
| Phase 0: before H1, create and spend sets are `{old}`. | Spec lines 112-123, 423-438. | `clients/go/consensus/rotation_descriptor.go:135-165`. | `clients/rust/crates/rubin-consensus/src/suite_registry.rs:228-257`. | `CV-NATIVE-ROTATION-CREATE`, `CV-NATIVE-ROTATION-CUTOFF`, `CV-NATIVE-ROTATION-SPEND`. | COVERED, but exact set-output CV coverage is partial; see GAP-01. |
| Phase 1: at H1, create and spend sets are `{old,new}`. | Spec lines 126-140, 429-430. | `clients/go/consensus/rotation_descriptor.go:140-164`. | `clients/rust/crates/rubin-consensus/src/suite_registry.rs:230-256`. | JSON fixtures expect new spend at H2-1 to be accepted in `conformance/fixtures/CV-NATIVE-ROTATION-SPEND.json:37-70`. | GAP: formal replay stubs still expect reject for the same H2-1 new-suite spend; see GAP-04. |
| Phase 2: at H2, create set is `{new}`, spend set remains `{old,new}`. | Spec lines 144-160, 431-432. | `clients/go/consensus/rotation_descriptor.go:135-165`. | `clients/rust/crates/rubin-consensus/src/suite_registry.rs:228-257`. | `conformance/fixtures/CV-NATIVE-ROTATION-CUTOFF.json:1-199`. | COVERED by clients and JSON fixtures; formal replay drift exists for CUTOFF-02; see GAP-04. |
| Phase 4: at H4, create and spend sets are `{new}`. | Spec lines 178-197, 433. | `clients/go/consensus/rotation_descriptor.go:151-165`. | `clients/rust/crates/rubin-consensus/src/suite_registry.rs:244-257`. | `conformance/fixtures/CV-NATIVE-ROTATION-SUNSET.json:1-168`. | COVERED by clients and JSON fixtures; formal replay drift and missing reject error pins exist; see GAP-02 and GAP-04. |
| `verify_sig` uses the full native suite registry; height gating happens before signature verification. | Spec lines 201-225, 455-471. | `clients/go/consensus/verify_sig_openssl.go:556-578`; sequential gates before verify at `clients/go/consensus/spend_verify.go:131-157`, `clients/go/consensus/spend_verify.go:182-227`, `clients/go/consensus/htlc.go:204-229`, `clients/go/consensus/stealth.go:69-82`; queued gates at `clients/go/consensus/sig_verify_queued.go:60-99`, `clients/go/consensus/sig_verify_queued.go:107-171`, `clients/go/consensus/sig_verify_queued.go:176-299`, `clients/go/consensus/sig_verify_queued.go:303-342`. | `clients/rust/crates/rubin-consensus/src/verify_sig_openssl.rs:326-340`; `clients/rust/crates/rubin-consensus/src/verify_sig_openssl/binding.rs:128-152`; gates at `clients/rust/crates/rubin-consensus/src/spend_verify.rs:119-145`, `clients/rust/crates/rubin-consensus/src/spend_verify.rs:354-403`, `clients/rust/crates/rubin-consensus/src/htlc.rs:294-330`, `clients/rust/crates/rubin-consensus/src/stealth.rs:119-198`. | Verify-sig registry tests and rotation spend tests. | COVERED for implementation paths. Shared CV spend op does not exercise these covenant validators end-to-end; see GAP-03. |
| CORE_P2PK create rule: output suite must be in `NATIVE_CREATE_SUITES(h)`. | Spec lines 229-235, 473-489. | `clients/go/consensus/covenant_genesis.go:47-58`. | `clients/rust/crates/rubin-consensus/src/covenant_genesis.rs:28-47`. | `CV-NATIVE-ROTATION-CREATE`; `CV-NATIVE-ROTATION-CUTOFF`; Go/Rust covenant-genesis tests. | COVERED. |
| CORE_P2PK spend rule: witness suite matches covenant data and is in `NATIVE_SPEND_SUITES(h)`. | Spec lines 237-243, 455-471. | Sequential path `clients/go/consensus/spend_verify.go:131-157`; queued path `clients/go/consensus/sig_verify_queued.go:60-99`. | `clients/rust/crates/rubin-consensus/src/spend_verify.rs:119-145`; key binding at `clients/rust/crates/rubin-consensus/src/spend_verify.rs:177-188`. | `CV-NATIVE-ROTATION-SPEND`; Go/Rust P2PK spend tests. | COVERED. |
| CORE_MULTISIG spend uses native spend set. | Spec lines 247-251, 455-471. | Dispatch from spend path at `clients/go/consensus/utxo_basic.go:350-370`; sequential threshold path at `clients/go/consensus/spend_verify.go:182-227`; queued threshold path at `clients/go/consensus/sig_verify_queued.go:107-171`. | Threshold path: `clients/rust/crates/rubin-consensus/src/spend_verify.rs:330-424`; dispatch in `clients/rust/crates/rubin-consensus/src/utxo_basic.rs:407-422`. | `CV-NATIVE-ROTATION-SPEND` carries MULTISIG membership rows. | GAP: no observed same-suite/no-mixed enforcement for multi-signature threshold slots when both old and new are live. See GAP-05. |
| CORE_HTLC selector is sentinel; HTLC signature uses a native spend suite. | Spec lines 255-259, 455-471. | Sequential selector check `clients/go/consensus/htlc.go:141-154`; sequential signature gate `clients/go/consensus/htlc.go:204-229`; queued path `clients/go/consensus/sig_verify_queued.go:176-299`. | Selector check `clients/rust/crates/rubin-consensus/src/htlc.rs:176-190`; signature gate `clients/rust/crates/rubin-consensus/src/htlc.rs:294-330`. | `CV-NATIVE-ROTATION-SPEND`; Go/Rust HTLC tests. | COVERED for the single native signature slot. |
| CORE_STEALTH spend uses a suite from `NATIVE_SPEND_SUITES(h)`. | Spec lines 263-266, 455-471. | Sequential path `clients/go/consensus/stealth.go:53-90`; queued path `clients/go/consensus/sig_verify_queued.go:303-342`. | `clients/rust/crates/rubin-consensus/src/stealth.rs:119-198`. | `CV-NATIVE-ROTATION-SPEND`; Go/Rust stealth tests. | COVERED. |
| CORE_VAULT owner authentication validates signatures according to `NATIVE_SPEND_SUITES(h)`. | Spec lines 270-273, 455-471. | Vault uses threshold signature validation at `clients/go/consensus/utxo_basic_vault.go:83-99`, which calls sequential threshold path `clients/go/consensus/spend_verify.go:182-227`; queued worker path uses `clients/go/consensus/sig_verify_queued.go:107-171`. | Vault dispatch at `clients/rust/crates/rubin-consensus/src/utxo_basic.rs:424-435`; vault threshold check at `clients/rust/crates/rubin-consensus/src/utxo_basic.rs:604-622`; threshold gate at `clients/rust/crates/rubin-consensus/src/spend_verify.rs:354-403`. | `CV-NATIVE-ROTATION-SPEND`; Go/Rust vault tests. | COVERED for native spend membership. Same-suite semantics are not explicit for VAULT in spec text but share threshold machinery; see GAP-05 follow-up. |
| Weight accounting becomes suite-aware without changing block weight limits. | Spec lines 277-289. | `clients/go/consensus/block_basic_weight.go:264-305`. | `clients/rust/crates/rubin-consensus/src/block_basic/weight.rs:124-164`. | `conformance/fixtures/CV-NATIVE-ROTATION-WEIGHT.json`; Go/Rust weight registry tests. | COVERED. |
| Reserved conformance gates must cover H1-1, H1, H2-1, H2, H4-1, H4. | Spec lines 293-317. | Runner support: `conformance/runner/run_cv_bundle.py:1688-1715`, `conformance/runner/run_cv_bundle.py:2049-2057`; Go CLI ops `clients/go/cmd/rubin-consensus-cli/runtime.go:1840-1925`. | Rust CLI ops `clients/rust/crates/rubin-consensus-cli/src/main.rs:2696-2864`. | Matrix rows `conformance/MATRIX.md:40-45`; fixtures under `conformance/fixtures/CV-NATIVE-ROTATION-*.json`. | PARTIAL. Existing gates cover several boundary points, but exact set-output rows and end-to-end covenant-family rows are missing; see GAP-01 and GAP-03. |
| Formal scope must cover deterministic lifecycle, create cutoff, spend sunset, and absence of mixed-suite behavior. | Spec lines 321-330 and 396-528. | Not applicable as implementation evidence. | Not applicable as implementation evidence. | Formal conformance replay files exist under `rubin-formal/RubinFormal/Conformance/CVNativeRotation*`. `rubin-formal/proof_coverage.json:10-199` has no native-rotation section entry. | GAP: formal model/replay is present but stale/partial relative to current spec and JSON fixtures; see GAP-04 and GAP-06. |
| Governance requires controller approval before activation. | Spec lines 334-365. | Production schedule is empty/default for mainnet/testnet in `conformance/fixtures/protocol/production_rotation_schedule_v1.json:1-7`; Go loader enforces allowed networks and default registry in `clients/go/node/production_rotation_schedule.go:101-177`, `clients/go/node/production_rotation_schedule.go:258-279`. | Rust loader enforces the same in `clients/rust/crates/rubin-node/src/production_rotation_schedule.rs:105-180`. | Production schedule tests in Go/Rust node packages. | COVERED for no-activation default state. Actual activation evidence is intentionally absent until controller approval. |
| Native rotation is separate from CORE_EXT replacement. | Spec lines 60-62, 369-377, 511-528. | Native P2PK/multisig/HTLC/stealth/vault paths consume rotation providers directly rather than CORE_EXT profiles; CORE_EXT remains in `clients/go/consensus/core_ext.go`. | Native paths consume `RotationProvider` directly; CORE_EXT remains in `clients/rust/crates/rubin-consensus/src/core_ext.rs`. | No dedicated CV or formal invariant observed for FI-ROT-07. | GAP for dedicated proof/vector coverage, not for observed native implementation routing. |

## Gap List

### GAP-01: No exact set-output conformance vectors

The runner and both CLIs support `rotation_native_create_suites` and
`expect_suite_ids` (`conformance/runner/run_cv_bundle.py:1688-1715`,
`conformance/runner/run_cv_bundle.py:2049-2057`,
`clients/go/cmd/rubin-consensus-cli/runtime.go:1871-1895`,
`clients/rust/crates/rubin-consensus-cli/src/main.rs:2755-2804`), but no current
`CV-NATIVE-ROTATION-*` fixture uses `rotation_native_create_suites`.

Proposed vector family for RUB-463B/RUB-508:

- `CV-NATIVE-ROTATION-SETS`
- Rows for H1-1, H1, H2-1, H2, H4-1, H4.
- Assert exact sorted `expect_suite_ids` for create and, if a spend-set CLI op is added, spend.

### GAP-02: Rotation fixture expectation metadata is incomplete/stale

Observed JSON fixture rejects without `expect_err`:

- `conformance/fixtures/CV-NATIVE-ROTATION-CUTOFF.json:37-68`
- `conformance/fixtures/CV-NATIVE-ROTATION-SUNSET.json:37-69`
- `conformance/fixtures/CV-NATIVE-ROTATION-SUNSET.json:71-101`
- `conformance/fixtures/CV-NATIVE-ROTATION-SUNSET.json:135-166`

The runner checks `expect_err` only when the field exists
(`conformance/runner/run_cv_bundle.py:1995-2007`), so these rows prove reject
parity but not the normalized error code.

Observed JSON fixture accepts with stale `expect_err`:

- `conformance/fixtures/CV-NATIVE-ROTATION-SPEND.json:37-70`
- `conformance/fixtures/CV-NATIVE-ROTATION-SPEND.json:135-168`
- `conformance/fixtures/CV-NATIVE-ROTATION-SPEND.json:233-266`
- `conformance/fixtures/CV-NATIVE-ROTATION-SPEND.json:331-364`

Those rows are valid accepts under current Phase 1 spend semantics, but
`expect_err` is ignored on successful rows by the runner and should not remain
as stale negative metadata.

Proposed vector update:

- Add `expect_err: "TX_ERR_SIG_ALG_INVALID"` to the reject rows above unless a
  stronger canonical error-code decision says otherwise.
- Remove `expect_err` from accepted overlap-window rows, or add fixture policy
  that rejects `expect_err` whenever `expect_ok` is true.

### GAP-03: Shared spend CVs do not execute covenant validators end-to-end

`rotation_spend_suite_check` requires `covenant_type` in the runner
(`conformance/runner/run_cv_bundle.py:1701-1715`), but both CLI
implementations only validate descriptor membership and do not dispatch into
P2PK/MULTISIG/HTLC/STEALTH/VAULT spend validators:

- Go: `clients/go/cmd/rubin-consensus-cli/runtime.go:1897-1925`
- Rust: `clients/rust/crates/rubin-consensus-cli/src/main.rs:2806-2864`

This is adequate for set membership parity, but it does not prove the
covenant-specific gates cited in this report.

Proposed vector family:

- `CV-NATIVE-ROTATION-SPEND-END2END`
- Minimal signed/invalid transactions per native covenant type.
- Include old/new suite acceptance at H1/H2 and old-suite rejection at H4.

### GAP-04: Formal conformance stubs drift from current JSON/spec

Observed drift:

- `rubin-formal/RubinFormal/Conformance/CVNativeRotationCutoffVectors.lean:14-20`
  still expects `NATIVE-ROT-CUTOFF-02` old-suite create at H2 to be accepted,
  while JSON expects reject in
  `conformance/fixtures/CV-NATIVE-ROTATION-CUTOFF.json:37-68`.
- `rubin-formal/RubinFormal/Conformance/CVNativeRotationSunsetVectors.lean:14-19`
  still expects SUNSET-02, SUNSET-03, and SUNSET-05 to be accepted, while JSON
  expects reject in `conformance/fixtures/CV-NATIVE-ROTATION-SUNSET.json`.
- `rubin-formal/RubinFormal/Conformance/CVNativeRotationSpendVectors.lean:18-34`
  expects new-suite spend at H2-1 to reject, while current spec Phase 1 allows
  spend `{old,new}` at H1 (`spec` lines 126-140).

Proposed follow-up:

- Regenerate or replace the manual Lean stubs from current JSON fixtures and
  current `RUBIN_NATIVE_CRYPTO_ROTATION_SPEC_v1`.
- Add a drift check so generated formal vector files cannot diverge from JSON.

### GAP-05: MULTISIG same-suite/no-mixed rule is not closed

Spec requires no mixed-suite multisig in v1 (`spec` lines 247-251), and formal
scope includes absence of mixed-suite behavior (`spec` lines 321-330). The
observed Go/Rust threshold validators gate each non-sentinel witness against
`NATIVE_SPEND_SUITES(h)` and the registry, but no same-suite accumulator or
mixed-suite reject path was observed:

- Go: `clients/go/consensus/spend_verify.go:182-227` and
  `clients/go/consensus/sig_verify_queued.go:107-171`
- Rust: `clients/rust/crates/rubin-consensus/src/spend_verify.rs:354-403`

This is an implementation/spec coverage gap, not fixed by this report.

Proposed vector family:

- `CV-NATIVE-ROTATION-MULTISIG-MIXED`
- A threshold multisig transaction with old+new witness suites during the
  overlap window.
- Expected result under the current spec is reject. If that is not intended,
  the spec must be revised before activation rather than treating mixed-suite
  acceptance as an implementation option.

### GAP-06: Formal proof coverage has no native-rotation section entry

`rubin-formal/proof_coverage.json:10-199` lists existing coverage sections, but
no native-rotation section entry was observed. There are conformance replay
files for rotation, but they are not reflected as a formal coverage claim and
currently drift from the JSON fixtures.

Proposed follow-up:

- Add native rotation to `proof_coverage.json` only after GAP-04 is repaired.
- Keep claim level bounded to executable replay/refinement unless dedicated
  FI-ROT proofs are added.

### GAP-07: Production schedule has only the no-activation/default state

The committed protocol production schedule fixture has empty mainnet/testnet
slots. That is correct for no activation, and both clients validate/default it,
but there is no non-empty controller-approved lifecycle descriptor to audit.

Proposed follow-up:

- When controller approval exists, add a non-empty production schedule fixture
  covering the full H1 -> H2 -> H4 lifecycle and keep it tied to governance
  evidence.

## Recommended Queue

1. Repair formal/vector drift first (GAP-04), because it can give false green
   evidence.
2. Add exact set-output vectors and error pins (GAP-01, GAP-02).
3. Close the MULTISIG same-suite implementation/vector gap against the current
   spec-required reject semantics, or revise the spec before activation (GAP-05).
4. Add end-to-end spend vectors per covenant family (GAP-03).
5. Add formal coverage registry entries only after generated/vector drift is
   gone (GAP-06).
6. Leave production activation schedule empty until governance evidence exists
   (GAP-07).

## Audit Boundary

This artifact reports observed evidence and gaps only. It does not change
consensus behavior, policy behavior, conformance fixtures, generated formal
artifacts, or production activation state.

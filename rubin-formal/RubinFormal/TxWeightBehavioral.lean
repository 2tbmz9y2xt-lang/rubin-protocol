import RubinFormal.TxWeightV2
import RubinFormal.CriticalInvariants
import RubinFormal.Conformance.CVWeightReplay

/-!
# Weight Accounting Behavioral Proofs (§9)

LIVE behavioral proofs on the weight formula from `TxWeightV2.lean`.
Bridges the decomposed weight computation (base/witness/DA/signature)
to the abstract `weight` model in `CriticalInvariants.lean` and the
conformance replay in `CVWeightReplay.lean`.

Evidence level: machine_checked_behavioral for the shared §9 row:
the live formula is behaviorally decomposed and bridged to the abstract model,
then replayed on CV-WEIGHT vectors; this is stronger than a narrow contract
but still not a monadic end-to-end proof.
Combines:

1. Constant pins: WITNESS_DISCOUNT_DIVISOR, VERIFY_COST_ML_DSA_87, VERIFY_COST_UNKNOWN_SUITE
2. Formula decomposition: live weight = 4*base + witness + da + sigCost
3. Abstract model bridge: live formula ↔ CriticalInvariants.weight
4. DA component behavioral: kind=0 → daBytes=0, compactSizeLen properties
5. SigCost decomposition: mlCount*8 + unknownCount*64
6. Conformance replay: cv_weight_vectors_pass (native_decide on real vectors)

Go equivalent: CalcTxWeight (consensus/tx_weight.go)
Rust equivalent: calc_tx_weight (rubin-consensus/src/tx_weight.rs)
-/

namespace RubinFormal
open TxWeightV2

/-! ## §9 Constants — canonical literal pins

Pin the spec constants to their literal values so symbolic rewrites
cannot silently mask constant drift between spec revisions.
-/

/-- WITNESS_DISCOUNT_DIVISOR canonical literal pin (CANONICAL §9). -/
theorem weight_discount_divisor_value : WITNESS_DISCOUNT_DIVISOR = 4 := rfl

/-- VERIFY_COST_ML_DSA_87 canonical literal pin (CANONICAL §9). -/
theorem weight_verify_cost_ml_dsa_value : VERIFY_COST_ML_DSA_87 = 8 := rfl

/-- VERIFY_COST_UNKNOWN_SUITE canonical literal pin (CANONICAL §9). -/
theorem weight_verify_cost_unknown_suite_value : VERIFY_COST_UNKNOWN_SUITE = 64 := rfl

/-- MAX_WITNESS_ITEMS canonical literal pin (CANONICAL §9). -/
theorem weight_max_witness_items_value : MAX_WITNESS_ITEMS = 1024 := rfl

/-- MAX_WITNESS_BYTES_PER_TX canonical literal pin (CANONICAL §9). -/
theorem weight_max_witness_bytes_value : MAX_WITNESS_BYTES_PER_TX = 100000 := rfl

/-! ## Weight formula — pure decomposition function

Extract the weight computation as a pure function of its four components,
matching the final `let weight := ...` in `txWeightAndStats`.
This is the normative §9 formula: weight = 4*base + witness + da + sigCost.
-/

/-- Pure weight formula matching the live computation in `txWeightAndStats`.
    Inputs: baseSize (bytes before witness), witnessSize (witness section bytes),
    daSize (compactSize + DA payload bytes), sigCost (verification cost sum). -/
def computeWeight (baseSize witnessSize daSize sigCost : Nat) : Nat :=
  WITNESS_DISCOUNT_DIVISOR * baseSize + witnessSize + daSize + sigCost

/-- Pure signature cost formula matching the live computation in `txWeightAndStats`.
    Inputs: mlCount (ML-DSA-87 witness items), unknownCount (unknown suite items). -/
def computeSigCost (mlCount unknownCount : Nat) : Nat :=
  mlCount * VERIFY_COST_ML_DSA_87 + unknownCount * VERIFY_COST_UNKNOWN_SUITE

/-! ## Formula equivalence: live ↔ abstract model

Bridge the live 4-component formula to the abstract 3-component `weight`
in CriticalInvariants.lean: `weight(base, witness, sigCost) = base*4 + witness + sigCost`.
The abstract model lumps witnessSize + daSize into the "witness" parameter.
-/

/-- Live weight formula equals the abstract model when witness+DA are combined.
    This bridges `computeWeight` to `CriticalInvariants.weight`. -/
theorem weight_formula_bridges_abstract (baseSize witnessSize daSize sigCost : Nat) :
    computeWeight baseSize witnessSize daSize sigCost =
    RubinFormal.weight baseSize (witnessSize + daSize) sigCost := by
  unfold computeWeight RubinFormal.weight WITNESS_DISCOUNT_DIVISOR
  omega

/-- Commutativity: base*4 = 4*base in the weight formula. -/
theorem weight_base_commutes (baseSize witnessSize daSize sigCost : Nat) :
    computeWeight baseSize witnessSize daSize sigCost =
    baseSize * 4 + witnessSize + daSize + sigCost := by
  unfold computeWeight WITNESS_DISCOUNT_DIVISOR
  omega

/-! ## Signature cost decomposition

The sigCost in the weight formula decomposes as:
  sigCost = mlCount * 8 + unknownCount * 64

This is the pre-rotation signature cost model.  Post-rotation uses
`WeightSuiteAware.totalSigCost` with registry lookups.
-/

/-- Signature cost with zero ML-DSA items is entirely from unknown suites. -/
theorem sigCost_zero_ml (unknownCount : Nat) :
    computeSigCost 0 unknownCount = unknownCount * VERIFY_COST_UNKNOWN_SUITE := by
  unfold computeSigCost
  simp

/-- Signature cost with zero unknown suites is entirely from ML-DSA. -/
theorem sigCost_zero_unknown (mlCount : Nat) :
    computeSigCost mlCount 0 = mlCount * VERIFY_COST_ML_DSA_87 := by
  unfold computeSigCost
  simp

/-- Signature cost is zero when both counts are zero. -/
theorem sigCost_zero : computeSigCost 0 0 = 0 := by
  unfold computeSigCost VERIFY_COST_ML_DSA_87 VERIFY_COST_UNKNOWN_SUITE
  simp

/-- Concrete check: single ML-DSA-87 witness → sigCost = 8. -/
theorem sigCost_single_ml : computeSigCost 1 0 = 8 := by native_decide

/-- Concrete check: single unknown suite witness → sigCost = 64. -/
theorem sigCost_single_unknown : computeSigCost 0 1 = 64 := by native_decide

/-- Signature cost is monotone in ML-DSA count. -/
theorem sigCost_monotone_ml (m1 m2 unknownCount : Nat) (h : m1 ≤ m2) :
    computeSigCost m1 unknownCount ≤ computeSigCost m2 unknownCount := by
  unfold computeSigCost
  exact Nat.add_le_add_right (Nat.mul_le_mul_right _ h) _

/-- Signature cost is monotone in unknown suite count. -/
theorem sigCost_monotone_unknown (mlCount u1 u2 : Nat) (h : u1 ≤ u2) :
    computeSigCost mlCount u1 ≤ computeSigCost mlCount u2 := by
  unfold computeSigCost
  exact Nat.add_le_add_left (Nat.mul_le_mul_right _ h) _

/-! ## DA component behavioral properties

The DA section contributes daSize = compactSizeLen(daLen) + daLen to weight.
For kind=0 (standard) transactions, daLen = 0 is enforced, making daBytes = 0.
-/

/-- compactSizeLen(0) = 1 (single-byte encoding for zero). -/
theorem compactSizeLen_zero : compactSizeLen 0 = 1 := by
  unfold compactSizeLen
  simp

/-- compactSizeLen for small values (< 0xfd) is always 1. -/
theorem compactSizeLen_small (n : Nat) (h : n < 0xfd) : compactSizeLen n = 1 := by
  unfold compactSizeLen
  simp [show ¬(0xfd ≤ n) from by omega]

/-- DA size contribution for kind=0: daLen=0 → daSize = 1.
    In kind=0 txs, `txWeightAndStats` enforces daLen = 0, so
    daSize = compactSizeLen 0 + 0 = 1. -/
theorem daSize_kind0 : compactSizeLen 0 + 0 = 1 := by
  simp [compactSizeLen_zero]

/-- When daLen = 0, the daBytes output is 0 regardless of kind.
    Models the live expression `daBytes := if txKind == 0x00 then 0 else daLen`
    from `txWeightAndStats` — under the `daLen = 0` precondition enforced for
    kind=0 txs, both branches collapse to 0. -/
theorem daBytes_zero_when_daLen_zero (txKind daLen : Nat) (h : daLen = 0) :
    (if txKind == 0x00 then 0 else daLen) = 0 := by
  subst h; split <;> rfl

/-! ## Weight formula monotonicity (4-component)

Full monotonicity over each individual component of the live formula,
extending the 3-component monotonicity from CriticalInvariants/UniversalInvariants
to the 4-component decomposition that matches the actual implementation.
-/

/-- Weight is monotone in baseSize (4x multiplier). -/
theorem computeWeight_monotone_base (b1 b2 w d s : Nat) (h : b1 ≤ b2) :
    computeWeight b1 w d s ≤ computeWeight b2 w d s := by
  unfold computeWeight WITNESS_DISCOUNT_DIVISOR
  omega

/-- Weight is monotone in witnessSize. -/
theorem computeWeight_monotone_witness (b w1 w2 d s : Nat) (h : w1 ≤ w2) :
    computeWeight b w1 d s ≤ computeWeight b w2 d s := by
  unfold computeWeight; omega

/-- Weight is monotone in daSize. -/
theorem computeWeight_monotone_da (b w d1 d2 s : Nat) (h : d1 ≤ d2) :
    computeWeight b w d1 s ≤ computeWeight b w d2 s := by
  unfold computeWeight; omega

/-- Weight is monotone in sigCost. -/
theorem computeWeight_monotone_sigCost (b w d s1 s2 : Nat) (h : s1 ≤ s2) :
    computeWeight b w d s1 ≤ computeWeight b w d s2 := by
  unfold computeWeight; omega

/-! ## Weight positivity and lower bounds

The base multiplier (4x) dominates the weight formula.  These bounds
are useful for fee-rate calculations and mempool admission.
-/

/-- Weight is always at least 4*baseSize (witness/DA/sig add non-negative amounts). -/
theorem computeWeight_ge_base (baseSize witnessSize daSize sigCost : Nat) :
    WITNESS_DISCOUNT_DIVISOR * baseSize ≤ computeWeight baseSize witnessSize daSize sigCost := by
  unfold computeWeight; omega

/-- Weight with zero witness/DA/sig equals exactly 4*baseSize. -/
theorem computeWeight_base_only (baseSize : Nat) :
    computeWeight baseSize 0 0 0 = WITNESS_DISCOUNT_DIVISOR * baseSize := by
  unfold computeWeight; omega

/-- Concrete: minimum valid transaction (baseSize=1, no witness/DA/sig) has weight 4. -/
theorem computeWeight_minimum_nonzero :
    computeWeight 1 0 0 0 = 4 := by native_decide

/-! ## Conformance replay bridge

The CV-WEIGHT conformance vectors exercise `txWeightAndStats` against real
transaction byte sequences and check exact (weight, daBytes, anchorBytes)
equality.  This is the concrete evidence layer backing the behavioral theorems.
-/

/-- CV-WEIGHT conformance replay: all weight vectors pass against the live
    `txWeightAndStats` implementation.  Proved by `native_decide` — the Lean
    kernel evaluates every vector to completion. -/
theorem weight_cv_replay_pass :
    RubinFormal.Conformance.cvWeightVectorsPass = true :=
  RubinFormal.Conformance.cv_weight_vectors_pass

/-! ## Behavioral closure summary

  The weight_accounting section (§9) is now behaviourally closed:

  - **Constants**: all 5 normative constants pinned to literal values (rfl)
  - **Formula decomposition**: `computeWeight` matches the final `let weight := ...`
    in `txWeightAndStats` exactly
  - **Abstract bridge**: `weight_formula_bridges_abstract` connects the live
    4-component formula to the 3-component `CriticalInvariants.weight`
  - **Signature cost**: decomposition into ML-DSA + unknown suite components
    with monotonicity in each
  - **DA component**: kind=0 → daLen=0 → daSize=1 → daBytes=0
  - **Monotonicity**: all 4 components independently monotone
  - **Conformance replay**: `cv_weight_vectors_pass` on real byte sequences
  - **Suite-aware model**: `WeightSuiteAware.weight_suite_aware_correct`
    covers post-rotation registry-based cost lookup

  Full Except-chain proof now machine-checked via txWeightAndStats_ok_weight_eq.
-/

/-! ## LIVE: Full Except-chain theorems on txWeightAndStats

The live function `txWeightAndStats` is composed from `parseTxHeader → parseTxBody →
finalizeTxWeight`. Each sub-function has ≤8 match/if points, making the full
case-analysis proof tractable without kernel overflow. -/

/-- LIVE: weightTail success → weight = computeWeight with CONCRETE witnesses.
    All components are determined by function arguments — zero unconstrained existentials. -/
theorem weightTail_ok (tx : Bytes) (txKind baseSize anchorBytes daLen : Nat)
    (ws : WitnessSectionResult) (c10 : Wire.Cursor) (stats : WeightStats)
    (h : weightTail tx txKind baseSize anchorBytes daLen ws c10 = .ok stats) :
    stats.weight = computeWeight baseSize (ws.endOff - ws.startOff)
      (compactSizeLen daLen + daLen)
      (ws.mlCount * VERIFY_COST_ML_DSA_87 + ws.unknownSuiteCount * VERIFY_COST_UNKNOWN_SUITE) := by
  unfold weightTail at h
  split at h; · exact Except.noConfusion h
  · split at h; · exact (nomatch h)
    · injection h with h; subst h; rfl

/-- LIVE: finalizeTxWeight success → weight = computeWeight with parse-derived witnesses.
    Only daLen is existential (parsed from cursor). witnessSize and sigCost are concrete
    from the WitnessSectionResult argument. -/
theorem finalizeTxWeight_ok (tx : Bytes) (txKind baseSize anchorBytes : Nat)
    (ws : WitnessSectionResult) (c : Wire.Cursor) (stats : WeightStats)
    (h : finalizeTxWeight tx txKind baseSize anchorBytes ws c = .ok stats) :
    ∃ daLen : Nat,
      stats.weight = computeWeight baseSize (ws.endOff - ws.startOff)
        (compactSizeLen daLen + daLen)
        (ws.mlCount * VERIFY_COST_ML_DSA_87 + ws.unknownSuiteCount * VERIFY_COST_UNKNOWN_SUITE) := by
  unfold finalizeTxWeight at h
  split at h; · exact Except.noConfusion h
  · split at h; · exact (nomatch h)
    · split at h
      · split at h; · exact (nomatch h)
        · exact ⟨_, weightTail_ok _ _ _ _ _ _ _ _ h⟩
      · split at h
        · split at h; · exact (nomatch h)
          · exact ⟨_, weightTail_ok _ _ _ _ _ _ _ _ h⟩
        · split at h; · exact (nomatch h)
          · exact ⟨_, weightTail_ok _ _ _ _ _ _ _ _ h⟩

/-- LIVE: Full Except-chain proof with constrained witnesses.
    If txWeightAndStats succeeds, weight = computeWeight where:
    - baseSize = cursor offset after parsing header+inputs+outputs+DA core (existential)
    - witnessSize = ws.endOff - ws.startOff (concrete from WitnessSectionResult)
    - daSize = compactSizeLen daLen + daLen (existential daLen from DA manifest parse)
    - sigCost = mlCount * 8 + unknownCount * 64 (concrete from WitnessSectionResult)
    Only baseSize and daLen are existential — both parse-derived, not arbitrary. -/
theorem txWeightAndStats_ok_weight_eq (tx : Bytes) (stats : WeightStats)
    (h : txWeightAndStats tx = .ok stats) :
    ∃ (baseSize daLen : Nat) (ws : WitnessSectionResult),
      stats.weight = computeWeight baseSize (ws.endOff - ws.startOff)
        (compactSizeLen daLen + daLen)
        (ws.mlCount * VERIFY_COST_ML_DSA_87 + ws.unknownSuiteCount * VERIFY_COST_UNKNOWN_SUITE) := by
  unfold txWeightAndStats at h
  simp only [bind, Except.bind] at h
  split at h; · exact Except.noConfusion h
  · split at h; · exact Except.noConfusion h
    · obtain ⟨daLen, hw⟩ := finalizeTxWeight_ok _ _ _ _ _ _ _ h
      exact ⟨_, daLen, _, hw⟩

/-- LIVE: Full Except-chain proof with parse-constrained witnesses.
    This strengthens `txWeightAndStats_ok_weight_eq` by recording the exact
    successful parse chain that produced the weight inputs. -/
theorem txWeightAndStats_ok_weight_eq_constrained (tx : Bytes) (stats : WeightStats)
    (h : txWeightAndStats tx = .ok stats) :
    ∃ (txKind : Nat) (c1 : Wire.Cursor) (baseSize anchorBytes : Nat)
      (ws : WitnessSectionResult) (c2 : Wire.Cursor) (daLen : Nat),
      parseTxHeader tx = .ok (txKind, c1) ∧
      parseTxBody txKind c1 = .ok (baseSize, anchorBytes, ws, c2) ∧
      finalizeTxWeight tx txKind baseSize anchorBytes ws c2 = .ok stats ∧
      stats.weight = computeWeight baseSize (ws.endOff - ws.startOff)
        (compactSizeLen daLen + daLen)
        (ws.mlCount * VERIFY_COST_ML_DSA_87 + ws.unknownSuiteCount * VERIFY_COST_UNKNOWN_SUITE) := by
  unfold txWeightAndStats at h
  cases hHeader : parseTxHeader tx with
  | error e =>
      simp only [bind, Except.bind, hHeader] at h
  | ok header =>
      rcases header with ⟨txKind, c1⟩
      cases hBody : parseTxBody txKind c1 with
      | error e =>
          simp only [bind, Except.bind, hHeader, hBody] at h
      | ok body =>
          rcases body with ⟨baseSize, anchorBytes, ws, c2⟩
          simp only [bind, Except.bind, hHeader, hBody] at h
          have hFinal : finalizeTxWeight tx txKind baseSize anchorBytes ws c2 = .ok stats := by
            exact h
          obtain ⟨daLen, hw⟩ := finalizeTxWeight_ok tx txKind baseSize anchorBytes ws c2 stats hFinal
          exact ⟨txKind, c1, baseSize, anchorBytes, ws, c2, daLen, rfl, hBody, hFinal, hw⟩

/-- LIVE: weightTail success implies weight > 0 (non-vacuous, uses h). -/
theorem weightTail_weight_pos (tx : Bytes) (txKind baseSize anchorBytes daLen : Nat)
    (ws : WitnessSectionResult) (c10 : Wire.Cursor) (stats : WeightStats)
    (h : weightTail tx txKind baseSize anchorBytes daLen ws c10 = .ok stats) :
    stats.weight > 0 := by
  unfold weightTail at h
  split at h; · exact Except.noConfusion h
  · split at h; · exact (nomatch h)
    · injection h with h; subst h
      show WITNESS_DISCOUNT_DIVISOR * baseSize + _ + (compactSizeLen daLen + daLen) + _ > 0
      simp only [WITNESS_DISCOUNT_DIVISOR, VERIFY_COST_ML_DSA_87, VERIFY_COST_UNKNOWN_SUITE]
      unfold compactSizeLen; split <;> omega

/-- LIVE: finalizeTxWeight success implies weight > 0 (non-vacuous). -/
theorem finalizeTxWeight_weight_pos (tx : Bytes) (txKind baseSize anchorBytes : Nat)
    (ws : WitnessSectionResult) (c : Wire.Cursor) (stats : WeightStats)
    (h : finalizeTxWeight tx txKind baseSize anchorBytes ws c = .ok stats) :
    stats.weight > 0 := by
  unfold finalizeTxWeight at h
  split at h; · exact Except.noConfusion h
  · split at h; · exact (nomatch h)
    · split at h
      · split at h; · exact (nomatch h)
        · exact weightTail_weight_pos tx txKind baseSize anchorBytes _ ws _ stats h
      · split at h
        · split at h; · exact (nomatch h)
          · exact weightTail_weight_pos tx txKind baseSize anchorBytes _ ws _ stats h
        · split at h; · exact (nomatch h)
          · exact weightTail_weight_pos tx txKind baseSize anchorBytes _ ws _ stats h

/-- LIVE: txWeightAndStats success implies weight > 0.
    Non-vacuous: 0 is explicitly excluded from .ok results because
    compactSizeLen ≥ 1 guarantees weight ≥ 1 in every .ok path.
    Empty input and 4-byte input are proved to reject, so `.ok` is non-trivial. -/
theorem txWeightAndStats_weight_pos (tx : Bytes) (stats : WeightStats)
    (h : txWeightAndStats tx = .ok stats) :
    stats.weight > 0 := by
  unfold txWeightAndStats at h
  simp only [bind, Except.bind] at h
  split at h; · exact Except.noConfusion h
  · split at h; · exact Except.noConfusion h
    · exact finalizeTxWeight_weight_pos tx _ _ _ _ _ stats h

/-- LIVE: txWeightAndStats rejects empty input. -/
theorem txWeightAndStats_error_empty :
    txWeightAndStats (RubinFormal.bytes #[]) = .error "TX_ERR_PARSE" := by
  unfold txWeightAndStats parseTxHeader; simp [Wire.Cursor.getU32le?]; rfl

/-- LIVE: txWeightAndStats rejects 4-byte input (nonce parsed but no kind byte). -/
theorem txWeightAndStats_error_4bytes (b0 b1 b2 b3 : UInt8) :
    txWeightAndStats (RubinFormal.bytes #[b0, b1, b2, b3]) = .error "TX_ERR_PARSE" := by
  unfold txWeightAndStats parseTxHeader; simp [Wire.Cursor.getU32le?, Wire.Cursor.getU8?]; rfl

end RubinFormal

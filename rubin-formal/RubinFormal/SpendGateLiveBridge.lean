/-
  RubinFormal/SpendGateLiveBridge.lean — Spend/Create Gate Bridge

  Counted LIVE+BRIDGE row for this file is the descriptor-aware spend-side
  live bridge. `spend_create_gate_ok_constrained` remains a helper theorem
  for the spend/create gate model surface: ∀ well-formed descriptor, ∀ height,
  spend and create gates accept ↔ suite membership, and accepted suites
  are never sentinel.

  The counted closure is now the real live P2PK spend path:
  - `validateP2PKSpendPreSig` on the descriptor-aware branch
  - `scanSingleInputStep` on the descriptor-aware P2PK branch

  Pre-rotation corollaries remain available through the `none` fallback.

  Spec: CANONICAL §5.4 (witness suite gating), §4.1.2 (rotation phases).
  Depends: NativeSpendCreateGate.lean (FI-ROT-04/05).
  Closes #285, #369.
-/

import RubinFormal.NativeSpendCreateGate
import RubinFormal.UtxoApplyGenesisV1
import RubinFormal.BytesEqLemmas

namespace RubinFormal

namespace SpendGateLiveBridge

open Rotation
open NativeSuiteRotation
open NativeSpendCreateGate
open UtxoApplyGenesisV1

/-! ### Pre-rotation spend suite characterization -/

/-- Pre-rotation: when h < d.h1, the only active spend suite is oldSuiteId.
    This is the foundational observation: before rotation activates,
    NativeSpendSuites collapses to a singleton. -/
theorem pre_rotation_spend_suites
    (d : RotationDeploymentDescriptor) (h : Nat)
    (hPhase1 : h < d.h1) :
    NativeSpendSuites h d = [d.oldSuiteId] := by
  simp [NativeSpendSuites, hPhase1]

/-! ### Model → Live bridge (forward direction)

  nativeSpendGate accept → suiteId = SUITE_ID_ML_DSA_87
  when NativeSpendSuites = [SUITE_ID_ML_DSA_87].

  This direction proves: if the model says "accept", the live hardcoded
  check `suite != SUITE_ID_ML_DSA_87 → reject` does NOT fire. -/

/-- When spend suites are exactly {ML_DSA_87}, model gate acceptance implies
    suiteId = SUITE_ID_ML_DSA_87, matching the live hardcoded check. -/
theorem gate_accept_implies_ml_dsa_87
    (d : RotationDeploymentDescriptor) (h suiteId : Nat)
    (hSuites : NativeSpendSuites h d = [SUITE_ID_ML_DSA_87])
    (hAccept : nativeSpendGate d h suiteId = GateResult.accept) :
    suiteId = SUITE_ID_ML_DSA_87 := by
  have hmem := fi_rot_04_spend_gate_sound d h suiteId hAccept
  rw [hSuites] at hmem
  simp [List.mem_singleton] at hmem
  exact hmem

/-! ### Live → Model bridge (backward direction)

  suiteId = SUITE_ID_ML_DSA_87 → nativeSpendGate accept
  when NativeSpendSuites = [SUITE_ID_ML_DSA_87].

  This direction proves: if the live check passes (suite is ML_DSA_87),
  the model also accepts. -/

/-- When suiteId = ML_DSA_87 and spend suites contain it, the model gate accepts. -/
theorem ml_dsa_87_implies_gate_accept
    (d : RotationDeploymentDescriptor) (h suiteId : Nat)
    (hSuites : NativeSpendSuites h d = [SUITE_ID_ML_DSA_87])
    (hSuite : suiteId = SUITE_ID_ML_DSA_87) :
    nativeSpendGate d h suiteId = GateResult.accept := by
  apply (fi_rot_04_spend_gate_iff d h suiteId).mpr
  rw [hSuites, hSuite]
  exact List.Mem.head _

/-! ### Full equivalence -/

/-- Full bridge: model gate ↔ live hardcoded suite check, pre-rotation scope.
    This is the FI-285 formal invariant: the model-level nativeSpendGate is
    semantically equivalent to the live hardcoded `suite != SUITE_ID_ML_DSA_87`
    check when NativeSpendSuites(h) = {ML_DSA_87}. -/
theorem spend_gate_live_equivalence
    (d : RotationDeploymentDescriptor) (h suiteId : Nat)
    (hSuites : NativeSpendSuites h d = [SUITE_ID_ML_DSA_87]) :
    nativeSpendGate d h suiteId = GateResult.accept ↔
    suiteId = SUITE_ID_ML_DSA_87 :=
  ⟨gate_accept_implies_ml_dsa_87 d h suiteId hSuites,
   ml_dsa_87_implies_gate_accept d h suiteId hSuites⟩

/-- Concrete Phase 1 bridge: when d.oldSuiteId = ML_DSA_87 and h < h1,
    the model gate is equivalent to the live suite check.
    This is the most common usage: genesis-era descriptor with ML_DSA_87
    as the sole native spend suite. -/
theorem spend_gate_phase1_bridge
    (d : RotationDeploymentDescriptor) (h suiteId : Nat)
    (hOld : d.oldSuiteId = SUITE_ID_ML_DSA_87)
    (hPhase1 : h < d.h1) :
    nativeSpendGate d h suiteId = GateResult.accept ↔
    suiteId = SUITE_ID_ML_DSA_87 := by
  have hSuites : NativeSpendSuites h d = [SUITE_ID_ML_DSA_87] := by
    rw [← hOld]; exact pre_rotation_spend_suites d h hPhase1
  exact spend_gate_live_equivalence d h suiteId hSuites

/-! ### Rejection bridge

  Completes the model ↔ live picture: when the live check rejects
  (suite ≠ ML_DSA_87), the model gate also rejects with the same
  error classification (TX_ERR_SIG_ALG_INVALID). -/

/-- Rejection bridge: suite ≠ ML_DSA_87 in pre-rotation scope → model gate
    rejects with reject_sig_alg_invalid, matching the live error code. -/
theorem spend_gate_rejection_bridge
    (d : RotationDeploymentDescriptor) (h suiteId : Nat)
    (hSuites : NativeSpendSuites h d = [SUITE_ID_ML_DSA_87])
    (hNeq : suiteId ≠ SUITE_ID_ML_DSA_87) :
    nativeSpendGate d h suiteId = GateResult.reject_sig_alg_invalid := by
  apply fi_rot_04_spend_gate_rejects
  rw [hSuites]
  simp [List.mem_singleton]
  exact hNeq

/-! ### Post-rotation generalization

  After rotation activates, NativeSpendSuites may contain {old, new} or {new}.
  The model gate remains the correct abstraction — these theorems show the
  gate remains sound for any phase, not just pre-rotation. -/

/-- General bridge: for ANY phase, model gate acceptance means the suite
    is one of the active spend suites (oldSuiteId or newSuiteId).
    The live code post-rotation would check `suite ∈ NATIVE_SPEND_SUITES(h)`
    instead of hardcoding ML_DSA_87. -/
theorem gate_accept_is_spend_suite
    (d : RotationDeploymentDescriptor) (h suiteId : Nat)
    (hAccept : nativeSpendGate d h suiteId = GateResult.accept) :
    suiteId ∈ NativeSpendSuites h d :=
  fi_rot_04_spend_gate_sound d h suiteId hAccept

/-- General bridge (converse): membership in NativeSpendSuites guarantees
    the model gate accepts. This is the post-rotation live code's logic. -/
theorem spend_suite_implies_gate_accept
    (d : RotationDeploymentDescriptor) (h suiteId : Nat)
    (hMem : suiteId ∈ NativeSpendSuites h d) :
    nativeSpendGate d h suiteId = GateResult.accept :=
  (fi_rot_04_spend_gate_iff d h suiteId).mpr hMem

/-! ### Live function bridge — validateP2PKSpendPreSig

  The theorems above establish: model gate accept ↔ suiteId = SUITE_ID_ML_DSA_87.
  The theorems below connect this to the LIVE function validateP2PKSpendPreSig
  (UtxoApplyGenesisV1.lean), proving that the model gate verdict determines
  whether the live suite check fires or not.

  validateP2PKSpendPreSig (line 44):
    `if suite != SUITE_ID_ML_DSA_87 then throw "TX_ERR_SIG_ALG_INVALID"`

  The bridge proves: model gate accept ↔ this `!=` check evaluates to false. -/

/-- The UtxoApplyGenesisV1 module's SUITE_ID_ML_DSA_87 is definitionally
    the same as the canonical RubinFormal.SUITE_ID_ML_DSA_87.
    This grounds cross-module suite ID references. -/
private theorem utxo_suite_eq_canonical :
    UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 = RubinFormal.SUITE_ID_ML_DSA_87 := by
  native_decide

/-- Live suite check does not fire when model gate accepts.
    validateP2PKSpendPreSig line 44: `if suite != SUITE_ID_ML_DSA_87 then throw`.
    When model gate accepts (pre-rotation), suiteId = ML_DSA_87,
    so `suite != SUITE_ID_ML_DSA_87` evaluates to false — no throw. -/
theorem live_suite_check_passes_on_gate_accept
    (d : RotationDeploymentDescriptor) (h : Nat) (w : UtxoBasicV1.WitnessItem)
    (hSuites : NativeSpendSuites h d = [SUITE_ID_ML_DSA_87])
    (hAccept : nativeSpendGate d h w.suiteId = GateResult.accept) :
    (w.suiteId != UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = false := by
  have hSuite := gate_accept_implies_ml_dsa_87 d h w.suiteId hSuites hAccept
  rw [hSuite, utxo_suite_eq_canonical]
  native_decide

/-- Live suite check fires when model gate rejects.
    When model gate rejects (pre-rotation), suiteId ≠ ML_DSA_87,
    so `suite != SUITE_ID_ML_DSA_87` evaluates to true → throw. -/
theorem live_suite_check_rejects_on_gate_reject
    (d : RotationDeploymentDescriptor) (h : Nat) (w : UtxoBasicV1.WitnessItem)
    (hSuites : NativeSpendSuites h d = [SUITE_ID_ML_DSA_87])
    (hReject : nativeSpendGate d h w.suiteId = GateResult.reject_sig_alg_invalid) :
    (w.suiteId != UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = true := by
  -- Extract w.suiteId ≠ SUITE_ID_ML_DSA_87 from rejection
  have hNotMem : w.suiteId ∉ NativeSpendSuites h d := by
    intro hmem
    have hAcc := (fi_rot_04_spend_gate_iff d h w.suiteId).mpr hmem
    rw [hAcc] at hReject; exact absurd hReject (by decide)
  rw [hSuites] at hNotMem
  simp [List.mem_singleton] at hNotMem
  -- hNotMem : w.suiteId ≠ SUITE_ID_ML_DSA_87
  -- Convert propositional ≠ to computational != via BEq
  show (!(w.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87)) = true
  rw [utxo_suite_eq_canonical, Bool.not_eq_true']
  -- goal: (w.suiteId == SUITE_ID_ML_DSA_87) = false
  cases hbeq : (w.suiteId == SUITE_ID_ML_DSA_87)
  · rfl
  · exact absurd (eq_of_beq hbeq) hNotMem

/-- Full model-to-live bridge: nativeSpendGate accept ↔ validateP2PKSpendPreSig
    suite check passes. This is the complete bridge from model to live for #285.
    Pre-rotation scope: NativeSpendSuites(h) = {ML_DSA_87}. -/
theorem gate_iff_live_suite_check
    (d : RotationDeploymentDescriptor) (h : Nat) (w : UtxoBasicV1.WitnessItem)
    (hSuites : NativeSpendSuites h d = [SUITE_ID_ML_DSA_87]) :
    nativeSpendGate d h w.suiteId = GateResult.accept ↔
    (w.suiteId != UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = false :=
  ⟨live_suite_check_passes_on_gate_accept d h w hSuites,
   fun hCheck => by
     have hbeq : (w.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = true := by
       cases hb : w.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87
       · simp [bne, hb] at hCheck
       · rfl
     have hSuiteEq := (eq_of_beq hbeq).trans utxo_suite_eq_canonical
     exact ml_dsa_87_implies_gate_accept d h w.suiteId hSuites hSuiteEq⟩

-- ═══════════════════════════════════════════════════════════════════
-- §  Constrained universal theorem (spend + create gate)
-- ═══════════════════════════════════════════════════════════════════

/-- **Spend/create gate constrained helper theorem** (§5.4/§4.1.2 model surface):
    for any well-formed descriptor, at every height, both spend and create
    gates accept iff the suite is in the active set, and accepted suites
    are never sentinel. Covers all 5 rotation phases.
    This theorem does not by itself close the post-rotation live bridge gap
    (G7 residual). -/
theorem spend_create_gate_ok_constrained
    (d : RotationDeploymentDescriptor) (reg : SuiteRegistry)
    (hwf : wellFormedDescriptor reg d)
    (h : Nat) :
    (∀ sid, nativeSpendGate d h sid = GateResult.accept ↔
      sid ∈ NativeSpendSuites h d) ∧
    (∀ sid, nativeP2PKCreateGate d h sid = GateResult.accept ↔
      sid ∈ NativeCreateSuites h d) ∧
    (∀ sid, nativeSpendGate d h sid = GateResult.accept →
      sid ≠ RubinFormal.SUITE_ID_SENTINEL) ∧
    (∀ sid, nativeP2PKCreateGate d h sid = GateResult.accept →
      sid ≠ RubinFormal.SUITE_ID_SENTINEL) :=
  ⟨fun sid => fi_rot_04_spend_gate_iff d h sid,
   fun sid => fi_rot_05_create_gate_iff d h sid,
   fun sid hacc => fi_rot_04_accepted_not_sentinel reg d h sid hwf hacc,
   fun sid hacc => fi_rot_05_accepted_not_sentinel reg d h sid hwf hacc⟩

-- ═══════════════════════════════════════════════════════════════════
-- §  Post-rotation live bridge on the real spend path
-- ═══════════════════════════════════════════════════════════════════

/-- If a suite is inactive at height `h`, the live P2PK spend validator rejects
    immediately with `TX_ERR_SIG_ALG_INVALID` on the descriptor-aware path. -/
theorem validateP2PKSpendPreSig_rejects_inactive_suite
    (d : RotationDeploymentDescriptor)
    (entry : UtxoBasicV1.UtxoEntry)
    (w : UtxoBasicV1.WitnessItem)
    (h : Nat)
    (hNotMem : w.suiteId ∉ NativeSpendSuites h d) :
    UtxoApplyGenesisV1.validateP2PKSpendPreSig entry w h (some d) =
      .error "TX_ERR_SIG_ALG_INVALID" := by
  have hGate :
      NativeSpendCreateGate.liveSpendGateAllows (some d) h w.suiteId = false :=
    (NativeSpendCreateGate.liveSpendGateAllows_some_false_iff d h w.suiteId).mpr hNotMem
  unfold UtxoApplyGenesisV1.validateP2PKSpendPreSig
  simp [hGate]
  rfl

/-- Descriptor-aware live P2PK spend bridge: once the same structural
    preconditions used by the live validator are satisfied, `.ok ()`
    is equivalent to membership in `NativeSpendSuites h d`. -/
theorem validateP2PKSpendPreSig_ok_constrained
    (d : RotationDeploymentDescriptor)
    (entry : UtxoBasicV1.UtxoEntry)
    (w : UtxoBasicV1.WitnessItem)
    (h : Nat)
    (hSize : entry.covenantData.size = CovenantGenesisV1.MAX_P2PK_COVENANT_DATA)
    (hTag : (entry.covenantData.get! 0).toNat = w.suiteId)
    (hHash : SHA3.sha3_256 w.pubkey = entry.covenantData.extract 1 33) :
    UtxoApplyGenesisV1.validateP2PKSpendPreSig entry w h (some d) = .ok () ↔
    w.suiteId ∈ NativeSpendSuites h d := by
  constructor
  · intro hOk
    by_contra hNotMem
    have hErr :=
      validateP2PKSpendPreSig_rejects_inactive_suite d entry w h hNotMem
    rw [hErr] at hOk
    cases hOk
  · intro hMem
    have hGate :
        NativeSpendCreateGate.liveSpendGateAllows (some d) h w.suiteId = true :=
      (NativeSpendCreateGate.liveSpendGateAllows_some_iff d h w.suiteId).mpr hMem
    have hHashFalse : (SHA3.sha3_256 w.pubkey != entry.covenantData.extract 1 33) = false := by
      rw [hHash]
      exact bytes_bne_self_false _
    unfold UtxoApplyGenesisV1.validateP2PKSpendPreSig
    simp [hGate, hSize, hTag, hHashFalse]
    rfl

/-- Deterministic successful result for the P2PK branch of `scanSingleInputStep`
    once all earlier live guards have passed. -/
private def p2pkScanResult
    (input : UtxoBasicV1.TxIn)
    (e : UtxoBasicV1.UtxoEntry)
    (acc : UtxoBasicV1.InputScanState) : UtxoBasicV1.InputScanState :=
  { acc with
      sumIn := acc.sumIn + e.value
      inputLockIds := acc.inputLockIds.concat (UtxoBasicV1.outputDescriptorLockId e)
      inputCovTypes := acc.inputCovTypes.concat e.covenantType
      inputEntries := acc.inputEntries.concat e
      requiredWitnessSlots := acc.requiredWitnessSlots + 1
      consumedOutpoints := acc.consumedOutpoints.concat (UtxoBasicV1.txInOutpoint input)
  }

/-- On the real input-scan path, an inactive P2PK suite is rejected with
    `TX_ERR_SIG_ALG_INVALID` once the earlier non-suite guards have passed. -/
theorem scanSingleInputStep_rejects_inactive_p2pk_suite
    (d : RotationDeploymentDescriptor)
    (input : UtxoBasicV1.TxIn)
    (utxoMap : Std.RBMap UtxoBasicV1.Outpoint UtxoBasicV1.UtxoEntry UtxoBasicV1.cmpOutpoint)
    (height : Nat)
    (acc : UtxoBasicV1.InputScanState)
    (e : UtxoBasicV1.UtxoEntry)
    (hNoDup : acc.consumedOutpoints.contains (UtxoBasicV1.txInOutpoint input) = false)
    (hFind : utxoMap.find? (UtxoBasicV1.txInOutpoint input) = some e)
    (hMaturity : UtxoBasicV1.validateCoinbaseMaturity e height = .ok ())
    (hP2PK : e.covenantType = UtxoBasicV1.COV_TYPE_P2PK)
    (hSize : e.covenantData.size = CovenantGenesisV1.MAX_P2PK_COVENANT_DATA)
    (hNotMem : (e.covenantData.get! 0).toNat ∉ NativeSpendSuites height d) :
    UtxoBasicV1.scanSingleInputStep input utxoMap height acc (some d) =
      .error "TX_ERR_SIG_ALG_INVALID" := by
  have hGate :
      NativeSpendCreateGate.liveSpendGateAllows (some d) height (e.covenantData.get! 0).toNat = false :=
    (NativeSpendCreateGate.liveSpendGateAllows_some_false_iff d height (e.covenantData.get! 0).toNat).mpr hNotMem
  unfold UtxoBasicV1.scanSingleInputStep
  simp [hNoDup, hFind, hMaturity, hP2PK, hSize, hGate,
    UtxoBasicV1.COV_TYPE_P2PK, UtxoBasicV1.COV_TYPE_ANCHOR, UtxoBasicV1.COV_TYPE_DA_COMMIT,
    UtxoBasicV1.COV_TYPE_VAULT]
  rfl

/-- Descriptor-aware live input-scan bridge for the P2PK branch: under the
    same preceding guards as the live scanner, the step succeeds iff the
    committed suite is active in `NativeSpendSuites h d`. -/
theorem scanSingleInputStep_ok_constrained
    (d : RotationDeploymentDescriptor)
    (input : UtxoBasicV1.TxIn)
    (utxoMap : Std.RBMap UtxoBasicV1.Outpoint UtxoBasicV1.UtxoEntry UtxoBasicV1.cmpOutpoint)
    (height : Nat)
    (acc : UtxoBasicV1.InputScanState)
    (e : UtxoBasicV1.UtxoEntry)
    (hNoDup : acc.consumedOutpoints.contains (UtxoBasicV1.txInOutpoint input) = false)
    (hFind : utxoMap.find? (UtxoBasicV1.txInOutpoint input) = some e)
    (hMaturity : UtxoBasicV1.validateCoinbaseMaturity e height = .ok ())
    (hP2PK : e.covenantType = UtxoBasicV1.COV_TYPE_P2PK)
    (hSize : e.covenantData.size = CovenantGenesisV1.MAX_P2PK_COVENANT_DATA) :
    UtxoBasicV1.scanSingleInputStep input utxoMap height acc (some d) =
      .ok (p2pkScanResult input e acc) ↔
    (e.covenantData.get! 0).toNat ∈ NativeSpendSuites height d := by
  constructor
  · intro hOk
    by_contra hNotMem
    have hErr :=
      scanSingleInputStep_rejects_inactive_p2pk_suite
        d input utxoMap height acc e hNoDup hFind hMaturity hP2PK hSize hNotMem
    rw [hErr] at hOk
    cases hOk
  · intro hMem
    have hGate :
        NativeSpendCreateGate.liveSpendGateAllows (some d) height (e.covenantData.get! 0).toNat = true :=
      (NativeSpendCreateGate.liveSpendGateAllows_some_iff d height (e.covenantData.get! 0).toNat).mpr hMem
    unfold UtxoBasicV1.scanSingleInputStep
    simp [p2pkScanResult, hNoDup, hFind, hMaturity, hP2PK, hSize, hGate,
      UtxoBasicV1.COV_TYPE_P2PK, UtxoBasicV1.COV_TYPE_ANCHOR, UtxoBasicV1.COV_TYPE_DA_COMMIT,
      UtxoBasicV1.COV_TYPE_VAULT]
    rfl

end SpendGateLiveBridge

end RubinFormal

/-
  RubinFormal/ThresholdSpendSuiteGateBridge.lean

  File role:
    bridge-only layer for threshold suite-gating semantics.
    Authoritative universal helper claims live in the suite-aware gate/model
    files; this file exists to pin bridge equivalence and scope transitions.

  Descriptor-aware suite gate BRIDGE for threshold-sig spend paths.
  Pre-rotation: BRIDGE theorems prove equivalence between the
  thresholdItemSuiteAllowed helper and `decide (suiteId = ML_DSA_87)`,
  which matches the live per-item comparison inside
  `validateThresholdSigSpendNoCrypto`.
  Post-rotation: BRIDGE theorems (helper ↔ NativeSpendSuites model),
  plus MODEL iff theorems on the helper.

  Classification:
    Pre-rotation theorems: BRIDGE (helper ↔ decide comparison)
    Post-rotation soundness/completeness: BRIDGE (helper ↔ model)
    Universal iff theorems: MODEL (on helper)
    evidence_level: machine_checked_universal
    (same decision-level bridge pattern as spend_gate_bridge)

  Gap closed: rubin-formal#419
  Spec: CANONICAL §5.4 (witness suite gating), §14.2 (MULTISIG),
        §24.1 (VAULT threshold sig), §23.2.1 (rotation phases).
  Depends: NativeSpendCreateGate.lean, UtxoApplyGenesisV1.lean.
-/

import RubinFormal.NativeSpendCreateGate
import RubinFormal.UtxoApplyGenesisV1

namespace RubinFormal

namespace ThresholdSpendSuiteGateBridge

open Rotation
open NativeSuiteRotation
open NativeSpendCreateGate
open UtxoApplyGenesisV1

/-! ### Rotation-aware threshold sig suite gate

  The live `validateThresholdSigSpendNoCrypto` has a hardcoded
  `w.suiteId == SUITE_ID_ML_DSA_87` check. Under rotation, this
  becomes `w.suiteId ∈ NativeSpendSuites h d`.

  We define the rotation-aware variant and prove equivalence
  with the existing hardcoded version under pre-rotation conditions. -/

/-- Rotation-aware per-item suite gate for threshold-sig loop.
    Returns true iff the witness item's suite is in the native spend set. -/
def thresholdItemSuiteAllowed
    (rotDesc? : Option RotationDeploymentDescriptor)
    (h : Nat) (w : UtxoBasicV1.WitnessItem) : Bool :=
  liveSpendGateAllows rotDesc? h w.suiteId

/-! ### Pre-rotation equivalence

  Under `none` (no rotation descriptor), `thresholdItemSuiteAllowed`
  reduces to `w.suiteId == SUITE_ID_ML_DSA_87`, matching the hardcoded
  check in `validateThresholdSigSpendNoCrypto`. -/

/-- Pre-rotation: the rotation-aware gate matches the hardcoded ML-DSA-87 check. -/
theorem pre_rotation_threshold_gate_eq_hardcoded
    (w : UtxoBasicV1.WitnessItem) (h : Nat) :
    thresholdItemSuiteAllowed none h w =
    decide (w.suiteId = SUITE_ID_ML_DSA_87) := by
  simp [thresholdItemSuiteAllowed, liveSpendGateAllows]

/-- Pre-rotation: if the hardcoded check accepts (suite = ML_DSA_87),
    the rotation-aware gate also accepts. -/
theorem pre_rotation_hardcoded_accept_implies_gate
    (w : UtxoBasicV1.WitnessItem) (h : Nat)
    (hSuite : w.suiteId = SUITE_ID_ML_DSA_87) :
    thresholdItemSuiteAllowed none h w = true := by
  rw [pre_rotation_threshold_gate_eq_hardcoded]
  simp [hSuite]

/-- Pre-rotation: if the hardcoded check rejects (suite ≠ ML_DSA_87),
    the rotation-aware gate also rejects. -/
theorem pre_rotation_hardcoded_reject_implies_gate
    (w : UtxoBasicV1.WitnessItem) (h : Nat)
    (hSuite : w.suiteId ≠ SUITE_ID_ML_DSA_87) :
    thresholdItemSuiteAllowed none h w = false := by
  rw [pre_rotation_threshold_gate_eq_hardcoded]
  simp [hSuite]

/-! ### Post-rotation model bridge

  Under `some d`, the rotation-aware gate matches the nativeSpendGate
  model for any height and any phase. -/

/-- Post-rotation: gate acceptance ↔ nativeSpendGate accept. -/
theorem post_rotation_gate_iff_model
    (d : RotationDeploymentDescriptor) (h : Nat)
    (w : UtxoBasicV1.WitnessItem) :
    thresholdItemSuiteAllowed (some d) h w = true ↔
    nativeSpendGate d h w.suiteId = GateResult.accept := by
  simp [thresholdItemSuiteAllowed, liveSpendGateAllows]

/-- Post-rotation: gate acceptance → suite ∈ NativeSpendSuites. -/
theorem post_rotation_gate_accept_soundness
    (d : RotationDeploymentDescriptor) (h : Nat)
    (w : UtxoBasicV1.WitnessItem)
    (hGate : thresholdItemSuiteAllowed (some d) h w = true) :
    w.suiteId ∈ NativeSpendSuites h d := by
  have hModel := (post_rotation_gate_iff_model d h w).mp hGate
  exact fi_rot_04_spend_gate_sound d h w.suiteId hModel

/-- Post-rotation: suite ∈ NativeSpendSuites → gate accepts. -/
theorem post_rotation_gate_accept_completeness
    (d : RotationDeploymentDescriptor) (h : Nat)
    (w : UtxoBasicV1.WitnessItem)
    (hMem : w.suiteId ∈ NativeSpendSuites h d) :
    thresholdItemSuiteAllowed (some d) h w = true := by
  exact (post_rotation_gate_iff_model d h w).mpr
    ((fi_rot_04_spend_gate_iff d h w.suiteId).mpr hMem)

/-- Post-rotation: gate rejection → suite ∉ NativeSpendSuites. -/
theorem post_rotation_gate_reject_soundness
    (d : RotationDeploymentDescriptor) (h : Nat)
    (w : UtxoBasicV1.WitnessItem)
    (hGate : thresholdItemSuiteAllowed (some d) h w = false) :
    w.suiteId ∉ NativeSpendSuites h d := by
  intro hmem
  have hAcc := post_rotation_gate_accept_completeness d h w hmem
  rw [hAcc] at hGate
  exact absurd hGate (by decide)

/-! ### Sentinel bypass preservation

  The sentinel check (`w.suiteId == SUITE_ID_SENTINEL`) is independent
  of suite rotation and happens before the suite gate. This theorem
  confirms sentinels are still correctly handled. -/

/-- Sentinel suite is never in NativeSpendSuites when both descriptor
    suite IDs are non-sentinel. This ensures the sentinel bypass in the
    threshold loop is orthogonal to the rotation-aware suite gate. -/
theorem sentinel_not_in_spend_suites
    (d : RotationDeploymentDescriptor) (h : Nat)
    (hWf : d.oldSuiteId ≠ RubinFormal.SUITE_ID_SENTINEL ∧
           d.newSuiteId ≠ RubinFormal.SUITE_ID_SENTINEL) :
    RubinFormal.SUITE_ID_SENTINEL ∉ NativeSpendSuites h d := by
  intro hmem
  cases NativeRegistryResolution.spend_suites_subset d h _ hmem with
  | inl h => exact hWf.1 h.symm
  | inr h => exact hWf.2 h.symm

/-! ### MODEL theorems: constrained iff on helper

  These operate on thresholdItemSuiteAllowed (helper), not on the
  live validateThresholdSigSpendNoCrypto. They are MODEL-level:
  useful for reasoning about rotation-aware behavior but not yet
  bridged to the live threshold loop. -/

/-- MODEL: ∀ descriptor, ∀ height, ∀ witness item,
    the threshold suite gate helper admits ↔ suite ∈ NativeSpendSuites(h, d).
    Holds for ALL witness items including sentinels (stronger than live
    code needs, since sentinels are bypassed before suite gate). -/
theorem threshold_suite_gate_iff_spend_suites
    (d : RotationDeploymentDescriptor) (h : Nat)
    (w : UtxoBasicV1.WitnessItem) :
    thresholdItemSuiteAllowed (some d) h w = true ↔
    w.suiteId ∈ NativeSpendSuites h d :=
  ⟨post_rotation_gate_accept_soundness d h w,
   post_rotation_gate_accept_completeness d h w⟩

/-- MODEL: ∀ descriptor, ∀ height, ∀ witness item,
    threshold suite gate helper rejection ↔ suite ∉ NativeSpendSuites(h, d). -/
theorem threshold_suite_gate_reject_iff
    (d : RotationDeploymentDescriptor) (h : Nat)
    (w : UtxoBasicV1.WitnessItem) :
    thresholdItemSuiteAllowed (some d) h w = false ↔
    w.suiteId ∉ NativeSpendSuites h d := by
  constructor
  · exact post_rotation_gate_reject_soundness d h w
  · intro hNotMem
    by_contra hNot
    simp only [Bool.not_eq_false] at hNot
    exact hNotMem (post_rotation_gate_accept_soundness d h w hNot)

/-! ### LIVE bridge to validateThresholdSigSpendNoCrypto

  The theorems above prove properties of the thresholdItemSuiteAllowed
  helper. These bridge theorems connect to the actual per-item suite
  check inside UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto:
    `else if w.suiteId == SUITE_ID_ML_DSA_87 then`
  This upgrades the row from model-only to live-bridged. -/

/-- Cross-module constant grounding: the UtxoApplyGenesisV1 suite ID is
    definitionally equal to the canonical RubinFormal.SUITE_ID_ML_DSA_87. -/
private theorem utxo_suite_eq_canonical :
    UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 = RubinFormal.SUITE_ID_ML_DSA_87 := by
  native_decide

/-- LIVE bridge (accept direction): when the rotation-aware gate accepts
    under pre-rotation, the live suite check in validateThresholdSigSpendNoCrypto
    evaluates to true (suite IS ML_DSA_87). -/
theorem live_threshold_suite_check_passes_on_gate_accept
    (w : UtxoBasicV1.WitnessItem) (h : Nat)
    (hGate : thresholdItemSuiteAllowed none h w = true) :
    (w.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = true := by
  have hEq := (pre_rotation_threshold_gate_eq_hardcoded w h) ▸ hGate
  simp only [decide_eq_true_eq] at hEq
  rw [hEq, utxo_suite_eq_canonical]
  native_decide

/-- LIVE bridge (reject direction): when the rotation-aware gate rejects
    under pre-rotation, the live per-item suite comparison evaluates to false.
    Note: this proves the comparison result only, not the full function
    behavior (sentinel items take an earlier branch in the live code). -/
theorem live_threshold_suite_check_rejects_on_gate_reject
    (w : UtxoBasicV1.WitnessItem) (h : Nat)
    (hGate : thresholdItemSuiteAllowed none h w = false) :
    (w.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = false := by
  have hNeq : w.suiteId ≠ SUITE_ID_ML_DSA_87 := by
    rw [pre_rotation_threshold_gate_eq_hardcoded] at hGate
    simpa [decide_eq_false_iff_not] using hGate
  rw [utxo_suite_eq_canonical]
  cases hbeq : (w.suiteId == SUITE_ID_ML_DSA_87)
  · rfl
  · exact absurd (eq_of_beq hbeq) hNeq

end ThresholdSpendSuiteGateBridge

end RubinFormal

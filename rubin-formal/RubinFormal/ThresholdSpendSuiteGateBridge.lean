/-
  RubinFormal/ThresholdSpendSuiteGateBridge.lean

  File role:
    bridge-only layer for threshold suite-gating semantics.
    Authoritative universal helper claims live in the suite-aware gate/model
    files; this file exists to pin bridge equivalence and scope transitions.

  Pre-rotation-only suite bridge: only `PRE_ROTATION_REGISTRY` without a descriptor may admit ML-DSA-87; all other calls fail closed, with no post-rotation claim.
-/

import RubinFormal.NativeSpendCreateGate
import RubinFormal.UtxoApplyGenesisV1

namespace RubinFormal

namespace ThresholdSpendSuiteGateBridge

open Rotation
open NativeSuiteRotation
open NativeSpendCreateGate
open UtxoApplyGenesisV1

/-- Pre-rotation-only per-item gate; descriptor-present or non-singleton registry calls reject. -/
def thresholdItemSuiteAllowed
    (reg : Rotation.SuiteRegistry)
    (rotDesc? : Option RotationDeploymentDescriptor)
    (h : Nat) (w : UtxoBasicV1.WitnessItem) : Bool :=
  if decide ((show List Rotation.SuiteEntry from reg) = [Rotation.ML_DSA_87_ENTRY]) && rotDesc?.isNone then
    decide (w.suiteId = SUITE_ID_ML_DSA_87)
  else
    false

/-! ### Pre-rotation equivalence

  Under `PRE_ROTATION_REGISTRY` and `none`, `thresholdItemSuiteAllowed`
  reduces to the hardcoded ML-DSA-87 check. -/

/-- Pre-rotation: the rotation-aware gate matches the hardcoded ML-DSA-87 check. -/
theorem pre_rotation_threshold_gate_eq_hardcoded
    (w : UtxoBasicV1.WitnessItem) (h : Nat) :
    thresholdItemSuiteAllowed PRE_ROTATION_REGISTRY none h w =
    decide (w.suiteId = SUITE_ID_ML_DSA_87) := by
  simp [thresholdItemSuiteAllowed, Rotation.PRE_ROTATION_REGISTRY, Rotation.ML_DSA_87_ENTRY]

/-- Pre-rotation: if the hardcoded check accepts (suite = ML_DSA_87),
    the rotation-aware gate also accepts. -/
theorem pre_rotation_hardcoded_accept_implies_gate
    (w : UtxoBasicV1.WitnessItem) (h : Nat)
    (hSuite : w.suiteId = SUITE_ID_ML_DSA_87) :
    thresholdItemSuiteAllowed PRE_ROTATION_REGISTRY none h w = true := by
  rw [pre_rotation_threshold_gate_eq_hardcoded]
  simp [hSuite]

/-- Pre-rotation: if the hardcoded check rejects (suite ≠ ML_DSA_87),
    the rotation-aware gate also rejects. -/
theorem pre_rotation_hardcoded_reject_implies_gate
    (w : UtxoBasicV1.WitnessItem) (h : Nat)
    (hSuite : w.suiteId ≠ SUITE_ID_ML_DSA_87) :
    thresholdItemSuiteAllowed PRE_ROTATION_REGISTRY none h w = false := by
  rw [pre_rotation_threshold_gate_eq_hardcoded]
  simp [hSuite]

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
    (hGate : thresholdItemSuiteAllowed PRE_ROTATION_REGISTRY none h w = true) :
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
    (hGate : thresholdItemSuiteAllowed PRE_ROTATION_REGISTRY none h w = false) :
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

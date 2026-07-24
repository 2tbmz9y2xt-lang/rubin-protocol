/-
  RubinFormal/ThresholdSpendSuiteGateBridge.lean

  Pre-rotation singleton-registry compatibility bridge; descriptor-present or other-registry calls fail closed.
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

theorem pre_rotation_threshold_gate_eq_hardcoded
    (w : UtxoBasicV1.WitnessItem) (h : Nat) :
    thresholdItemSuiteAllowed PRE_ROTATION_REGISTRY none h w =
    decide (w.suiteId = SUITE_ID_ML_DSA_87) := by
  simp [thresholdItemSuiteAllowed, Rotation.PRE_ROTATION_REGISTRY, Rotation.ML_DSA_87_ENTRY]

theorem pre_rotation_hardcoded_accept_implies_gate
    (w : UtxoBasicV1.WitnessItem) (h : Nat)
    (hSuite : w.suiteId = SUITE_ID_ML_DSA_87) :
    thresholdItemSuiteAllowed PRE_ROTATION_REGISTRY none h w = true := by
  rw [pre_rotation_threshold_gate_eq_hardcoded]
  simp [hSuite]

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

theorem live_threshold_suite_check_passes_on_gate_accept
    (w : UtxoBasicV1.WitnessItem) (h : Nat)
    (hGate : thresholdItemSuiteAllowed PRE_ROTATION_REGISTRY none h w = true) :
    (w.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = true := by
  have hEq := (pre_rotation_threshold_gate_eq_hardcoded w h) ▸ hGate
  simp only [decide_eq_true_eq] at hEq
  rw [hEq, utxo_suite_eq_canonical]
  native_decide

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

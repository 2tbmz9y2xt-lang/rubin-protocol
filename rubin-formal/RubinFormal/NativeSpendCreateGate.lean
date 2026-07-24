/-
  RubinFormal/NativeSpendCreateGate.lean — FI-ROT-04 + FI-ROT-05

  Q-FORMAL-ROTATION-04:
  FI-ROT-04: native_spend_gate_sound — AcceptNativeSpend(tx,h) →
    witness.suite_id ∈ NATIVE_SPEND_SUITES(h)
  FI-ROT-05: p2pk_create_cutoff_v1 — AcceptCreate_CORE_P2PK(output,h) →
    output.suite_id ∈ NATIVE_CREATE_SUITES(h)

  Spec: CANONICAL §5.4 (witness canonicalization), §4.1.2 (suite phases).
  Depends: Q-FORMAL-ROTATION-02 (NativeRegistryResolution.lean).
  Closes #124.
-/

import RubinFormal.RotationPrelude
import RubinFormal.NativeSuiteRotation
import RubinFormal.NativeRegistryResolution

namespace RubinFormal

namespace NativeSpendCreateGate

open Rotation
open NativeSuiteRotation
open NativeRegistryResolution

/-! ### Abstract spend/create gate model

  The semantic gate checks whether a witness suite_id is in the
  active suite set for the current height. This is distinct from
  the parser (which accepts any suite for canonical parsing) and
  the weight function (which assigns cost per suite). -/

/-- Result of a native spend gate check. -/
inductive GateResult where
  | accept : GateResult
  | reject_sig_alg_invalid : GateResult
      -- exact live spend path, and the newer runtime create validator, both
      -- surface TX_ERR_SIG_ALG_INVALID for suite-gate failure
  | reject_covenant_type_invalid : GateResult
      -- retained for the older abstract/legacy create-side classification
  deriving Repr, DecidableEq

/-- The native spend gate: accepts iff suite_id ∈ NATIVE_SPEND_SUITES(h).
    This models the post-rotation generalization of the hardcoded
    `suite != SUITE_ID_ML_DSA_87 → TX_ERR_SIG_ALG_INVALID` check. -/
def nativeSpendGate
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) : GateResult :=
  if suiteId ∈ NativeSpendSuites h d then GateResult.accept
  else GateResult.reject_sig_alg_invalid

/-- Descriptor-aware live spend gate predicate.
    `none` keeps the pre-rotation singleton behavior `{ML_DSA_87}`.
    `some d` lifts the post-rotation model gate onto the live spend path. -/
def liveSpendGateAllows
    (rotDesc? : Option RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) : Bool :=
  match rotDesc? with
  | none => decide (suiteId = RubinFormal.SUITE_ID_ML_DSA_87)
  | some d => decide (nativeSpendGate d h suiteId = GateResult.accept)

/-- Descriptor-aware live P2PK create gate predicate.
    `none` keeps the pre-rotation singleton behavior `{ML_DSA_87}`.
    `some d` lifts the post-rotation model create gate onto the live create path. -/
def liveCreateGateAllows
    (rotDesc? : Option RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) : Bool :=
  match rotDesc? with
  | none => decide (suiteId = RubinFormal.SUITE_ID_ML_DSA_87)
  | some d => decide (suiteId ∈ NativeCreateSuites h d)

/-- The native P2PK create gate: accepts iff suite_id ∈ NATIVE_CREATE_SUITES(h).
    P2PK is the only native covenant that commits suite_id at creation time. -/
def nativeP2PKCreateGate
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) : GateResult :=
  if suiteId ∈ NativeCreateSuites h d then GateResult.accept
  else GateResult.reject_covenant_type_invalid

/-! ### FI-ROT-04: native_spend_gate_sound -/

/-- FI-ROT-04 (soundness): if the spend gate accepts, the suite is in
    NATIVE_SPEND_SUITES(h). -/
theorem fi_rot_04_spend_gate_sound
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat)
    (haccept : nativeSpendGate d h suiteId = GateResult.accept) :
    suiteId ∈ NativeSpendSuites h d := by
  unfold nativeSpendGate at haccept
  split at haccept
  · assumption
  · contradiction

/-- FI-ROT-04 (completeness): if suite ∉ NATIVE_SPEND_SUITES(h),
    the gate rejects with TX_ERR_SIG_ALG_INVALID. -/
theorem fi_rot_04_spend_gate_rejects
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat)
    (hnotIn : suiteId ∉ NativeSpendSuites h d) :
    nativeSpendGate d h suiteId = GateResult.reject_sig_alg_invalid := by
  unfold nativeSpendGate
  simp [hnotIn]

/-- FI-ROT-04 (equivalence): the gate is equivalent to membership. -/
theorem fi_rot_04_spend_gate_iff
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) :
    nativeSpendGate d h suiteId = GateResult.accept ↔
    suiteId ∈ NativeSpendSuites h d := by
  constructor
  · exact fi_rot_04_spend_gate_sound d h suiteId
  · intro hmem
    unfold nativeSpendGate
    simp [hmem]

/-- Pre-rotation fallback branch of the live spend gate helper. -/
theorem liveSpendGateAllows_none_iff
    (h : Nat) (suiteId : Nat) :
    liveSpendGateAllows none h suiteId = true ↔
    suiteId = RubinFormal.SUITE_ID_ML_DSA_87 := by
  constructor
  · intro hAllow
    simpa [liveSpendGateAllows] using hAllow
  · intro hEq
    simp [liveSpendGateAllows, hEq]

/-- Post-rotation branch of the live spend gate helper is equivalent to the
    abstract spend gate acceptance criterion. -/
theorem liveSpendGateAllows_some_iff
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) :
    liveSpendGateAllows (some d) h suiteId = true ↔
    suiteId ∈ NativeSpendSuites h d := by
  constructor
  · intro hAllow
    have hGate : nativeSpendGate d h suiteId = GateResult.accept := by
      simpa [liveSpendGateAllows] using hAllow
    exact (fi_rot_04_spend_gate_iff d h suiteId).mp hGate
  · intro hMem
    have hGate : nativeSpendGate d h suiteId = GateResult.accept :=
      (fi_rot_04_spend_gate_iff d h suiteId).mpr hMem
    simp [liveSpendGateAllows, hGate]

/-- Boolean false form of the post-rotation live spend gate helper. -/
theorem liveSpendGateAllows_some_false_iff
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) :
    liveSpendGateAllows (some d) h suiteId = false ↔
    suiteId ∉ NativeSpendSuites h d := by
  constructor
  · intro hFalse
    intro hMem
    have hTrue : liveSpendGateAllows (some d) h suiteId = true :=
      (liveSpendGateAllows_some_iff d h suiteId).mpr hMem
    rw [hFalse] at hTrue
    cases hTrue
  · intro hNotMem
    cases hAllow : liveSpendGateAllows (some d) h suiteId with
    | false => rfl
    | true =>
        exfalso
        exact hNotMem ((liveSpendGateAllows_some_iff d h suiteId).mp hAllow)

/-- Pre-rotation fallback branch of the live create gate helper. -/
theorem liveCreateGateAllows_none_iff
    (h : Nat) (suiteId : Nat) :
    liveCreateGateAllows none h suiteId = true ↔
    suiteId = RubinFormal.SUITE_ID_ML_DSA_87 := by
  constructor
  · intro hAllow
    simpa [liveCreateGateAllows] using hAllow
  · intro hEq
    simp [liveCreateGateAllows, hEq]

/-- Post-rotation branch of the live create gate helper is equivalent to the
    abstract create gate acceptance criterion. -/
theorem liveCreateGateAllows_some_iff
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) :
    liveCreateGateAllows (some d) h suiteId = true ↔
    suiteId ∈ NativeCreateSuites h d := by
  simp [liveCreateGateAllows]

/-- Boolean false form of the post-rotation live create gate helper. -/
theorem liveCreateGateAllows_some_false_iff
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) :
    liveCreateGateAllows (some d) h suiteId = false ↔
    suiteId ∉ NativeCreateSuites h d := by
  constructor
  · intro hFalse
    intro hMem
    have hTrue : liveCreateGateAllows (some d) h suiteId = true :=
      (liveCreateGateAllows_some_iff d h suiteId).mpr hMem
    rw [hFalse] at hTrue
    cases hTrue
  · intro hNotMem
    cases hAllow : liveCreateGateAllows (some d) h suiteId with
    | false => rfl
    | true =>
        exfalso
        exact hNotMem ((liveCreateGateAllows_some_iff d h suiteId).mp hAllow)

/-- FI-ROT-04: spend gate is determined solely by (d, h, suiteId).
    No covenant-type-specific logic: the gate function signature takes
    only descriptor, height, and suiteId — covenant type is not an argument.
    This is the architectural invariant: suite gating is uniform. -/
theorem fi_rot_04_spend_gate_determined_by_suite
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) :
    ∀ (result : GateResult),
      nativeSpendGate d h suiteId = result →
      (result = GateResult.accept ↔ suiteId ∈ NativeSpendSuites h d) := by
  intro result hresult
  constructor
  · intro heq; rw [heq] at hresult; exact fi_rot_04_spend_gate_sound d h suiteId hresult
  · intro hmem
    have : nativeSpendGate d h suiteId = GateResult.accept :=
      (fi_rot_04_spend_gate_iff d h suiteId).mpr hmem
    rw [this] at hresult; exact hresult.symm

/-- FI-ROT-04: accepted suite is never sentinel (from wellFormedDescriptor). -/
theorem fi_rot_04_accepted_not_sentinel
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat)
    (hwf : wellFormedDescriptor reg d)
    (haccept : nativeSpendGate d h suiteId = GateResult.accept) :
    suiteId ≠ RubinFormal.SUITE_ID_SENTINEL := by
  have hmem := fi_rot_04_spend_gate_sound d h suiteId haccept
  exact active_spend_suite_not_sentinel reg d h suiteId hwf hmem
where
  active_spend_suite_not_sentinel
      (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat) (sid : Nat)
      (hwf : wellFormedDescriptor reg d)
      (hactive : sid ∈ NativeSpendSuites h d) :
      sid ≠ RubinFormal.SUITE_ID_SENTINEL := by
    obtain ⟨_, holdNS, hnewNS, _, _, _⟩ := hwf
    rcases spend_suites_subset d h sid hactive with rfl | rfl <;> assumption

/-! ### FI-ROT-05: p2pk_create_cutoff_v1 -/

/-- FI-ROT-05 (soundness): if the P2PK create gate accepts, the suite is in
    NATIVE_CREATE_SUITES(h). -/
theorem fi_rot_05_create_gate_sound
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat)
    (haccept : nativeP2PKCreateGate d h suiteId = GateResult.accept) :
    suiteId ∈ NativeCreateSuites h d := by
  unfold nativeP2PKCreateGate at haccept
  split at haccept
  · assumption
  · contradiction

/-- FI-ROT-05 (equivalence): create gate is equivalent to membership. -/
theorem fi_rot_05_create_gate_iff
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat) :
    nativeP2PKCreateGate d h suiteId = GateResult.accept ↔
    suiteId ∈ NativeCreateSuites h d :=
  ⟨fi_rot_05_create_gate_sound d h suiteId,
   fun hmem => by unfold nativeP2PKCreateGate; simp [hmem]⟩

/-- FI-ROT-05 (completeness): if suite ∉ NATIVE_CREATE_SUITES(h),
    P2PK creation is rejected. -/
theorem fi_rot_05_create_gate_rejects
    (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat)
    (hnotIn : suiteId ∉ NativeCreateSuites h d) :
    nativeP2PKCreateGate d h suiteId = GateResult.reject_covenant_type_invalid := by
  unfold nativeP2PKCreateGate
  simp [hnotIn]

/-- FI-ROT-05 (cutoff corollary): after H2, old suite P2PK creation is invalid. -/
theorem fi_rot_05_old_suite_rejected_after_h2
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat)
    (hwf : wellFormedDescriptor reg d)
    (hge : d.h2 ≤ h) :
    nativeP2PKCreateGate d h d.oldSuiteId = GateResult.reject_covenant_type_invalid := by
  apply fi_rot_05_create_gate_rejects
  unfold NativeCreateSuites
  obtain ⟨hneq, _, _, _, _, _⟩ := hwf
  have hge1 : ¬ h < d.h1 := by omega
  have hge2 : ¬ h < d.h2 := by omega
  simp [hge1, hge2, List.mem_singleton]
  exact hneq

/-- FI-ROT-05: accepted create suite is never sentinel. -/
theorem fi_rot_05_accepted_not_sentinel
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat) (suiteId : Nat)
    (hwf : wellFormedDescriptor reg d)
    (haccept : nativeP2PKCreateGate d h suiteId = GateResult.accept) :
    suiteId ≠ RubinFormal.SUITE_ID_SENTINEL := by
  have hmem := fi_rot_05_create_gate_sound d h suiteId haccept
  obtain ⟨_, holdNS, hnewNS, _, _, _⟩ := hwf
  rcases create_suites_subset d h suiteId hmem with rfl | rfl <;> assumption

end NativeSpendCreateGate

end RubinFormal

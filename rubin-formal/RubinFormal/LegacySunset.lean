/-
  RubinFormal/LegacySunset.lean — FI-ROT-06

  Q-FORMAL-ROTATION-05: legacy_noncommitting_outputs_not_frozen_before_H4

  Before H4: old suite spends valid (even after H2 create cutoff).
  At/after H4: old suite spends rejected for ALL native covenant types.
  Non-committing create formats (VAULT/MULTISIG/HTLC/STEALTH) are not
  affected by the H2 P2PK-create cutoff since they don't commit suite at creation.

  Spec: CANONICAL §4.1.2 (five-case table), §4.1.4 (sunset).
  Depends: Q-FORMAL-ROTATION-04 (NativeSpendCreateGate.lean).
  Closes #125.
-/

import RubinFormal.RotationPrelude
import RubinFormal.NativeSuiteRotation
import RubinFormal.NativeSpendCreateGate

namespace RubinFormal

namespace LegacySunset

open Rotation
open NativeSuiteRotation
open NativeSpendCreateGate

/-! ### FI-ROT-06: legacy sunset behavior -/

/-- Before H4 (or H4 undefined), old suite is in NATIVE_SPEND_SUITES(h). -/
theorem fi_rot_06_old_suite_spendable_before_h4
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat)
    (_hwf : wellFormedDescriptor reg d)
    (hno_sunset : d.h4 = none ∨ ∃ h4val, d.h4 = some h4val ∧ h < h4val) :
    d.oldSuiteId ∈ NativeSpendSuites h d := by
  unfold NativeSpendSuites
  split
  · -- h < h1: spend = [old]
    simp [List.mem_singleton]
  · -- h ≥ h1
    rcases hno_sunset with hnone | ⟨h4val, hsome, hlt⟩
    · simp [hnone, List.mem_cons, List.mem_singleton]
    · simp [hsome]
      have : ¬ h4val ≤ h := by omega
      simp [this, List.mem_cons, List.mem_singleton]

/-- Before H4, old suite spend gate accepts. -/
theorem fi_rot_06_old_suite_spend_accepted_before_h4
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat)
    (hwf : wellFormedDescriptor reg d)
    (hno_sunset : d.h4 = none ∨ ∃ h4val, d.h4 = some h4val ∧ h < h4val) :
    nativeSpendGate d h d.oldSuiteId = GateResult.accept := by
  have hmem := fi_rot_06_old_suite_spendable_before_h4 reg d h hwf hno_sunset
  exact (fi_rot_04_spend_gate_iff d h d.oldSuiteId).mpr hmem

/-- At/after H4, old suite is NOT in NATIVE_SPEND_SUITES(h). -/
theorem fi_rot_06_old_suite_not_spendable_after_h4
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat)
    (hwf : wellFormedDescriptor reg d)
    (h4val : Nat) (hh4 : d.h4 = some h4val) (hge : h4val ≤ h) :
    d.oldSuiteId ∉ NativeSpendSuites h d := by
  unfold NativeSpendSuites
  obtain ⟨hneq, _, _, _, hh12, hh24⟩ := hwf
  split
  · -- h < h1: spend = [old], but h4val ≤ h and h1 < h2 < h4val, contradiction
    have : d.h2 < h4val := hh24 h4val hh4
    omega
  · simp [hh4, hge, List.mem_singleton]
    exact hneq

/-- After H4, old suite spend gate rejects with TX_ERR_SIG_ALG_INVALID.
    This is the universal sunset: ALL native covenant types (P2PK, MULTISIG,
    VAULT, STEALTH) reject old suite spends after H4. -/
theorem fi_rot_06_old_suite_rejected_after_h4
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat)
    (hwf : wellFormedDescriptor reg d)
    (h4val : Nat) (hh4 : d.h4 = some h4val) (hge : h4val ≤ h) :
    nativeSpendGate d h d.oldSuiteId = GateResult.reject_sig_alg_invalid := by
  exact fi_rot_04_spend_gate_rejects d h d.oldSuiteId
    (fi_rot_06_old_suite_not_spendable_after_h4 reg d h hwf h4val hh4 hge)

/-- After H4, new suite remains spendable (new suite is always in spend set
    once h ≥ h1, and H4 > h2 > h1 by well-formedness). -/
theorem fi_rot_06_new_suite_always_spendable_after_h4
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat)
    (hwf : wellFormedDescriptor reg d)
    (h4val : Nat) (hh4 : d.h4 = some h4val) (hge : h4val ≤ h) :
    d.newSuiteId ∈ NativeSpendSuites h d := by
  obtain ⟨_, _, _, _, hh12, hh24⟩ := hwf
  have : d.h2 < h4val := hh24 h4val hh4
  unfold NativeSpendSuites
  have : ¬ h < d.h1 := by omega
  simp [this, hh4, hge, List.mem_singleton]

/-! ### Non-committing covenant types and H2

  VAULT, MULTISIG, HTLC, and STEALTH do not commit suite_id at creation.
  The H2 create cutoff only affects P2PK (which commits suite in covenant data).
  Spend-side gate is uniform — all types use NATIVE_SPEND_SUITES. -/

/-- H2 create cutoff only restricts NATIVE_CREATE_SUITES, not NATIVE_SPEND_SUITES.
    After H2, old suite can still be spent (until H4). -/
theorem fi_rot_06_spend_unaffected_by_h2_create_cutoff
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat)
    (hwf : wellFormedDescriptor reg d)
    (_hge_h2 : d.h2 ≤ h)
    (hno_sunset : d.h4 = none ∨ ∃ h4val, d.h4 = some h4val ∧ h < h4val) :
    d.oldSuiteId ∈ NativeSpendSuites h d := by
  exact fi_rot_06_old_suite_spendable_before_h4 reg d h hwf hno_sunset

end LegacySunset

end RubinFormal

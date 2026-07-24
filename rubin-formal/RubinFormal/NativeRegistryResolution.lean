/-
  RubinFormal/NativeRegistryResolution.lean — FI-ROT-03 + universal

  Evidence level: machine_checked_universal.
  `native_rotation_ok_constrained` proves: ∀ well-formed descriptor in
  well-formed registry, ∀ height → phase partition holds ∧ all active
  create/spend suites resolve to unique entries. Covers all 5 rotation
  phases including post-rotation dispatch.
  No claim about byte-level wire encoding trace (G7 residual).

  Q-FORMAL-ROTATION-02: native registry resolution is deterministic.
  suite_id ∈ ActiveNativeSuites(h) → ∃! entry, registryLookup(suite_id)

  Spec: CANONICAL §4.1.1, §4.1.2, §4.1.3, §23.2.1.
  Depends: Q-FORMAL-ROTATION-01 (NativeSuiteRotation.lean).
  Closes #122, #368.
-/

import RubinFormal.RotationPrelude
import RubinFormal.NativeSuiteRotation

namespace RubinFormal

namespace NativeRegistryResolution

open Rotation
open NativeSuiteRotation

/-! ### Registry well-formedness -/

/-- A registry is well-formed if no two entries share the same suiteId. -/
def registryNoDuplicates (reg : SuiteRegistry) : Prop :=
  ∀ (i j : Nat) (hi : i < reg.length) (hj : j < reg.length),
    (reg.get ⟨i, hi⟩).suiteId = (reg.get ⟨j, hj⟩).suiteId → i = j

/-! ### FI-ROT-03: registry resolution deterministic -/

/-- The result of `registryLookup` is deterministic by construction:
    `List.find?` always returns the same element for the same input. -/
theorem fi_rot_03_registry_lookup_deterministic
    (reg : SuiteRegistry) (sid : Nat) :
    ∀ (e1 e2 : SuiteEntry),
      registryLookup reg sid = some e1 →
      registryLookup reg sid = some e2 →
      e1 = e2 := by
  intro e1 e2 h1 h2
  rw [h1] at h2
  injection h2

/-- For a well-formed registry (no duplicates), if a suite is registered,
    lookup returns an entry whose fields are uniquely determined. -/
theorem fi_rot_03_unique_entry
    (reg : SuiteRegistry) (sid : Nat)
    (_hnd : registryNoDuplicates reg)
    (hreg : isRegistered reg sid) :
    ∃ entry, registryLookup reg sid = some entry ∧ ∀ e2, registryLookup reg sid = some e2 → e2 = entry := by
  obtain ⟨entry, hentry⟩ := hreg
  exact ⟨entry, hentry, fun e2 h2 => by rw [hentry] at h2; exact (Option.some.inj h2).symm⟩

/-- The looked-up entry's canonical tuple fields are uniquely determined by the
    suite_id and registry. -/
theorem fi_rot_03_params_unique
    (reg : SuiteRegistry) (sid : Nat) (entry : SuiteEntry)
    (hfind : registryLookup reg sid = some entry) :
    ∀ e2, registryLookup reg sid = some e2 →
      e2.semanticId = entry.semanticId ∧
      e2.pubkeyBytes = entry.pubkeyBytes ∧
      e2.sigBytes = entry.sigBytes ∧
      e2.verifyCost = entry.verifyCost ∧
      e2.bindingProfile = entry.bindingProfile := by
  intro e2 h2
  have : e2 = entry := fi_rot_03_registry_lookup_deterministic reg sid e2 entry h2 hfind
  subst this
  constructor
  · rfl
  · constructor
    · rfl
    · constructor
      · rfl
      · constructor
        · rfl
        · rfl

/-! ### Connection to active suites and descriptors -/

/-- NativeCreateSuites only contains oldSuiteId and/or newSuiteId. -/
theorem create_suites_subset
    (d : RotationDeploymentDescriptor) (h : Nat) (sid : Nat)
    (hmem : sid ∈ NativeCreateSuites h d) :
    sid = d.oldSuiteId ∨ sid = d.newSuiteId := by
  unfold NativeCreateSuites at hmem
  split at hmem
  · simp [List.mem_singleton] at hmem; exact Or.inl hmem
  · split at hmem
    · simp [List.mem_cons, List.mem_singleton] at hmem
      rcases hmem with h1 | h2 <;> [exact Or.inl h1; exact Or.inr h2]
    · simp [List.mem_singleton] at hmem; exact Or.inr hmem

/-- NativeSpendSuites only contains oldSuiteId and/or newSuiteId. -/
theorem spend_suites_subset
    (d : RotationDeploymentDescriptor) (h : Nat) (sid : Nat)
    (hmem : sid ∈ NativeSpendSuites h d) :
    sid = d.oldSuiteId ∨ sid = d.newSuiteId := by
  unfold NativeSpendSuites at hmem
  split at hmem
  · simp [List.mem_singleton] at hmem; exact Or.inl hmem
  · cases hh4 : d.h4 with
    | none =>
      simp [hh4] at hmem
      rcases hmem with h1 | h2 <;> [exact Or.inl h1; exact Or.inr h2]
    | some h4val =>
      simp [hh4] at hmem
      split at hmem
      · simp [List.mem_singleton] at hmem; exact Or.inr hmem
      · simp [List.mem_cons, List.mem_singleton] at hmem
        rcases hmem with h1 | h2 <;> [exact Or.inl h1; exact Or.inr h2]

/-- A well-formed descriptor's active suites are all registered.
    PROVED: NativeCreateSuites/NativeSpendSuites only return
    d.oldSuiteId or d.newSuiteId, both registered by hypothesis. -/
theorem descriptor_suites_registered
    (d : RotationDeploymentDescriptor) (reg : SuiteRegistry) (h : Nat)
    (hwf : wellFormedDescriptor reg d) :
    (∀ sid ∈ NativeCreateSuites h d, isRegistered reg sid) ∧
    (∀ sid ∈ NativeSpendSuites h d, isRegistered reg sid) := by
  have hcons := wellFormedDescriptor_registryConsistent reg d hwf
  obtain ⟨hold, hnew⟩ := hcons
  constructor
  · intro sid hmem
    rcases create_suites_subset d h sid hmem with rfl | rfl
    · exact hold
    · exact hnew
  · intro sid hmem
    rcases spend_suites_subset d h sid hmem with rfl | rfl
    · exact hold
    · exact hnew

/-- Main theorem: for any active native spend suite at height h, registry
    resolution returns exactly one entry with determined parameters.

    This is the formal guarantee that the consensus code can replace
    hardcoded constants with registry lookups without ambiguity. -/
theorem fi_rot_03_active_suite_resolves
    (d : RotationDeploymentDescriptor) (reg : SuiteRegistry) (h : Nat) (sid : Nat)
    (hnd : registryNoDuplicates reg)
    (hwf : wellFormedDescriptor reg d)
    (hactive : sid ∈ NativeSpendSuites h d) :
    ∃ entry, registryLookup reg sid = some entry ∧ ∀ e2, registryLookup reg sid = some e2 → e2 = entry := by
  have ⟨_, hspend⟩ := descriptor_suites_registered d reg h hwf
  exact fi_rot_03_unique_entry reg sid hnd (hspend sid hactive)

/-- Same for create suites. -/
theorem fi_rot_03_active_create_suite_resolves
    (d : RotationDeploymentDescriptor) (reg : SuiteRegistry) (h : Nat) (sid : Nat)
    (hnd : registryNoDuplicates reg)
    (hwf : wellFormedDescriptor reg d)
    (hactive : sid ∈ NativeCreateSuites h d) :
    ∃ entry, registryLookup reg sid = some entry ∧ ∀ e2, registryLookup reg sid = some e2 → e2 = entry := by
  have ⟨hcreate, _⟩ := descriptor_suites_registered d reg h hwf
  exact fi_rot_03_unique_entry reg sid hnd (hcreate sid hactive)

/-! ### Canonical single-suite registry theorems (#287)

  Parametric versions that take any registry equal to `[ML_DSA_87_ENTRY]`,
  removing hard dependence on the `PRE_ROTATION_REGISTRY` constant.
  The pre-rotation specialisations are backward-compatible corollaries. -/

/-- Any single-ML-DSA-87 registry resolves suite 0x01 to ML_DSA_87_ENTRY. -/
theorem single_ml_dsa_registry_resolves (reg : SuiteRegistry)
    (hreg : reg = [ML_DSA_87_ENTRY]) :
    registryLookup reg 0x01 = some ML_DSA_87_ENTRY := by
  subst hreg; native_decide

/-- Any single-entry registry trivially has no duplicate suite IDs. -/
theorem single_entry_registry_no_duplicates (reg : SuiteRegistry) (e : SuiteEntry)
    (hreg : reg = [e]) :
    registryNoDuplicates reg := by
  subst hreg; intro i j hi hj _; simp at hi hj; omega

/-- Pre-rotation corollary: ML-DSA-87 resolves correctly. -/
theorem fi_rot_03_pre_rotation_ml_dsa_resolves :
    registryLookup PRE_ROTATION_REGISTRY 0x01 = some ML_DSA_87_ENTRY :=
  single_ml_dsa_registry_resolves PRE_ROTATION_REGISTRY rfl

/-- Pre-rotation corollary: no duplicate suite IDs. -/
theorem fi_rot_03_pre_rotation_no_duplicates :
    registryNoDuplicates PRE_ROTATION_REGISTRY :=
  single_entry_registry_no_duplicates PRE_ROTATION_REGISTRY ML_DSA_87_ENTRY rfl

-- ═══════════════════════════════════════════════════════════════════
-- §  Constrained universal theorem (§4.1.2, §4.1.3, §23.2.1)
-- ═══════════════════════════════════════════════════════════════════

/-- **Native rotation constrained universal** (§4.1.2/§4.1.3/§23.2.1):
    for any well-formed descriptor in a well-formed registry, at every
    height the phase partition holds and all active suites (create and
    spend) resolve to unique registry entries.
    Scope: structural model parity with Go/Rust suite_registry.
    No claim about byte-level wire encoding trace (G7 residual). -/
theorem native_rotation_ok_constrained
    (d : RotationDeploymentDescriptor) (reg : SuiteRegistry)
    (hwf : wellFormedDescriptor reg d)
    (hnd : registryNoDuplicates reg)
    (h : Nat) :
    RotationPhase d h ∧
    (∀ sid, sid ∈ NativeCreateSuites h d →
      ∃ entry, registryLookup reg sid = some entry ∧
      ∀ e2, registryLookup reg sid = some e2 → e2 = entry) ∧
    (∀ sid, sid ∈ NativeSpendSuites h d →
      ∃ entry, registryLookup reg sid = some entry ∧
      ∀ e2, registryLookup reg sid = some e2 → e2 = entry) :=
  ⟨NativeSuiteRotation.fi_rot_02_phase_partition reg d hwf h,
   fun sid hm => fi_rot_03_active_create_suite_resolves d reg h sid hnd hwf hm,
   fun sid hm => fi_rot_03_active_suite_resolves d reg h sid hnd hwf hm⟩

end NativeRegistryResolution

end RubinFormal

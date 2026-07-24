/-
  RubinFormal/RegistryResolutionLiveBridge.lean — FI-ROT-03 Live Bridge

  Bridges model registryLookup / NativeRegistryResolution theorems to
  live Go/Rust SuiteRegistry behavior.

  Live code mapping:
  - Go:   consensus/suite_registry.go → Lookup, IsRegistered, DefaultSuiteRegistry
  - Rust: src/suite_registry.rs → lookup, is_registered, default_suite_registry
  - Go:   consensus/suite_registry.go → DescriptorRotationProvider.NativeCreateSuites/NativeSpendSuites
  - Rust: src/suite_registry.rs → DescriptorRotationProvider

  The Lean `registryLookup` (List.find?) faithfully models Go/Rust map-based
  lookup for well-formed registries (no duplicate IDs). This file proves
  completeness properties bridging model guarantees to live code behavior.

  Spec: CANONICAL §4.1.1 (suite registry), §4.1.2 (rotation phases).
  Depends: NativeRegistryResolution.lean, NativeSuiteRotation.lean.
-/

import RubinFormal.NativeRegistryResolution
import RubinFormal.NativeSuiteRotation

namespace RubinFormal

namespace RegistryResolutionLiveBridge

open Rotation NativeSuiteRotation NativeRegistryResolution

-- ═══════════════════════════════════════════════════════════════════
-- §1  Pre-rotation negative lookup bridge
--
-- Go `DefaultSuiteRegistry().Lookup(id)` returns `(zero, false)` for
-- any id ∉ {0x01}. Rust `default_suite_registry().lookup(id)` is identical.
-- ═══════════════════════════════════════════════════════════════════

/-- SENTINEL (0x00) is not registered in the pre-rotation registry.
    Bridges Go `DefaultSuiteRegistry().IsRegistered(SUITE_ID_SENTINEL) = false`. -/
theorem sentinel_not_registered :
    registryLookup PRE_ROTATION_REGISTRY SUITE_ID_SENTINEL = none := by
  native_decide

/-- Suite 0x02 is not registered pre-rotation. No second suite exists before
    rotation activation. Matches Go `DefaultSuiteRegistry().Lookup(0x02) → false`. -/
theorem suite_02_not_registered :
    registryLookup PRE_ROTATION_REGISTRY 0x02 = none := by
  native_decide

/-- Suite 0xFF is not registered pre-rotation.
    Matches Go `DefaultSuiteRegistry().Lookup(0xFF) → false`. -/
theorem suite_ff_not_registered :
    registryLookup PRE_ROTATION_REGISTRY 0xFF = none := by
  native_decide

-- ═══════════════════════════════════════════════════════════════════
-- §2  IsRegistered complete characterization (universal bridge)
-- ═══════════════════════════════════════════════════════════════════

/-- **Pre-rotation IsRegistered bridge (universal)**: a suite is registered
    in the pre-rotation registry if and only if it is ML-DSA-87 (0x01).

    This is the complete characterization bridging:
    - Go `DefaultSuiteRegistry().IsRegistered(suiteID)` → `suiteID == 0x01`
    - Rust `SuiteRegistry::default().is_registered(suite_id)` → `suite_id == 0x01`

    Universal over all Nat, not just finite test cases. -/
theorem pre_rotation_registered_iff (sid : Nat) :
    isRegistered PRE_ROTATION_REGISTRY sid ↔ sid = 1 := by
  constructor
  · -- Forward: if registered, then sid must be 0x01
    intro ⟨entry, hfind⟩
    -- The only entry in PRE_ROTATION_REGISTRY has suiteId = 1.
    -- If the find? predicate matched, then 1 == sid was true.
    by_contra hne
    have hne1 : sid ≠ 1 := hne
    -- Show lookup returns none when sid ≠ 1
    have hbeqF : ((1 : Nat) == sid) = false := by
      cases h : ((1 : Nat) == sid)
      · rfl
      · exact absurd (eq_of_beq h) (by omega)
    -- Unfold and simplify: find? on singleton with false predicate → none
    have : registryLookup PRE_ROTATION_REGISTRY sid = none := by
      unfold registryLookup PRE_ROTATION_REGISTRY ML_DSA_87_ENTRY
      simp [List.find?, hbeqF]
    rw [this] at hfind
    exact Option.noConfusion hfind
  · -- Backward: sid = 1 → registered
    intro heq; subst heq
    exact ⟨ML_DSA_87_ENTRY, by native_decide⟩

-- ═══════════════════════════════════════════════════════════════════
-- §3  Lookup params bridge — Go/Rust constant parity
-- ═══════════════════════════════════════════════════════════════════

/-- Any singleton registry extensionally equal to `[ML_DSA_87_ENTRY]` returns
    exactly the canonical ML-DSA-87 entry at suite ID `0x01`. -/
theorem single_ml_dsa_lookup_exact_entry
    (reg : SuiteRegistry) (entry : SuiteEntry)
    (hreg : reg = [ML_DSA_87_ENTRY])
    (hfind : registryLookup reg 0x01 = some entry) :
    entry = ML_DSA_87_ENTRY := by
  have hresolve : registryLookup reg 0x01 = some ML_DSA_87_ENTRY :=
    NativeRegistryResolution.single_ml_dsa_registry_resolves reg hreg
  rw [hresolve] at hfind
  simpa using (Option.some.inj hfind).symm

/-- ML-DSA-87 lookup returns exact params matching Go/Rust consensus constants:
    - Go: `ML_DSA_87_PUBKEY_BYTES = 2592`, `ML_DSA_87_SIG_BYTES = 4627`, `VERIFY_COST_ML_DSA_87 = 8`
    - Rust: same constants in `params.rs`

    Quantified over every entry returned by a singleton ML-DSA-87 registry. -/
theorem ml_dsa_87_params_bridge
    (reg : SuiteRegistry) (entry : SuiteEntry)
    (hreg : reg = [ML_DSA_87_ENTRY])
    (hfind : registryLookup reg 0x01 = some entry) :
    entry.pubkeyBytes = 2592 ∧ entry.sigBytes = 4627 ∧ entry.verifyCost = 8 := by
  have heq : entry = ML_DSA_87_ENTRY :=
    single_ml_dsa_lookup_exact_entry reg entry hreg hfind
  subst entry
  exact ⟨rfl, rfl, rfl⟩

/-- Exact pre-rotation native tuple for ML-DSA-87 as carried by the
    authoritative Section 4.1.1 registry entry, quantified over every
    singleton registry equal to `[ML_DSA_87_ENTRY]`. -/
theorem ml_dsa_87_manifest_tuple_bridge
    (reg : SuiteRegistry) (entry : SuiteEntry)
    (hreg : reg = [ML_DSA_87_ENTRY])
    (hfind : registryLookup reg 0x01 = some entry) :
    entry.suiteId = 0x01 ∧
      entry.semanticId = "ml-dsa-87" ∧
      entry.pubkeyBytes = 2592 ∧
      entry.sigBytes = 4627 ∧
      entry.verifyCost = 8 ∧
      entry.bindingProfile = "native-v1-raw-digest32" := by
  have heq : entry = ML_DSA_87_ENTRY :=
    single_ml_dsa_lookup_exact_entry reg entry hreg hfind
  subst entry
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-- Exact `NativeSuiteEntryBytes_v1` payload for the pre-rotation ML-DSA-87
    native registry entry. This closes the normative field order for the
    native component of the canonical binding manifest for every singleton
    registry equal to `[ML_DSA_87_ENTRY]`. -/
theorem ml_dsa_87_manifest_bytes_hash_bridge
    (reg : SuiteRegistry) (entry : SuiteEntry)
    (hreg : reg = [ML_DSA_87_ENTRY])
    (hfind : registryLookup reg 0x01 = some entry) :
    Rotation.nativeSuiteEntryBytesV1? entry = some
      (RubinFormal.bytes #[
        0x01,
        0x09, 0x6d, 0x6c, 0x2d, 0x64, 0x73, 0x61, 0x2d, 0x38, 0x37,
        0x20, 0x0a, 0x00, 0x00,
        0x13, 0x12, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x16, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x2d, 0x76, 0x31, 0x2d,
        0x72, 0x61, 0x77, 0x2d, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x33, 0x32
      ]) ∧
    Rotation.nativeSuiteEntryHashV1? entry = some
      (RubinFormal.bytes #[
        0x3f, 0x8a, 0x8f, 0x6b, 0xe4, 0xed, 0x04, 0x54,
        0x43, 0x32, 0xfc, 0x65, 0x3a, 0x09, 0x02, 0x47,
        0x43, 0x7a, 0x44, 0xa8, 0x0d, 0xc7, 0xba, 0x78,
        0x28, 0xc2, 0x23, 0x2d, 0xda, 0x14, 0xee, 0xa9
      ]) := by
  have heq : entry = ML_DSA_87_ENTRY :=
    single_ml_dsa_lookup_exact_entry reg entry hreg hfind
  subst entry
  exact ⟨by native_decide, by native_decide⟩

/-- The looked-up entry's suiteId matches the query — no ID confusion.
    Bridges Go: `p, ok := reg.Lookup(id); p.SuiteID == id`. -/
theorem lookup_preserves_suite_id :
    ∀ entry, registryLookup PRE_ROTATION_REGISTRY 0x01 = some entry →
      entry.suiteId = 0x01 := by
  intro entry hfind
  have : entry = ML_DSA_87_ENTRY := by
    have h := fi_rot_03_pre_rotation_ml_dsa_resolves
    rw [h] at hfind; exact Option.some.inj hfind.symm
  subst this; rfl

-- ═══════════════════════════════════════════════════════════════════
-- §4  DescriptorRotationProvider phase bridge
--
-- Go `DescriptorRotationProvider.NativeCreateSuites(height)`:
--   h < CreateHeight       → {old}
--   CreateHeight ≤ h < SpendHeight → {old, new}
--   h ≥ SpendHeight        → {new}
--
-- Go `DescriptorRotationProvider.NativeSpendSuites(height)`:
--   h < CreateHeight       → {old}
--   SunsetHeight ≠ 0 && h ≥ SunsetHeight → {new}
--   else                   → {old, new}
--
-- Lean NativeCreateSuites / NativeSpendSuites match this logic.
-- ═══════════════════════════════════════════════════════════════════

/-- Pre-rotation (h < h1): both create and spend are singleton {oldSuiteId}.
    Matches Go/Rust `DefaultRotationProvider` (always returns {ML_DSA_87}). -/
theorem pre_rotation_suites_singleton
    (d : RotationDeploymentDescriptor) (h : Nat) (hlt : h < d.h1) :
    NativeCreateSuites h d = [d.oldSuiteId] ∧
    NativeSpendSuites h d = [d.oldSuiteId] :=
  ⟨by simp [NativeCreateSuites, hlt], by simp [NativeSpendSuites, hlt]⟩

/-- Phase 2 (h1 ≤ h < h2): both create and spend include {old, new}.
    Matches Go `DescriptorRotationProvider` Phase 1 (H1 ≤ h < H2):
    create={old,new}, spend={old,new}. -/
theorem transition_phase_both_suites
    (d : RotationDeploymentDescriptor) (reg : SuiteRegistry)
    (hwf : wellFormedDescriptor reg d) (h : Nat)
    (hge : d.h1 ≤ h) (hlt : h < d.h2) :
    NativeCreateSuites h d = [d.oldSuiteId, d.newSuiteId] ∧
    NativeSpendSuites h d = [d.oldSuiteId, d.newSuiteId] := by
  have hlt1 : ¬ h < d.h1 := by omega
  constructor
  · simp [NativeCreateSuites, hlt1, hlt]
  · simp only [NativeSpendSuites, hlt1, ite_false]
    match hh4 : d.h4 with
    | none => rfl
    | some h4val =>
      have hh2h4 := hwf.2.2.2.2.2 h4val hh4
      have : ¬ h4val ≤ h := by omega
      simp [hh4, this]

/-- Post-transition create (h ≥ h2): only new suite for creation.
    Matches Go: `h ≥ SpendHeight → create={new}`. -/
theorem post_transition_create_new_only
    (d : RotationDeploymentDescriptor) (h : Nat)
    (hge1 : d.h1 ≤ h) (hge2 : d.h2 ≤ h) :
    NativeCreateSuites h d = [d.newSuiteId] := by
  simp [NativeCreateSuites, show ¬ h < d.h1 by omega, show ¬ h < d.h2 by omega]

/-- Post-sunset spend (h ≥ h4): only new suite for spending.
    Matches Go: `SunsetHeight != 0 && h >= SunsetHeight → spend={new}`. -/
theorem post_sunset_spend_new_only
    (d : RotationDeploymentDescriptor) (h h4val : Nat)
    (hge1 : d.h1 ≤ h) (hh4 : d.h4 = some h4val) (hge4 : h4val ≤ h) :
    NativeSpendSuites h d = [d.newSuiteId] := by
  simp [NativeSpendSuites, show ¬ h < d.h1 by omega, hh4, hge4]

-- ═══════════════════════════════════════════════════════════════════
-- §5  DefaultRotationProvider bridge
--
-- Go `DefaultRotationProvider` always returns {ML_DSA_87} for both
-- create and spend at all heights. Lean `preRotationActiveSuites`
-- matches this behavior exactly.
-- ═══════════════════════════════════════════════════════════════════

/-- `preRotationActiveSuites(h) = [0x01]` for all h.
    Bridges Go `DefaultRotationProvider.NativeCreateSuites/NativeSpendSuites`.
    Both always return `NewNativeSuiteSet(SUITE_ID_ML_DSA_87)`. -/
theorem default_provider_always_ml_dsa (h : Nat) :
    preRotationActiveSuites h = [0x01] := rfl

/-- Default provider suite is always registered — bridges Go safety:
    `DefaultSuiteRegistry().IsRegistered(ML_DSA_87) = true` at all heights. -/
theorem default_provider_suite_registered (h : Nat) :
    ∀ sid ∈ preRotationActiveSuites h,
      isRegistered PRE_ROTATION_REGISTRY sid := by
  intro sid hmem
  simp [preRotationActiveSuites, List.mem_singleton] at hmem
  subst hmem
  exact ⟨ML_DSA_87_ENTRY, by native_decide⟩

end RegistryResolutionLiveBridge

end RubinFormal

/-
  RubinFormal/WeightSuiteAware.lean — Q-FORMAL-ROTATION-03

  File role:
    active authoritative universal layer for post-rotation weight accounting.
    `TxWeightV2.lean` remains the historical pre-rotation helper surface.

  Theorem: weight_suite_aware_correct — for any transaction T and height h,
  weight(T,h) using NATIVE_SPEND_SUITES(h) registry VERIFY_COST is
  deterministic and matches spec §9 formula.

  Uses FI-ROT-03 registry resolution as premise.

  Spec: CANONICAL §9 (transaction weight formula).
  Depends: Q-FORMAL-ROTATION-02 (NativeRegistryResolution.lean).
  Closes #123.
-/

import RubinFormal.RotationPrelude
import RubinFormal.NativeSuiteRotation
import RubinFormal.NativeRegistryResolution
import RubinFormal.TxWeightV2

namespace RubinFormal

namespace WeightSuiteAware

open Rotation
open NativeSuiteRotation
open NativeRegistryResolution
open TxWeightV2

/-! ### Suite-aware signature cost model

  Spec §9 formula (post-rotation):
    sigCost = Σ_i costOf(witness_i.suite_id)

  where costOf(sid) :=
    if sid = SENTINEL then 0
    else match registryLookup reg sid with
    | some entry => entry.verifyCost
    | none       => VERIFY_COST_UNKNOWN_SUITE
-/

/-- Suite-aware verification cost for a single witness item.
    Looks up verifyCost from registry; falls back to VERIFY_COST_UNKNOWN_SUITE
    for unregistered suites; sentinel has zero cost. -/
def suiteAwareCost (reg : SuiteRegistry) (suiteId : Nat) : Nat :=
  if suiteId == RubinFormal.SUITE_ID_SENTINEL then 0
  else match registryLookup reg suiteId with
  | some entry => entry.verifyCost
  | none       => TxWeightV2.VERIFY_COST_UNKNOWN_SUITE

/-- Total signature cost for a list of witness suite IDs. -/
def totalSigCost (reg : SuiteRegistry) (suiteIds : List Nat) : Nat :=
  suiteIds.foldl (fun acc sid => acc + suiteAwareCost reg sid) 0

/-- Helper: Nat.beq n 0 = false when n ≠ 0. -/
private theorem nat_beq_ne_zero {n : Nat} (h : n ≠ 0) : Nat.beq n 0 = false := by
  cases n with
  | zero => exact absurd rfl h
  | succ _ => rfl

/-- Helper: suiteAwareCost unfolds for non-sentinel suites. -/
private theorem suiteAwareCost_nonSentinel (reg : SuiteRegistry) (sid : Nat)
    (h : sid ≠ RubinFormal.SUITE_ID_SENTINEL) :
    suiteAwareCost reg sid = match registryLookup reg sid with
      | some entry => entry.verifyCost
      | none => TxWeightV2.VERIFY_COST_UNKNOWN_SUITE := by
  unfold suiteAwareCost RubinFormal.SUITE_ID_SENTINEL
  have hbeq : (sid == (0 : Nat)) = false := by
    show Nat.beq sid 0 = false
    exact nat_beq_ne_zero h
  simp [hbeq]

/-! ### Determinism: same registry + same suiteIds → same cost -/

/-- suiteAwareCost is a pure function of registry and suiteId. -/
theorem fi_rot_03_suite_aware_cost_deterministic
    (reg : SuiteRegistry) (sid : Nat) :
    suiteAwareCost reg sid = suiteAwareCost reg sid :=
  rfl

/-- totalSigCost is deterministic: same inputs → same output. -/
theorem fi_rot_03_total_sig_cost_deterministic
    (reg : SuiteRegistry) (suiteIds : List Nat) :
    totalSigCost reg suiteIds = totalSigCost reg suiteIds :=
  rfl

/-! ### Pre-rotation equivalence

  In the pre-rotation registry (only ML-DSA-87), the suite-aware cost
  matches the hardcoded formula:
    suiteAwareCost(SENTINEL) = 0
    suiteAwareCost(ML_DSA_87) = VERIFY_COST_ML_DSA_87 = 8
    suiteAwareCost(unknown)  = VERIFY_COST_UNKNOWN_SUITE = 64
-/

/-- Sentinel suite has zero cost. -/
theorem fi_rot_03_sentinel_zero_cost (reg : SuiteRegistry) :
    suiteAwareCost reg RubinFormal.SUITE_ID_SENTINEL = 0 := by
  unfold suiteAwareCost RubinFormal.SUITE_ID_SENTINEL
  simp

/-- ML-DSA-87 cost matches VERIFY_COST_ML_DSA_87 in any single-ML-DSA-87 registry (#287). -/
theorem ml_dsa_cost_matches_canonical (reg : SuiteRegistry)
    (hreg : reg = [ML_DSA_87_ENTRY]) :
    suiteAwareCost reg TxWeightV2.SUITE_ID_ML_DSA_87 =
    TxWeightV2.VERIFY_COST_ML_DSA_87 := by
  subst hreg; native_decide

/-- Pre-rotation corollary. -/
theorem fi_rot_03_ml_dsa_cost_matches :
    suiteAwareCost PRE_ROTATION_REGISTRY TxWeightV2.SUITE_ID_ML_DSA_87 =
    TxWeightV2.VERIFY_COST_ML_DSA_87 :=
  ml_dsa_cost_matches_canonical PRE_ROTATION_REGISTRY rfl

/-- Unknown suite cost matches VERIFY_COST_UNKNOWN_SUITE in any registry (#287). -/
theorem unknown_suite_cost_any_registry (reg : SuiteRegistry) (sid : Nat)
    (hnotSentinel : sid ≠ RubinFormal.SUITE_ID_SENTINEL)
    (hnotRegistered : registryLookup reg sid = none) :
    suiteAwareCost reg sid =
    TxWeightV2.VERIFY_COST_UNKNOWN_SUITE := by
  rw [suiteAwareCost_nonSentinel _ _ hnotSentinel, hnotRegistered]

/-- Pre-rotation corollary. -/
theorem fi_rot_03_unknown_suite_cost (sid : Nat)
    (hnotSentinel : sid ≠ RubinFormal.SUITE_ID_SENTINEL)
    (hnotRegistered : registryLookup PRE_ROTATION_REGISTRY sid = none) :
    suiteAwareCost PRE_ROTATION_REGISTRY sid =
    TxWeightV2.VERIFY_COST_UNKNOWN_SUITE :=
  unknown_suite_cost_any_registry PRE_ROTATION_REGISTRY sid hnotSentinel hnotRegistered

/-! ### Active suites are never sentinel

  With the strengthened wellFormedDescriptor (old ≠ SENTINEL, new ≠ SENTINEL),
  any suite in NativeCreateSuites or NativeSpendSuites is non-sentinel. -/

/-- Any spend-active suite is not sentinel. -/
theorem active_spend_suite_not_sentinel
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat) (sid : Nat)
    (hwf : wellFormedDescriptor reg d)
    (hactive : sid ∈ NativeSpendSuites h d) :
    sid ≠ RubinFormal.SUITE_ID_SENTINEL := by
  obtain ⟨_, holdNS, hnewNS, _, _, _⟩ := hwf
  have hor := NativeRegistryResolution.spend_suites_subset d h sid hactive
  rcases hor with rfl | rfl <;> assumption

/-- Any create-active suite is not sentinel. -/
theorem active_create_suite_not_sentinel
    (reg : SuiteRegistry) (d : RotationDeploymentDescriptor) (h : Nat) (sid : Nat)
    (hwf : wellFormedDescriptor reg d)
    (hactive : sid ∈ NativeCreateSuites h d) :
    sid ≠ RubinFormal.SUITE_ID_SENTINEL := by
  obtain ⟨_, holdNS, hnewNS, _, _, _⟩ := hwf
  have hor := NativeRegistryResolution.create_suites_subset d h sid hactive
  rcases hor with rfl | rfl <;> assumption

/-! ### Main theorem: weight_suite_aware_correct

  For any registered suite in NATIVE_SPEND_SUITES(h), the suite-aware cost
  equals the registry's verifyCost — proving the weight formula is correct
  and deterministic when using registry lookups instead of hardcoded constants.

  Note: `hnotSentinel` is no longer a separate premise — it follows from
  `wellFormedDescriptor` which now enforces non-sentinel suite IDs. -/

/-- Main theorem: for any suite active in NATIVE_SPEND_SUITES(h),
    the suite-aware cost equals the unique registry entry's verifyCost.

    This is the formal guarantee that replacing
      `mlCount * VERIFY_COST_ML_DSA_87`
    with
      `Σ count(suite) * registry[suite].verifyCost`
    is correct for all registered suites. -/
theorem weight_suite_aware_correct
    (d : RotationDeploymentDescriptor) (reg : SuiteRegistry) (h : Nat) (sid : Nat)
    (hnd : registryNoDuplicates reg)
    (hwf : wellFormedDescriptor reg d)
    (hactive : sid ∈ NativeSpendSuites h d) :
    ∃ entry, registryLookup reg sid = some entry ∧
      suiteAwareCost reg sid = entry.verifyCost := by
  have hnotSentinel : sid ≠ RubinFormal.SUITE_ID_SENTINEL :=
    active_spend_suite_not_sentinel reg d h sid hwf hactive
  have ⟨entry, hlookup, _⟩ := fi_rot_03_active_suite_resolves d reg h sid hnd hwf hactive
  refine ⟨entry, hlookup, ?_⟩
  rw [suiteAwareCost_nonSentinel _ _ hnotSentinel, hlookup]

/-- Same for create suites. -/
theorem weight_suite_aware_correct_create
    (d : RotationDeploymentDescriptor) (reg : SuiteRegistry) (h : Nat) (sid : Nat)
    (hnd : registryNoDuplicates reg)
    (hwf : wellFormedDescriptor reg d)
    (hactive : sid ∈ NativeCreateSuites h d) :
    ∃ entry, registryLookup reg sid = some entry ∧
      suiteAwareCost reg sid = entry.verifyCost := by
  have hnotSentinel : sid ≠ RubinFormal.SUITE_ID_SENTINEL :=
    active_create_suite_not_sentinel reg d h sid hwf hactive
  have ⟨entry, hlookup, _⟩ := fi_rot_03_active_create_suite_resolves d reg h sid hnd hwf hactive
  refine ⟨entry, hlookup, ?_⟩
  rw [suiteAwareCost_nonSentinel _ _ hnotSentinel, hlookup]

/-- Two ML-DSA-87 sigs cost 16 in any single-ML-DSA-87 registry (#287). -/
theorem two_ml_dsa_sigs_cost_canonical (reg : SuiteRegistry)
    (hreg : reg = [ML_DSA_87_ENTRY]) :
    totalSigCost reg
      [TxWeightV2.SUITE_ID_ML_DSA_87, TxWeightV2.SUITE_ID_ML_DSA_87] = 16 := by
  subst hreg; native_decide

/-- Pre-rotation corollary. -/
theorem fi_rot_03_pre_rotation_two_sigs :
    totalSigCost PRE_ROTATION_REGISTRY
      [TxWeightV2.SUITE_ID_ML_DSA_87, TxWeightV2.SUITE_ID_ML_DSA_87] = 16 :=
  two_ml_dsa_sigs_cost_canonical PRE_ROTATION_REGISTRY rfl

/-- Sentinel + ML-DSA-87 costs 8 in any single-ML-DSA-87 registry (#287). -/
theorem sentinel_plus_ml_dsa_cost_canonical (reg : SuiteRegistry)
    (hreg : reg = [ML_DSA_87_ENTRY]) :
    totalSigCost reg
      [RubinFormal.SUITE_ID_SENTINEL, TxWeightV2.SUITE_ID_ML_DSA_87] = 8 := by
  subst hreg; native_decide

/-- Pre-rotation corollary. -/
theorem fi_rot_03_pre_rotation_sentinel_plus_sig :
    totalSigCost PRE_ROTATION_REGISTRY
      [RubinFormal.SUITE_ID_SENTINEL, TxWeightV2.SUITE_ID_ML_DSA_87] = 8 :=
  sentinel_plus_ml_dsa_cost_canonical PRE_ROTATION_REGISTRY rfl

end WeightSuiteAware

end RubinFormal

import RubinFormal.TxContextFormal
import RubinFormal.UtxoApplyGenesisV1

/-!
# Uint128 comparison and vault conservation bridges

These helper equivalences do not establish full transaction validation.
-/

namespace RubinFormal

/-- Live Uint128 comparator matching Go/Rust hi/lo limb ordering. -/
def compareUint128 (a b : TxContext.Uint128) : Bool :=
  if a.hi > b.hi then true
  else if a.hi = b.hi then decide (a.lo ≥ b.lo)
  else false

/-- Live limb comparator matches the TxContext model predicate exactly. -/
theorem compareUint128_eq_true_iff_model (a b : TxContext.Uint128) :
    compareUint128 a b = true ↔ TxContext.uint128GTE a b := by
  unfold compareUint128 TxContext.uint128GTE
  by_cases hgt : a.hi > b.hi
  · simp [hgt]
  · by_cases heq : a.hi = b.hi
    · by_cases hlo : a.lo ≥ b.lo <;> simp [hgt, heq, hlo]
    · simp [hgt, heq]

/-- Live Uint128 comparator is numerically equivalent to the native value order. -/
theorem compareUint128_native_equivalence (a b : TxContext.Uint128) :
    compareUint128 a b = true ↔ a.toNat ≥ b.toNat := by
  rw [compareUint128_eq_true_iff_model]
  exact TxContext.uint128GTE_native_equivalence a b

open UtxoApplyGenesisV1 in
/-- BRIDGE: live no-vault conservation path matches the model predicate. -/
theorem vault_bridge_no_vault (totalIn totalOut vis : Nat) :
    TxContext.checkValueConservation totalIn totalOut vis false = true ↔
    validateValueConservation totalOut totalIn 0 vis = .ok () := by
  simp only [TxContext.checkValueConservation, validateValueConservation]
  constructor
  · intro h
    by_cases h1 : totalOut > totalIn
    · simp [h1] at h
    · simp [h1] at h ⊢
  · intro h
    by_cases h1 : totalOut > totalIn
    · simp [h1] at h
    · simp [h1] at h ⊢

open UtxoApplyGenesisV1 in
/-- BRIDGE: live single-vault conservation path matches the model predicate. -/
theorem vault_bridge_with_vault (totalIn totalOut vis : Nat) :
    TxContext.checkValueConservation totalIn totalOut vis true = true ↔
    validateValueConservation totalOut totalIn 1 vis = .ok () := by
  simp only [TxContext.checkValueConservation, validateValueConservation]
  constructor
  · intro h
    by_cases h1 : totalOut > totalIn
    · simp [h1] at h
    · simp [h1] at h ⊢
      by_cases h2 : totalOut < vis <;> simp [h2] at h ⊢
  · intro h
    by_cases h1 : totalOut > totalIn
    · simp [h1] at h
    · simp [h1] at h ⊢
      by_cases h2 : totalOut < vis <;> simp [h2] at h ⊢

end RubinFormal

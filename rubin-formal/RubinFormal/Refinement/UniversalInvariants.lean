import RubinFormal.CriticalInvariants
import RubinFormal.ArithmeticSafety

namespace RubinFormal.Refinement

open RubinFormal

theorem weight_monotone_base (base1 base2 witness sigCost : Nat) (h : base1 ≤ base2) :
    RubinFormal.weight base1 witness sigCost ≤ RubinFormal.weight base2 witness sigCost := by
  unfold RubinFormal.weight
  have hMul : base1 * 4 ≤ base2 * 4 := Nat.mul_le_mul_right 4 h
  have hAdd1 : base1 * 4 + witness ≤ base2 * 4 + witness := Nat.add_le_add_right hMul witness
  exact Nat.add_le_add_right hAdd1 sigCost

theorem weight_monotone_sigCost (base witness sigCost1 sigCost2 : Nat) (h : sigCost1 ≤ sigCost2) :
    RubinFormal.weight base witness sigCost1 ≤ RubinFormal.weight base witness sigCost2 := by
  unfold RubinFormal.weight
  exact Nat.add_le_add_left h (base * 4 + witness)

theorem clampTimestampStep_eq_newTs_of_le (prevTs newTs maxStep : Nat)
    (h : newTs ≤ prevTs + maxStep) :
    RubinFormal.clampTimestampStep prevTs newTs maxStep = newTs := by
  unfold RubinFormal.clampTimestampStep
  exact Nat.min_eq_left h

theorem clampTimestampStep_eq_cap_of_lt (prevTs newTs maxStep : Nat)
    (h : prevTs + maxStep < newTs) :
    RubinFormal.clampTimestampStep prevTs newTs maxStep = prevTs + maxStep := by
  unfold RubinFormal.clampTimestampStep
  exact Nat.min_eq_right (Nat.le_of_lt h)

theorem satSub_eq_zero_of_le (a b : Nat) (h : a ≤ b) :
    RubinFormal.satSub a b = 0 := by
  by_cases hb : b ≤ a
  · have hab : a = b := Nat.le_antisymm h hb
    simp [RubinFormal.satSub, hb, hab]
  · simp [RubinFormal.satSub, hb]

theorem daChunkSetValid_implies_nonempty (chunks : List Nat) :
    RubinFormal.daChunkSetValid chunks → chunks ≠ [] := by
  intro h
  simpa [RubinFormal.daChunkSetValid] using h

end RubinFormal.Refinement

import Std

namespace RubinFormal

def maxU128 : Nat := (2 ^ 128) - 1

def inU128 (x : Nat) : Prop := x ≤ maxU128

def satSub (a b : Nat) : Nat :=
  if b ≤ a then a - b else 0

theorem satSub_no_underflow (a b : Nat) : satSub a b ≤ a := by
  by_cases h : b ≤ a
  · simp [satSub, h]
    exact Nat.sub_le a b
  · simp [satSub, h]

theorem satSub_exact_when_ge (a b : Nat) (h : b ≤ a) :
    satSub a b = a - b := by
  simp [satSub, h]

theorem satSub_zero_when_underflow (a b : Nat) (h : a < b) :
    satSub a b = 0 := by
  have hNot : ¬ b ≤ a := Nat.not_le_of_gt h
  simp [satSub, hNot]

def satAddU128 (a b : Nat) : Nat :=
  Nat.min (a + b) maxU128

theorem satAddU128_bounded (a b : Nat) : satAddU128 a b ≤ maxU128 := by
  unfold satAddU128
  exact Nat.min_le_right (a + b) maxU128

theorem satAddU128_preserves_lower_bound (a b : Nat) (ha : inU128 a) :
    a ≤ satAddU128 a b := by
  unfold satAddU128 inU128 at *
  by_cases hCap : a + b ≤ maxU128
  · simp [Nat.min_eq_left hCap]
    exact Nat.le_add_right a b
  · have hMin : Nat.min (a + b) maxU128 = maxU128 := Nat.min_eq_right (Nat.le_of_not_ge hCap)
    rw [hMin]
    exact ha

def floorDiv (a b : Nat) : Nat := a / b

theorem floorDiv_mul_le (a b : Nat) (hb : 0 < b) :
    floorDiv a b * b ≤ a := by
  unfold floorDiv
  exact Nat.div_mul_le_self a b

theorem floorDiv_deterministic (a b : Nat) : floorDiv a b = floorDiv a b := rfl

end RubinFormal

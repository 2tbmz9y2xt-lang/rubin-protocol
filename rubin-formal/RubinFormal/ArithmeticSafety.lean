import Std
import RubinFormal.SubsidyV1

namespace RubinFormal

def maxU64 : Nat := (2 ^ 64) - 1
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

-- §19.1 — Subsidy arithmetic fits in machine integer types.
-- PR #420 changed consensus implementations to u128/big.Int.
-- These theorems formally verify the type change is sufficient.

/-- Right-shift never increases a natural number:
    Nat.shiftRight n k = n / 2^k ≤ n. -/
private theorem nat_shiftRight_le (n k : Nat) : Nat.shiftRight n k ≤ n := by
  show n >>> k ≤ n
  rw [Nat.shiftRight_eq_div_pow]
  exact Nat.div_le_self n (2 ^ k)

/-- blockSubsidy always returns ≤ MINEABLE_CAP, hence fits in u64. -/
theorem blockSubsidy_bounded (h ag : Nat) :
    SubsidyV1.blockSubsidy h ag ≤ SubsidyV1.MINEABLE_CAP := by
  unfold SubsidyV1.blockSubsidy
  split
  · -- h == 0 → result is 0
    exact Nat.zero_le _
  · split
    · -- alreadyGenerated ≥ MINEABLE_CAP → result is TAIL_EMISSION_PER_BLOCK
      unfold SubsidyV1.TAIL_EMISSION_PER_BLOCK SubsidyV1.MINEABLE_CAP; omega
    · -- else: let remaining; let baseReward; if ... then TAIL else baseReward
      -- Beta-reduce let bindings so split can reach the inner if:
      show (if Nat.shiftRight (SubsidyV1.MINEABLE_CAP - ag) SubsidyV1.EMISSION_SPEED_FACTOR
              < SubsidyV1.TAIL_EMISSION_PER_BLOCK
            then SubsidyV1.TAIL_EMISSION_PER_BLOCK
            else Nat.shiftRight (SubsidyV1.MINEABLE_CAP - ag) SubsidyV1.EMISSION_SPEED_FACTOR)
            ≤ SubsidyV1.MINEABLE_CAP
      split
      · -- baseReward < TAIL → result is TAIL ≤ MINEABLE_CAP
        unfold SubsidyV1.TAIL_EMISSION_PER_BLOCK SubsidyV1.MINEABLE_CAP; omega
      · -- baseReward ≥ TAIL → result is shiftRight(remaining, 20) ≤ remaining ≤ MINEABLE_CAP
        exact Nat.le_trans (nat_shiftRight_le _ _) (Nat.sub_le _ _)

/-- MINEABLE_CAP fits in u64.
    F-AUDIT-11: native_decide is used because these are concrete numeric comparisons
    (4900000000000000 ≤ 2^64-1). Lean's `decide` times out on numbers this large.
    `norm_num` (Mathlib) would be kernel-verified but Mathlib is not a dependency.
    native_decide compiles to a native binary checked by the Lean compiler. -/
theorem mineable_cap_in_u64 : SubsidyV1.MINEABLE_CAP ≤ maxU64 := by
  native_decide

/-- blockSubsidy result fits in u64. -/
theorem blockSubsidy_in_u64 (h ag : Nat) :
    SubsidyV1.blockSubsidy h ag ≤ maxU64 :=
  Nat.le_trans (blockSubsidy_bounded h ag) mineable_cap_in_u64

/-- alreadyGenerated + blockSubsidy + fees fits in u128 when inputs are bounded.
    This is the key safety theorem for PR #420 (u128 arithmetic). -/
theorem subsidy_accumulation_in_u128 (h ag fees : Nat)
    (hAg : ag ≤ SubsidyV1.MINEABLE_CAP)
    (hFees : fees ≤ maxU64) :
    ag + SubsidyV1.blockSubsidy h ag + fees ≤ maxU128 := by
  have hSub := blockSubsidy_bounded h ag
  calc ag + SubsidyV1.blockSubsidy h ag + fees
      ≤ SubsidyV1.MINEABLE_CAP + SubsidyV1.MINEABLE_CAP + maxU64 :=
        Nat.add_le_add (Nat.add_le_add hAg hSub) hFees
    -- F-AUDIT-11: see mineable_cap_in_u64 comment for native_decide rationale.
    _ ≤ maxU128 := by native_decide

end RubinFormal

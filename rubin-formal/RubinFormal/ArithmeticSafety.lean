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

/-- Structural ceiling on a block's `sum_fees`.

    A fee is `sum_in - sum_out`, so a block's aggregate fee cannot exceed the
    total input value its transactions spend. Every input carries a u64 value
    and consumes at least one weight unit, so the aggregate is bounded by
    `MAX_BLOCK_WEIGHT * maxU64`. That is `1254378597012249509820000000`, which
    needs 91 bits — far above u64.

    ASSUMPTION, not a theorem of this model: it is the consensus resource
    limit `MAX_BLOCK_WEIGHT` (clients/go/consensus/constants.go) restated as a
    numeric bound. This package models no block weight accounting, so the
    derivation is not machine-checked here; only the u128 containment below
    is. Consumers must read `sum_fees ≤ maxBlockSumFees` as an assumption
    discharged by the consensus implementation and its conformance vectors,
    not as a proved property. -/
def maxBlockSumFees : Nat := 68000000 * maxU64

/-- The block sum_fees ceiling genuinely exceeds u64, which is exactly why the
    previous `fees ≤ maxU64` premise was unsound. -/
theorem maxBlockSumFees_exceeds_u64 : maxU64 < maxBlockSumFees := by
  native_decide

/-- The coinbase value bound `blockSubsidy + sum_fees` fits in u128 for every
    `sum_fees` within the structural ceiling.

    This is the bound the implementations actually compute
    (`validateCoinbaseValueBound` / `validate_coinbase_value_bound`): the
    coinbase limit is `block_subsidy(h) + sum_fees` in checked u128. Fees do
    NOT accumulate into `already_generated`, which is subsidy-only, so they
    are deliberately not summed with it here. -/
theorem block_reward_bound_in_u128 (h ag fees : Nat)
    (hFees : fees ≤ maxBlockSumFees) :
    SubsidyV1.blockSubsidy h ag + fees ≤ maxU128 := by
  have hSub := blockSubsidy_bounded h ag
  calc SubsidyV1.blockSubsidy h ag + fees
      ≤ SubsidyV1.MINEABLE_CAP + maxBlockSumFees := Nat.add_le_add hSub hFees
    -- F-AUDIT-11: see mineable_cap_in_u64 comment for native_decide rationale.
    _ ≤ maxU128 := by native_decide

/-- Exact subsidy-only accumulation stays within u128 throughout the u64 height
    domain. `accumulatedSubsidy (h + 1)` includes subsidies at heights `1..h`;
    the height-zero term is zero by `blockSubsidy`. -/
theorem subsidy_accumulation_in_u128 (h : Nat) (hHeight : h ≤ maxU64) :
    SubsidyV1.accumulatedSubsidy (h + 1) ≤ h * SubsidyV1.MINEABLE_CAP ∧
    h * SubsidyV1.MINEABLE_CAP < 2 ^ 117 ∧
    2 ^ 117 < 2 ^ 128 ∧
    SubsidyV1.accumulatedSubsidy (h + 1) ≤ maxU128 := by
  have hAccumulated : ∀ n : Nat,
      SubsidyV1.accumulatedSubsidy (n + 1) ≤ n * SubsidyV1.MINEABLE_CAP := by
    intro n
    induction n with
    | zero =>
        simp [SubsidyV1.accumulatedSubsidy, SubsidyV1.blockSubsidy]
    | succ n ih =>
        rw [SubsidyV1.accumulatedSubsidy]
        calc
          SubsidyV1.accumulatedSubsidy (Nat.succ n) +
              SubsidyV1.blockSubsidy (Nat.succ n)
                (SubsidyV1.accumulatedSubsidy (Nat.succ n))
              ≤ n * SubsidyV1.MINEABLE_CAP + SubsidyV1.MINEABLE_CAP :=
                Nat.add_le_add ih (blockSubsidy_bounded _ _)
          _ = Nat.succ n * SubsidyV1.MINEABLE_CAP := by
                exact (Nat.succ_mul n SubsidyV1.MINEABLE_CAP).symm

  have hHeightPow : h < 2 ^ 64 := by
    have hMax : maxU64 < 2 ^ 64 := by
      unfold maxU64
      exact Nat.sub_lt (Nat.pow_pos (by omega)) (by omega)
    exact Nat.lt_of_le_of_lt hHeight hMax
  have hCapPow : SubsidyV1.MINEABLE_CAP < 2 ^ 53 := by
    unfold SubsidyV1.MINEABLE_CAP
    decide
  have hCapPos : 0 < SubsidyV1.MINEABLE_CAP := by
    unfold SubsidyV1.MINEABLE_CAP
    omega
  have hPow64Pos : 0 < 2 ^ 64 := Nat.pow_pos (by omega)
  have hProduct : h * SubsidyV1.MINEABLE_CAP < 2 ^ 117 := by
    calc
      h * SubsidyV1.MINEABLE_CAP < (2 ^ 64) * SubsidyV1.MINEABLE_CAP :=
        Nat.mul_lt_mul_of_pos_right hHeightPow hCapPos
      _ < (2 ^ 64) * (2 ^ 53) :=
        Nat.mul_lt_mul_of_pos_left hCapPow hPow64Pos
      _ = 2 ^ 117 := (Nat.pow_add 2 64 53).symm
  have hPow117Pos : 0 < 2 ^ 117 := Nat.pow_pos (by omega)
  have hPowBound : 2 ^ 117 < 2 ^ 128 := by
    calc
      2 ^ 117 = (2 ^ 117) * 1 := by simp
      _ < (2 ^ 117) * (2 ^ 11) :=
        Nat.mul_lt_mul_of_pos_left (by decide) hPow117Pos
      _ = 2 ^ 128 := (Nat.pow_add 2 117 11).symm
  have hAccumulatedBound := hAccumulated h
  have hU128 : SubsidyV1.accumulatedSubsidy (h + 1) ≤ maxU128 := by
    have hLt : SubsidyV1.accumulatedSubsidy (h + 1) < 2 ^ 128 :=
      Nat.lt_trans (Nat.lt_of_le_of_lt hAccumulatedBound hProduct) hPowBound
    unfold maxU128
    exact Nat.le_sub_one_of_lt hLt
  exact ⟨hAccumulatedBound, hProduct, hPowBound, hU128⟩

end RubinFormal

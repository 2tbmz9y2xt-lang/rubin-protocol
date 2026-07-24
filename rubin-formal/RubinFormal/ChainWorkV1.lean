import RubinFormal.PowV1
import Std.Tactic.Omega

namespace RubinFormal

namespace ChainWorkV1

def blockWork (targetNat : Nat) : Nat :=
  Nat.shiftLeft 1 256 / targetNat

theorem blockWork_pos (targetNat : Nat)
    (hTargetPos : 0 < targetNat)
    (hTargetLe : targetNat ≤ PowV1.powLimit) :
    0 < blockWork targetNat := by
  unfold blockWork
  apply Nat.zero_lt_of_ne_zero
  intro hZero
  have hDecomp := Nat.div_add_mod (Nat.shiftLeft 1 256) targetNat
  rw [hZero, Nat.mul_zero, Nat.zero_add] at hDecomp
  have hLt : Nat.shiftLeft 1 256 < targetNat := by
    rw [← hDecomp]
    exact Nat.mod_lt _ hTargetPos
  have hPow : PowV1.powLimit < Nat.shiftLeft 1 256 := by
    native_decide
  have hTargetLt : targetNat < Nat.shiftLeft 1 256 := Nat.lt_of_le_of_lt hTargetLe hPow
  exact (Nat.not_lt_of_ge (Nat.le_of_lt hTargetLt)) hLt

def chainWork : List Nat → Nat
  | [] => 0
  | targetNat :: rest => blockWork targetNat + chainWork rest

theorem chainWork_nil : chainWork [] = 0 := by
  rfl

theorem chainWork_append_one (targets : List Nat) (targetNat : Nat) :
    chainWork (targets ++ [targetNat]) = chainWork targets + blockWork targetNat := by
  induction targets with
  | nil =>
      simp [chainWork]
  | cons head tail ih =>
      simp [chainWork, ih, Nat.add_assoc]

theorem chainWork_strict_mono (targets : List Nat) (targetNat : Nat)
    (hBlockPos : 0 < blockWork targetNat) :
    chainWork targets < chainWork (targets ++ [targetNat]) := by
  rw [chainWork_append_one]
  omega

def heavierChain (lhs rhs : List Nat) : Bool :=
  decide (chainWork lhs > chainWork rhs)

theorem heavierChain_asymmetric (lhs rhs : List Nat) :
    heavierChain lhs rhs = true → heavierChain rhs lhs = false := by
  intro hForward
  have hGt : chainWork lhs > chainWork rhs := decide_eq_true_eq.mp hForward
  have hNotReverse : ¬ chainWork rhs > chainWork lhs := by
    intro hLt
    exact Nat.lt_asymm hGt hLt
  simp [heavierChain, hNotReverse]

theorem heavierChain_irreflexive (targets : List Nat) :
    heavierChain targets targets = false := by
  have hNotSelf : ¬ chainWork targets > chainWork targets := by
    exact Nat.lt_irrefl _
  simp [heavierChain, hNotSelf]

theorem heavierChain_total_of_ne (lhs rhs : List Nat)
    (hNe : chainWork lhs ≠ chainWork rhs) :
    heavierChain lhs rhs = true ∨ heavierChain rhs lhs = true := by
  unfold heavierChain
  by_cases hGt : chainWork lhs > chainWork rhs
  · left
    exact decide_eq_true_eq.mpr hGt
  · right
    have hLe : chainWork lhs ≤ chainWork rhs := Nat.le_of_not_gt hGt
    have hLt : chainWork lhs < chainWork rhs := Nat.lt_of_le_of_ne hLe hNe
    exact decide_eq_true_eq.mpr hLt

end ChainWorkV1

end RubinFormal

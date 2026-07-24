import RubinFormal.ChainWorkV1
import RubinFormal.PowV1

namespace RubinFormal

namespace ForkChoiceV1

open ChainWorkV1

def validTargetNat (targetNat : Nat) : Bool :=
  targetNat != 0 && targetNat ≤ PowV1.powLimit

def bytesLT : List UInt8 → List UInt8 → Bool
  | [], [] => false
  | [], _ => true
  | _, [] => false
  | x :: xs, y :: ys =>
      if x < y then true else if x > y then false else bytesLT xs ys

theorem validTargetNat_true_of_bounds (targetNat : Nat)
    (hPos : 0 < targetNat)
    (hLe : targetNat ≤ PowV1.powLimit) :
    validTargetNat targetNat = true := by
  simp [validTargetNat, Nat.ne_of_gt hPos, hLe]

theorem zeroTarget_rejected : validTargetNat 0 = false := by
  simp [validTargetNat]

theorem overLimitTarget_rejected (targetNat : Nat)
    (h : PowV1.powLimit < targetNat) :
    validTargetNat targetNat = false := by
  simp [validTargetNat, Nat.not_le.mpr h]

theorem emptyChain_loses (targetNat : Nat)
    (hPos : 0 < targetNat)
    (hLe : targetNat ≤ PowV1.powLimit) :
    chainWork [] < chainWork [targetNat] := by
  have hBlockPos : 0 < blockWork targetNat := blockWork_pos targetNat hPos hLe
  simpa using chainWork_strict_mono [] targetNat hBlockPos

theorem heavierChain_wins (lhs rhs : List Nat)
    (h : chainWork lhs > chainWork rhs) :
    heavierChain lhs rhs = true := by
  exact decide_eq_true_eq.mpr h

end ForkChoiceV1

end RubinFormal

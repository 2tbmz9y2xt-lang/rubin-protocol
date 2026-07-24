import RubinFormal.Types

namespace RubinFormal

private theorem uint8_beq_eq_decide (x y : UInt8) :
    BEq.beq x y = decide (x = y) := by
  cases x with
  | mk xv =>
    cases y with
    | mk yv =>
      simp [BEq.beq]

theorem bytes_beq_refl (a : Bytes) : (a == a) = true := by
  cases a with
  | mk ad =>
      show Array.isEqv ad ad BEq.beq = true
      have h :
          (fun (x y : UInt8) => @BEq.beq UInt8 _ x y) =
          (fun x y => decide (x = y)) := by
        funext x y
        exact uint8_beq_eq_decide x y
      have hrw :
          Array.isEqv ad ad BEq.beq =
          Array.isEqv ad ad (fun x y => decide (x = y)) := by
        congr 1
      rw [hrw]
      exact Array.isEqv_self ad

theorem bytes_bne_self_false (a : Bytes) : (a != a) = false := by
  show (!(a == a)) = false
  rw [bytes_beq_refl]
  rfl

theorem bytes_beq_true_eq
    (a b : Bytes)
    (h : (a == b) = true) :
    a = b := by
  cases a with
  | mk ad =>
      cases b with
      | mk bd =>
          change Array.isEqv ad bd BEq.beq = true at h
          have hData : ad = bd := by
            apply Array.eq_of_isEqv
            simpa using h
          cases hData
          rfl

theorem bytes_bne_false_eq
    (a b : Bytes)
    (h : (a != b) = false) :
    a = b := by
  change (!(a == b)) = false at h
  cases hEq : (a == b) with
  | false =>
      simp [hEq] at h
  | true =>
      exact bytes_beq_true_eq a b hEq

theorem bytes_bne_true_of_ne
    (a b : Bytes)
    (h : a ≠ b) :
    (a != b) = true := by
  cases hCmp : (a != b) with
  | true => rfl
  | false =>
      exact False.elim (h (bytes_bne_false_eq a b hCmp))

theorem bne_false_eq
    (a b : Bytes)
    (h : (a != b) = false) :
    a = b :=
  bytes_bne_false_eq a b h

end RubinFormal

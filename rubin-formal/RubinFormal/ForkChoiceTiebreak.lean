import RubinFormal.ForkChoiceV1

/-!
# Fork-Choice Tie-Break Determinism (§23)

Proves `bytesLT` is irreflexive and total on same-length lists,
giving deterministic tie-break for equal-chainwork fork choice.
-/

namespace RubinFormal

open ForkChoiceV1

private theorem uint8_lt_irrefl (x : UInt8) : ¬ (x < x) :=
  fun h => Nat.lt_irrefl x.val.val h

private theorem uint8_eq_of_not_lt_not_gt {x y : UInt8}
    (h1 : ¬ x < y) (h2 : ¬ y < x) : x = y := by
  have h1' : ¬ x.val.val < y.val.val := h1
  have h2' : ¬ y.val.val < x.val.val := h2
  have hEq : x.val.val = y.val.val := by omega
  rcases x with ⟨⟨xn, xh⟩⟩
  rcases y with ⟨⟨yn, yh⟩⟩
  simp only at hEq
  subst hEq
  rfl

theorem bytesLT_irrefl : ∀ (xs : List UInt8), bytesLT xs xs = false
  | [] => rfl
  | x :: xs => by
    unfold bytesLT
    have h1 := uint8_lt_irrefl x
    simp [show ¬ (x < x) from h1, show ¬ (x > x) from h1]
    exact bytesLT_irrefl xs

theorem bytesLT_total_of_ne : ∀ (xs ys : List UInt8),
    xs.length = ys.length → xs ≠ ys →
    bytesLT xs ys = true ∨ bytesLT ys xs = true
  | [], [], _, hNeq => absurd rfl hNeq
  | x :: xs, y :: ys, hLen, hNeq => by
    unfold bytesLT
    by_cases hLt : x < y
    · simp [hLt]
    · by_cases hGt : (y < x)
      · right; simp [hGt]
      · have hEq := uint8_eq_of_not_lt_not_gt hLt hGt
        subst hEq
        have h1 := uint8_lt_irrefl x
        simp [show ¬ (x < x) from h1, show ¬ (x > x) from h1]
        exact bytesLT_total_of_ne xs ys (by simpa using hLen) (fun h => hNeq (congr_arg (x :: ·) h))
  | [], _ :: _, hLen, _ => by simp at hLen
  | _ :: _, [], hLen, _ => by simp at hLen

/-- Fork-choice tie-break is deterministic for 32-byte hashes. -/
theorem fork_choice_tiebreak_deterministic
    (hashA hashB : List UInt8)
    (hLenA : hashA.length = 32)
    (hLenB : hashB.length = 32)
    (hNeq : hashA ≠ hashB) :
    bytesLT hashA hashB = true ∨ bytesLT hashB hashA = true :=
  bytesLT_total_of_ne hashA hashB (hLenA ▸ hLenB ▸ rfl) hNeq

end RubinFormal

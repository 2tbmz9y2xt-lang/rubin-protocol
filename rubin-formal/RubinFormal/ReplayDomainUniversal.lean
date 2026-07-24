import RubinFormal.BlockBasicCheckV1
import RubinFormal.CriticalInvariants

namespace RubinFormal

open BlockBasicCheckV1

private theorem contains_true_of_mem {x : Nat} {xs : List Nat} (h : x ∈ xs) :
    xs.contains x = true := by
  induction xs with
  | nil =>
      cases h
  | cons y ys ih =>
      simp at h ⊢
      cases h with
      | inl hEq =>
          subst hEq
          simp
      | inr hMem =>
          exact Or.inr (ih hMem)

private theorem contains_eq_false_iff_not_mem {x : Nat} {xs : List Nat} :
    xs.contains x = false ↔ x ∉ xs := by
  constructor
  · intro hFalse
    intro hMem
    have hTrue : xs.contains x = true := contains_true_of_mem hMem
    rw [hFalse] at hTrue
    cases hTrue
  · intro hNotMem
    induction xs with
    | nil =>
        simp
    | cons y ys ih =>
        have hxy : x ≠ y := List.ne_of_not_mem_cons hNotMem
        have htail : x ∉ ys := fun hmem => hNotMem (List.mem_cons_of_mem _ hmem)
        simp [hxy, ih htail]

private theorem nodup_append_singleton_iff (seen : List Nat) (x : Nat) :
    List.Nodup (seen ++ [x]) ↔ List.Nodup seen ∧ x ∉ seen := by
  constructor
  · intro h
    have hPair : (seen ++ [x]).Pairwise (fun a b => a ≠ b) := by
      simpa [List.Nodup] using h
    rw [List.pairwise_append] at hPair
    refine ⟨hPair.1, ?_⟩
    intro hx
    exact (hPair.2.2 x hx x (by simp)) rfl
  · rintro ⟨hSeen, hx⟩
    unfold List.Nodup at *
    rw [List.pairwise_append]
    refine ⟨hSeen, by simp, ?_⟩
    intro a ha b hb
    have hb' : b = x := by simpa using hb
    subst hb'
    intro hEq
    exact hx (hEq ▸ ha)

private theorem anyDuplicateAcc_true_of_not_nodup_append
    (rest seen : List Nat)
    (hSeen : List.Nodup seen)
    (hDup : ¬ List.Nodup (seen ++ rest)) :
    anyDuplicateAcc rest seen = true := by
  induction rest generalizing seen with
  | nil =>
      exact False.elim (hDup (by simpa using hSeen))
  | cons x xs ih =>
      by_cases hx : x ∈ seen
      · have hcontains : seen.contains x = true := contains_true_of_mem hx
        simp [anyDuplicateAcc, hcontains]
      · have hSeen' : List.Nodup (seen ++ [x]) :=
          (nodup_append_singleton_iff seen x).2 ⟨hSeen, hx⟩
        have hDup' : ¬ List.Nodup ((seen ++ [x]) ++ xs) := by
          intro h
          exact hDup (by simpa [List.append_assoc] using h)
        have hcontains : seen.contains x = false :=
          (contains_eq_false_iff_not_mem).2 hx
        simp [anyDuplicateAcc, hcontains, ih (seen ++ [x]) hSeen' hDup']

private theorem anyDuplicateAcc_false_of_nodup_append
    (rest seen : List Nat)
    (hSeen : List.Nodup seen)
    (hNoDup : List.Nodup (seen ++ rest)) :
    anyDuplicateAcc rest seen = false := by
  induction rest generalizing seen with
  | nil =>
      simp [anyDuplicateAcc]
  | cons x xs ih =>
      have hNoDupPair : (seen ++ x :: xs).Pairwise (fun a b => a ≠ b) := by
        simpa [List.Nodup] using hNoDup
      rw [List.pairwise_append] at hNoDupPair
      have hx : x ∉ seen := by
        intro hxMem
        exact (hNoDupPair.2.2 x hxMem x (by simp)) rfl
      have hSeen' : List.Nodup (seen ++ [x]) :=
        (nodup_append_singleton_iff seen x).2 ⟨hSeen, hx⟩
      have hTailPair : (x :: xs).Pairwise (fun a b => a ≠ b) := hNoDupPair.2.1
      have hXsPair : xs.Pairwise (fun a b => a ≠ b) := (List.pairwise_cons.mp hTailPair).2
      have hNoDup' : List.Nodup ((seen ++ [x]) ++ xs) := by
        unfold List.Nodup
        rw [List.pairwise_append]
        refine ⟨?_, ?_, ?_⟩
        · simpa [List.Nodup] using hSeen'
        · exact hXsPair
        · intro a ha b hb
          rcases List.mem_append.mp ha with haSeen | haLast
          · exact (hNoDupPair.2.2 a haSeen b (by simp [hb]))
          · have haEq : a = x := by simpa using haLast
            subst haEq
            exact (List.pairwise_cons.mp hTailPair).1 b hb
      have hcontains : seen.contains x = false :=
        (contains_eq_false_iff_not_mem).2 hx
      simp [anyDuplicateAcc, hcontains, ih (seen ++ [x]) hSeen' hNoDup']

/-- Exact bridge from the live duplicate-finder to the abstract replay-domain invariant. -/
theorem anyDuplicate_eq_true_iff_not_nonceReplayFree (xs : List Nat) :
    anyDuplicate xs = true ↔ ¬ nonceReplayFree xs := by
  constructor
  · intro hTrue
    intro hReplay
    have hNoDup : List.Nodup ([] ++ xs) := by
      simpa [nonceReplayFree] using hReplay
    have hFalse : anyDuplicateAcc xs [] = false :=
      anyDuplicateAcc_false_of_nodup_append xs [] (by
        unfold List.Nodup
        exact List.Pairwise.nil) hNoDup
    have hFalse' : anyDuplicate xs = false := by simpa [anyDuplicate] using hFalse
    rw [hFalse'] at hTrue
    cases hTrue
  · intro hReplay
    have hDup : ¬ List.Nodup ([] ++ xs) := by
      simpa [nonceReplayFree] using hReplay
    exact anyDuplicateAcc_true_of_not_nodup_append xs [] (by
      unfold List.Nodup
      exact List.Pairwise.nil) hDup

/-- Companion exactness lemma for the accepting branch of the live duplicate-finder. -/
theorem anyDuplicate_eq_false_iff_nonceReplayFree (xs : List Nat) :
    anyDuplicate xs = false ↔ nonceReplayFree xs := by
  constructor
  · intro hFalse
    by_contra hReplay
    have hTrue : anyDuplicate xs = true :=
      anyDuplicate_eq_true_iff_not_nonceReplayFree xs |>.2 hReplay
    rw [hFalse] at hTrue
    cases hTrue
  · intro hReplay
    have hNoDup : List.Nodup ([] ++ xs) := by
      simpa [nonceReplayFree] using hReplay
    exact anyDuplicateAcc_false_of_nodup_append xs [] (by
      unfold List.Nodup
      exact List.Pairwise.nil) hNoDup

private theorem nonceReplayCheck_from_collected_nonces (nonces : List Nat) :
    (do
      let nonces ← Except.ok nonces
      if anyDuplicate nonces = true then
        throw "TX_ERR_NONCE_REPLAY"
      else
        pure ()) =
    (if anyDuplicate nonces = true then
      Except.error "TX_ERR_NONCE_REPLAY"
    else
      Except.ok ()) := by
  rfl

/-- Universal live reject theorem: once nonce extraction succeeds and the
    extracted nonce list is not replay-free, the executable `nonceReplayCheck`
    rejects with `TX_ERR_NONCE_REPLAY`. -/
theorem nonceReplayCheck_rejects_duplicate_nonce_list
    (txs : List Bytes) (nonces : List Nat)
    (hCollect : collectNonces txs = .ok nonces)
    (hReplay : ¬ nonceReplayFree nonces) :
    nonceReplayCheck txs = .error "TX_ERR_NONCE_REPLAY" := by
  have hDup : anyDuplicate nonces = true :=
    (anyDuplicate_eq_true_iff_not_nonceReplayFree nonces).2 hReplay
  unfold nonceReplayCheck
  rw [hCollect]
  change (if anyDuplicate nonces = true then
    Except.error "TX_ERR_NONCE_REPLAY"
  else
    Except.ok ()) = Except.error "TX_ERR_NONCE_REPLAY"
  simp [hDup]

/-- Universal live accept theorem: once nonce extraction succeeds and the
    extracted nonce list is replay-free, the executable `nonceReplayCheck`
    accepts. -/
theorem nonceReplayCheck_accepts_replay_free_nonce_list
    (txs : List Bytes) (nonces : List Nat)
    (hCollect : collectNonces txs = .ok nonces)
    (hReplay : nonceReplayFree nonces) :
    nonceReplayCheck txs = .ok () := by
  have hNoDup : anyDuplicate nonces = false :=
    (anyDuplicate_eq_false_iff_nonceReplayFree nonces).2 hReplay
  unfold nonceReplayCheck
  rw [hCollect]
  change (if anyDuplicate nonces = true then
    Except.error "TX_ERR_NONCE_REPLAY"
  else
    Except.ok ()) = Except.ok ()
  simp [hNoDup]

end RubinFormal

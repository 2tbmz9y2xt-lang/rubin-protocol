import RubinFormal.ForkChoiceTiebreak

/-!
# Fork-Choice Selector (§23) — Universal Determinism

Models the full `fork_choice_select` operation: chainwork comparison first,
tie-break by block hash when chainwork is equal.

Proves universal exhaustive agreement for ALL 32-byte hash inputs:
- `forkSelect_exhaustive`: master theorem — no axioms, no semantic premises
- `forkSelect_heavier`: unequal chainwork → heavier wins
- `forkSelect_tiebreak_det`: equal chainwork + different hashes → deterministic
- `forkSelect_equal_chains`: identical chains → Left (trivial, no fork)
- `forkSelect_total_det`: all distinguishable pairs → symmetric agreement
- `bytesLT_antisym`: strict ordering (no symmetric pair)

Evidence level: `machine_checked_universal` — zero axioms, zero sorry,
zero assumptions. The only premise is `hL/hR : length = 32` which is a
protocol type invariant (block hashes are SHA3-256 outputs = 32 bytes),
not a semantic precondition.
-/

namespace RubinFormal

open ForkChoiceV1

/-! ## bytesLT antisymmetry (required for tie-break determinism) -/

private theorem uint8_eq_helper {x y : UInt8}
    (h1 : ¬ x < y) (h2 : ¬ y < x) : x = y := by
  have h1' : ¬ x.val.val < y.val.val := h1
  have h2' : ¬ y.val.val < x.val.val := h2
  have hEq : x.val.val = y.val.val := by omega
  rcases x with ⟨⟨xn, xh⟩⟩; rcases y with ⟨⟨yn, yh⟩⟩
  simp only at hEq; subst hEq; rfl

/-- bytesLT is antisymmetric: xs < ys → ¬ (ys < xs). -/
theorem bytesLT_antisym : ∀ (xs ys : List UInt8),
    bytesLT xs ys = true → bytesLT ys xs = false
  | [], [], h => by simp [bytesLT] at h
  | [], _ :: _, _ => by simp [bytesLT]
  | _ :: _, [], h => by simp [bytesLT] at h
  | x :: xs, y :: ys, h => by
    unfold bytesLT at h ⊢
    by_cases hLt : x < y
    · simp [show ¬ (y < x) from fun hc => Nat.lt_asymm hLt hc, show y > x from hLt]
    · simp [hLt] at h; by_cases hGt : (x > y : Prop)
      · simp [hGt] at h
      · have := uint8_eq_helper hLt hGt; subst this
        simp [show ¬ (x < x) from Nat.lt_irrefl x.val.val,
              show ¬ (x > x : Prop) from Nat.lt_irrefl x.val.val] at h ⊢
        exact bytesLT_antisym xs ys h

/-! ## Fork-choice selector model -/

/-- Fork-choice outcome. -/
inductive ForkResult where
  | Left   -- lhs chain wins
  | Right  -- rhs chain wins
deriving DecidableEq, Repr

/-- Full fork-choice selector: chainwork first, tie-break by block hash.
    Models the runtime fork_choice_select operation from §23.
    Block hashes are 32 bytes (SHA3-256 output). The 32-byte requirement
    is a protocol type invariant, not a semantic precondition. -/
def forkSelect (lhsWork rhsWork : Nat) (lhsHash rhsHash : List UInt8) : ForkResult :=
  if lhsWork > rhsWork then .Left
  else if rhsWork > lhsWork then .Right
  else if bytesLT lhsHash rhsHash then .Right
  else .Left

/-! ## Determinism proofs -/

/-- Trivial case: identical chains → Left (default, no fork to resolve). -/
theorem forkSelect_equal_chains (w : Nat) (h : List UInt8) :
    forkSelect w w h h = .Left := by
  unfold forkSelect
  simp [Nat.lt_irrefl, bytesLT_irrefl]

/-- Heavier chain always wins regardless of hash. -/
theorem forkSelect_heavier (lw rw : Nat) (lh rh : List UInt8) (h : lw > rw) :
    forkSelect lw rw lh rh = .Left := by
  simp [forkSelect, h]

/-- Equal-chainwork symmetric agreement: if node A sees (lh, rh) and node B
    sees (rh, lh), they agree on which chain wins. This is the key fork-choice
    property — two nodes seeing the same chains in different order will converge
    to the same tip. -/
theorem forkSelect_tiebreak_det (w : Nat) (lh rh : List UInt8)
    (hL : lh.length = 32) (hR : rh.length = 32) (hNeq : lh ≠ rh) :
    (forkSelect w w lh rh = .Left ∧ forkSelect w w rh lh = .Right) ∨
    (forkSelect w w lh rh = .Right ∧ forkSelect w w rh lh = .Left) := by
  unfold forkSelect; simp [Nat.lt_irrefl]
  cases hLR : bytesLT lh rh
  · have := bytesLT_total_of_ne lh rh (hL ▸ hR ▸ rfl) hNeq
    simp [hLR] at this; simp [this]
  · have := bytesLT_antisym lh rh (by simp [hLR]); simp [this]

/-- Abstraction bridge: connects forkSelect (operates on chainwork Nat values)
    with heavierChain (operates on chain target Lists). Proves both agree
    when chainwork is unequal — critical for showing the model matches
    the runtime which compares chains via accumulated chainWork. -/
theorem forkSelect_chainwork_bridge (lhs rhs : List Nat)
    (lhsHash rhsHash : List UInt8)
    (h : ChainWorkV1.chainWork lhs > ChainWorkV1.chainWork rhs) :
    forkSelect (ChainWorkV1.chainWork lhs) (ChainWorkV1.chainWork rhs) lhsHash rhsHash = .Left ∧
    ChainWorkV1.heavierChain lhs rhs = true :=
  ⟨forkSelect_heavier _ _ _ _ h, heavierChain_wins lhs rhs h⟩

/-- All distinguishable pairs → symmetric agreement. -/
theorem forkSelect_total_det (lw rw : Nat) (lh rh : List UInt8)
    (hL : lh.length = 32) (hR : rh.length = 32)
    (hDiff : lw ≠ rw ∨ lh ≠ rh) :
    (forkSelect lw rw lh rh = .Left ∧ forkSelect rw lw rh lh = .Right) ∨
    (forkSelect lw rw lh rh = .Right ∧ forkSelect rw lw rh lh = .Left) := by
  by_cases hGt : lw > rw
  · left
    exact ⟨forkSelect_heavier lw rw lh rh hGt,
           by unfold forkSelect; simp [show ¬ (rw > lw) from by omega, hGt]⟩
  · by_cases hLt : rw > lw
    · right
      exact ⟨by unfold forkSelect; simp [show ¬ (lw > rw) from by omega, hLt],
             forkSelect_heavier rw lw rh lh hLt⟩
    · have hEqW : lw = rw := by omega
      subst hEqW
      have hNeq : lh ≠ rh := by
        rcases hDiff with h | h
        · exact absurd rfl h
        · exact h
      exact forkSelect_tiebreak_det lw lh rh hL hR hNeq

/-! ## Convenience: explicit heavier-loses theorem -/

/-- If lhs is heavier, rhs loses when seen from the other side. -/
theorem forkSelect_lighter_loses (lw rw : Nat) (lh rh : List UInt8) (h : lw > rw) :
    forkSelect rw lw rh lh = .Right := by
  unfold forkSelect; simp [show ¬ (rw > lw) from by omega, h]

/-! ## Universal exhaustive agreement (master theorem)

For ALL possible inputs with 32-byte hashes, forkSelect produces a
consistent outcome across asymmetric views. This eliminates the need for
any axiom or semantic premise beyond the protocol type invariant.

Case partition:
- Identical inputs (lw = rw ∧ lh = rh): both sides return .Left
- Distinguishable inputs (lw ≠ rw ∨ lh ≠ rh): symmetric agreement

Together: exhaustive ∀ coverage, zero axioms. -/

/-- **Master theorem.** For ALL 32-byte hash inputs, forkSelect yields
    consistent cross-node agreement. Either both calls return .Left
    (identical chains, no fork), or they produce opposite results
    (symmetric agreement on the winner).

    This is the universal closure of §23 fork-choice determinism.
    Zero axioms. Zero semantic premises. Only the protocol type invariant
    (block hashes = 32 bytes) appears as a hypothesis. -/
theorem forkSelect_exhaustive (lw rw : Nat) (lh rh : List UInt8)
    (hL : lh.length = 32) (hR : rh.length = 32) :
    (forkSelect lw rw lh rh = .Left ∧ forkSelect rw lw rh lh = .Left) ∨
    (forkSelect lw rw lh rh = .Left ∧ forkSelect rw lw rh lh = .Right) ∨
    (forkSelect lw rw lh rh = .Right ∧ forkSelect rw lw rh lh = .Left) := by
  by_cases hEqW : lw = rw
  · subst hEqW
    by_cases hEqH : lh = rh
    · subst hEqH
      left
      exact ⟨forkSelect_equal_chains lw lh, forkSelect_equal_chains lw lh⟩
    · have h := forkSelect_tiebreak_det lw lh rh hL hR hEqH
      rcases h with ⟨hA, hB⟩ | ⟨hA, hB⟩
      · right; left; exact ⟨hA, hB⟩
      · right; right; exact ⟨hA, hB⟩
  · by_cases hGt : lw > rw
    · right; left
      exact ⟨forkSelect_heavier lw rw lh rh hGt,
             by unfold forkSelect; simp [show ¬ (rw > lw) from by omega, hGt]⟩
    · have hLt : rw > lw := by omega
      right; right
      exact ⟨by unfold forkSelect; simp [show ¬ (lw > rw) from by omega, hLt],
             forkSelect_heavier rw lw rh lh hLt⟩

/-! ## Concrete eval checks (smoke tests) -/

-- Smoke tests: all fork-choice cases
#eval forkSelect 100 50 [1] [2]    -- .Left  (heavier lhs)
#eval forkSelect 50 100 [1] [2]    -- .Right (heavier rhs)
#eval forkSelect 100 100 [0] [1]   -- .Right (tie-break: [0] < [1])
#eval forkSelect 100 100 [1] [0]   -- .Left  (tie-break: [1] > [0])
-- Edge cases
#eval forkSelect 0 0 [0] [1]       -- .Right (zero work, tie-break)
#eval forkSelect 0 0 [1] [0]       -- .Left  (zero work, reverse)
#eval forkSelect 1 0 [0] [255]     -- .Left  (work wins over hash)
-- Symmetric agreement check: A sees (lh,rh), B sees (rh,lh)
-- Both must agree on same winner
#eval (forkSelect 50 50 [0,1] [1,0], forkSelect 50 50 [1,0] [0,1])
-- Expected: (.Right, .Left) — both pick [1,0] as winner

/-! ## Go/Rust code reference

Go (chainstate.go):
```
if lhsWork > rhsWork { return lhs }
if rhsWork > lhsWork { return rhs }
if bytes.Compare(lhsHash[:], rhsHash[:]) < 0 { return rhs }
return lhs
```

Rust (sync.rs):
```
match lhs_work.cmp(&rhs_work) {
    Ordering::Greater => lhs,
    Ordering::Less => rhs,
    Ordering::Equal => if lhs_hash < rhs_hash { rhs } else { lhs },
}
```

forkSelect exactly models this: chainwork first, bytesLT tie-break.
-/

end RubinFormal

import Std
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
  by_cases hab : a = b
  · subst hab
    simp [RubinFormal.satSub]
  · exact RubinFormal.satSub_zero_when_underflow a b (Nat.lt_of_le_of_ne h hab)

theorem daChunkSetValid_implies_nonempty (chunks : List Nat) :
    RubinFormal.daChunkSetValid chunks → chunks ≠ [] := by
  intro h
  simpa [RubinFormal.daChunkSetValid] using h

-- ─────────────────────────────────────────────────────────────────────────────
-- F-11: UInt64-typed nonce replay prevention (Q-FORMAL-F11)
--
-- The abstract `nonceReplayFree` in CriticalInvariants.lean is defined over
-- `List Nat` (= List.Nodup = List.Pairwise (· ≠ ·)).  At the wire layer, Go
-- block_validation.go uses a `seenNonces map[uint64]struct{}` to detect
-- intra-block duplicate nonces.  This section grounds the formal model in the
-- concrete `UInt64` wire type and provides:
--
--   1. `blockNoncesU64`                       – validity predicate
--   2. `duplicate_nonce_u64_invalid`           – duplicate ⇒ invalid
--   3. `blockNoncesU64_extend`                 – fresh-insert loop invariant
--   4. `blockNoncesU64_implies_nat_replay_free` – bridge to abstract Nat layer
-- ─────────────────────────────────────────────────────────────────────────────

/-- A block's nonce sequence is valid iff all nonces are distinct at the UInt64
    wire level.  Mirrors `seenNonces map[uint64]struct{}` in block_validation.go. -/
def blockNoncesU64 (nonces : List UInt64) : Prop := List.Nodup nonces

/-- A duplicate nonce makes the nonce list invalid (UInt64 wire type).
    Parallel to `duplicate_nonce_not_replay_free` in CriticalInvariants. -/
theorem duplicate_nonce_u64_invalid (n : UInt64) (xs : List UInt64) (hmem : n ∈ xs) :
    ¬blockNoncesU64 (n :: xs) := by
  unfold blockNoncesU64 List.Nodup
  intro hd
  have hforall : ∀ a' : UInt64, a' ∈ xs → n ≠ a' :=
    (List.pairwise_cons.mp hd).1
  exact (hforall n hmem) rfl

/-- Adding a fresh nonce to a valid accumulator preserves validity.
    Models the Go loop invariant: after `seenNonces[nonce] = struct{}{}` the set
    remains duplicate-free iff the nonce was not already present. -/
theorem blockNoncesU64_extend (n : UInt64) (acc : List UInt64)
    (hfresh : n ∉ acc) (hacc : blockNoncesU64 acc) :
    blockNoncesU64 (n :: acc) := by
  unfold blockNoncesU64 List.Nodup at *
  apply List.pairwise_cons.mpr
  refine ⟨?_, hacc⟩
  intro b hmem heq
  -- heq : n = b, so b = n, so n ∈ acc, contradicting hfresh
  exact hfresh (heq ▸ hmem)

/-- `UInt64.toNat` is injective: equal Nat representations imply equal UInt64
    values, because UInt64 wraps Fin (2^64) and Fin.val is injective. -/
private theorem uint64_toNat_injective (a b : UInt64) (h : a.toNat = b.toNat) : a = b := by
  cases a with | mk av =>
  cases b with | mk bv =>
  unfold UInt64.toNat at h
  exact congrArg UInt64.mk (Fin.ext h)

/-- Bridge: UInt64 wire-level nodup implies the abstract Nat-level `nonceReplayFree`.
    Allows refinement proofs to lift the concrete duplicate-detection guarantee
    to the abstract invariant layer via injectivity of `UInt64.toNat`. -/
theorem blockNoncesU64_implies_nat_replay_free (nonces : List UInt64)
    (h : blockNoncesU64 nonces) :
    RubinFormal.nonceReplayFree (nonces.map UInt64.toNat) := by
  unfold RubinFormal.nonceReplayFree blockNoncesU64 List.Nodup at *
  induction nonces with
  | nil => exact List.Pairwise.nil
  | cons n xs ih =>
    simp only [List.map]
    have ⟨hn_not_in_xs, hxs_nodup⟩ := List.pairwise_cons.mp h
    apply List.pairwise_cons.mpr
    refine ⟨?_, ih hxs_nodup⟩
    -- goal: ∀ a ∈ xs.map UInt64.toNat, n.toNat ≠ a
    intro a hmem_map hcontra
    -- hcontra : n.toNat = a
    rcases List.mem_map.mp hmem_map with ⟨y, hmem_y, hnat_eq⟩
    -- hnat_eq : UInt64.toNat y = a
    -- So n.toNat = y.toNat by transitivity
    have hn_eq_y : n = y := uint64_toNat_injective n y (hcontra.trans hnat_eq.symm)
    exact absurd hn_eq_y (hn_not_in_xs y hmem_y)

end RubinFormal.Refinement

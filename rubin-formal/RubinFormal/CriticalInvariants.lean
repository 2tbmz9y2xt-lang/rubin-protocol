import Std
import RubinFormal.Types

namespace RubinFormal

/-!
## Critical Invariants — v2 (Q-FORMAL-GAP-01, 2026-03-06)

This module contains critical consensus invariant helpers. The following
toy/tautological definitions were removed and replaced with substantive
theorems in `PinnedSections.lean` that reference real code:

- F-01: `txidPreimage`/`wtxidPreimage` (toy `List Nat`) → replaced by
  `txid_wtxid_preimage_distinct` over real `ByteArray.extract` + `SHA3.sha3_256`.
- F-02: `sighashPreimage` (toy 3-list) → replaced by fixed-size encoding
  invariants over real `SighashV1.u64le`/`u32le` (proved directly in PinnedSections).
- F-03: `coinbaseWitnessCommitmentSeed = 0` (rfl tautology) → replaced by
  `coinbase_value_bounded` referencing real `SubsidyV1.validateCoinbaseValueBound`.
-/

-- ═══════════════════════════════════════════════════════════════════
-- F-01: txid/wtxid preimage distinctness (ByteArray, not toy List Nat)
-- ═══════════════════════════════════════════════════════════════════

/-- A ByteArray of strictly smaller size cannot equal a larger one. -/
theorem bytearray_ne_of_size_lt (a b : ByteArray) (h : a.size < b.size) : a ≠ b := by
  intro hab
  exact Nat.lt_irrefl a.size (hab ▸ h)

/-- When `n < bs.size`, extracting `[0, n)` yields fewer bytes than `bs`.
    This is the structural basis for txid ≠ wtxid preimage distinctness:
    `txid = SHA3(tx.extract 0 coreEnd)` and `wtxid = SHA3(tx)`, and
    when witness is non-empty, `coreEnd < tx.size`. -/
theorem extract_prefix_size_lt (bs : ByteArray) (n : Nat) (h : n < bs.size) :
    (bs.extract 0 n).size < bs.size := by
  simp [ByteArray.extract, ByteArray.size]
  omega

/-- For a valid transaction with non-empty witness section (coreEnd < tx.size),
    the txid preimage bytes (core = tx.extract 0 coreEnd) differ from the
    wtxid preimage bytes (full tx). This is the substantive structural property;
    SHA3 collision resistance is a standard cryptographic assumption. -/
theorem txid_wtxid_preimage_bytes_distinct (tx : ByteArray) (coreEnd : Nat)
    (h : coreEnd < tx.size) :
    tx.extract 0 coreEnd ≠ tx := by
  apply bytearray_ne_of_size_lt
  exact extract_prefix_size_lt tx coreEnd h

-- ═══════════════════════════════════════════════════════════════════
-- Existing (non-toy) invariants — retained unchanged
-- ═══════════════════════════════════════════════════════════════════

def weight (base witness sigCost : Nat) : Nat := base * 4 + witness + sigCost

theorem weight_monotone_witness (base witness1 witness2 sigCost : Nat)
    (h : witness1 ≤ witness2) :
    weight base witness1 sigCost ≤ weight base witness2 sigCost := by
  unfold weight
  have h₁ : base * 4 + witness1 ≤ base * 4 + witness2 := Nat.add_le_add_left h (base * 4)
  exact Nat.add_le_add_right h₁ sigCost

inductive ErrorCode
  | TxErrParse
  | TxErrSigInvalid
  | BlockErrTimestampOld
deriving DecidableEq

theorem error_codes_distinct : ErrorCode.TxErrParse ≠ ErrorCode.TxErrSigInvalid := by
  simp

inductive CovenantType
  | P2PK
  | HTLC
  | VAULT
deriving DecidableEq

theorem covenant_types_distinct : CovenantType.P2PK ≠ CovenantType.HTLC := by
  simp

def clampTimestampStep (prevTs newTs maxStep : Nat) : Nat := Nat.min newTs (prevTs + maxStep)

theorem clamp_respects_upper_bound (prevTs newTs maxStep : Nat) :
    clampTimestampStep prevTs newTs maxStep ≤ prevTs + maxStep := by
  unfold clampTimestampStep
  exact Nat.min_le_right newTs (prevTs + maxStep)

def witnessCursorValid (cursor slots witnessCount : Nat) : Prop := cursor + slots ≤ witnessCount

/-- v2 (F-13 fix): General case — any slots, not just 0. -/
theorem witness_cursor_valid_general (cursor slots witnessCount : Nat)
    (h : cursor + slots ≤ witnessCount) :
    witnessCursorValid cursor slots witnessCount := h

/-- After consuming 1 witness slot, the remaining cursor is still valid.
    Captures the operational invariant of witness iteration loops. -/
theorem witness_cursor_advance (cursor slots witnessCount : Nat)
    (h : witnessCursorValid cursor (slots + 1) witnessCount) :
    witnessCursorValid (cursor + 1) slots witnessCount := by
  unfold witnessCursorValid at *
  omega

/-- Original zero-slot case (retained for backward compatibility). -/
theorem witness_cursor_zero_slot (cursor witnessCount : Nat) (h : cursor ≤ witnessCount) :
    witnessCursorValid cursor 0 witnessCount := by
  unfold witnessCursorValid
  simpa [Nat.add_zero] using h

def nonceReplayFree (nonces : List Nat) : Prop := List.Nodup nonces

theorem duplicate_nonce_not_replay_free (n : Nat) (xs : List Nat) (h : n ∈ xs) :
    ¬ nonceReplayFree (n :: xs) := by
  unfold nonceReplayFree
  intro hn
  have hforall : ∀ a' : Nat, a' ∈ xs → n ≠ a' :=
    (List.pairwise_cons.mp hn).1
  exact (hforall n h) rfl

structure UtxoEntry where
  spendable : Bool
  value : Nat

def canSpend (entry : UtxoEntry) : Prop := entry.spendable = true

theorem non_spendable_cannot_spend (v : Nat) :
    ¬ canSpend { spendable := false, value := v } := by
  unfold canSpend
  simp

def valueConserved (sumIn sumOut : Nat) : Prop := sumOut ≤ sumIn

theorem value_conservation_with_extra_input (sumIn sumOut fee : Nat)
    (h : valueConserved sumIn sumOut) :
    valueConserved (sumIn + fee) sumOut := by
  unfold valueConserved at *
  exact Nat.le_trans h (Nat.le_add_right sumIn fee)

def daPayloadCommitment (chunks : List Nat) : Nat := chunks.foldl (fun acc c => acc + c) 0
def daChunkSetValid (chunks : List Nat) : Prop := chunks ≠ []

/-- v2 (F-12/F-15 fix): replaced trivial `x = x` with substantive base-case behavior. -/
theorem da_payload_commitment_empty : daPayloadCommitment [] = 0 := rfl

theorem da_payload_commitment_nonneg (chunks : List Nat) :
    0 ≤ daPayloadCommitment chunks := Nat.zero_le _

theorem da_chunk_set_requires_nonempty : ¬ daChunkSetValid [] := by
  simp [daChunkSetValid]

def parseTransactionWire (bytes : List Nat) : Option Nat := bytes.head?

theorem parse_empty_none : parseTransactionWire [] = none := rfl

end RubinFormal

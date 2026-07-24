import RubinFormal.BlockBasicCheckV1
import RubinFormal.BytesEqLemmas
namespace RubinFormal
open BlockBasicCheckV1
open BlockBasicV1

-- ============================================================
-- §16 block_timestamp_rules — Universal Upgrade
-- ============================================================

-- Concrete regression tests (WRAPPER class):
theorem timestamp_after_mtp_accepted :
    timestampBounds 100 101 = .ok () := by rfl
theorem timestamp_at_mtp_rejected :
    timestampBounds 100 100 = .error "BLOCK_ERR_TIMESTAMP_OLD" := by rfl
theorem timestamp_before_mtp_rejected :
    timestampBounds 100 50 = .error "BLOCK_ERR_TIMESTAMP_OLD" := by rfl

-- ============================================================
-- LIVE: insertNat / sortNat — membership
-- ============================================================

theorem mem_insertNat_iff (a x : Nat) (xs : List Nat) :
    a ∈ insertNat x xs ↔ a = x ∨ a ∈ xs := by
  induction xs with
  | nil => unfold insertNat; simp
  | cons y ys ih =>
    unfold insertNat
    split <;> simp [List.mem_cons, ih] <;> constructor <;> intro h <;>
      rcases h with rfl | rfl | h <;> simp_all

theorem mem_sortNat_iff (a : Nat) (xs : List Nat) :
    a ∈ sortNat xs ↔ a ∈ xs := by
  induction xs with
  | nil => simp [sortNat]
  | cons x rest ih =>
    simp only [sortNat, mem_insertNat_iff, ih, List.mem_cons]

-- ============================================================
-- LIVE: insertNat / sortNat — length preservation
-- ============================================================

theorem insertNat_length (x : Nat) (xs : List Nat) :
    (insertNat x xs).length = xs.length + 1 := by
  induction xs with
  | nil => unfold insertNat; rfl
  | cons y ys ih =>
    unfold insertNat
    split
    · simp [List.length_cons]
    · simp [List.length_cons, ih]

theorem sortNat_length (xs : List Nat) :
    (sortNat xs).length = xs.length := by
  induction xs with
  | nil => rfl
  | cons x rest ih =>
    unfold sortNat
    rw [insertNat_length, ih, List.length_cons]

-- ============================================================
-- LIVE: insertNat / sortNat — sortedness
-- ============================================================

theorem insertNat_sorted (x : Nat) (xs : List Nat)
    (h : List.Pairwise (· ≤ ·) xs) :
    List.Pairwise (· ≤ ·) (insertNat x xs) := by
  induction xs with
  | nil =>
    unfold insertNat
    exact List.Pairwise.cons (fun _ h => absurd h (List.not_mem_nil _)) .nil
  | cons y ys ih =>
    unfold insertNat
    split
    case inl hle =>
      apply List.Pairwise.cons
      · intro b hb
        rw [List.mem_cons] at hb
        rcases hb with rfl | hb
        · exact hle
        · exact Nat.le_trans hle (List.rel_of_pairwise_cons h hb)
      · exact h
    case inr hgt =>
      have hyx : y ≤ x := by omega
      have ih_result := ih (List.Pairwise.of_cons h)
      apply List.Pairwise.cons
      · intro b hb
        rw [mem_insertNat_iff] at hb
        rcases hb with rfl | hb
        · exact hyx
        · exact List.rel_of_pairwise_cons h hb
      · exact ih_result

theorem sortNat_sorted (xs : List Nat) :
    List.Pairwise (· ≤ ·) (sortNat xs) := by
  induction xs with
  | nil => exact .nil
  | cons x rest ih =>
    exact insertNat_sorted x (sortNat rest) ih

-- ============================================================
-- LIVE: medianTimePast
-- ============================================================

theorem medianTimePast_empty_err :
    medianTimePast [] = .error "BLOCK_ERR_PARSE" := by
  unfold medianTimePast; rfl

theorem medianTimePast_nonempty_ok (x : Nat) (xs : List Nat) :
    ∃ v, medianTimePast (x :: xs) = .ok v := by
  unfold medianTimePast
  simp [List.isEmpty]
  exact ⟨_, rfl⟩

/-- LIVE: medianTimePast returns the element at the median index of the sorted input.
    Connects the existential in `medianTimePast_nonempty_ok` to a concrete value,
    closing the composition gap between sort correctness and MTP output. -/
theorem medianTimePast_value (x : Nat) (xs : List Nat) :
    medianTimePast (x :: xs) =
      .ok ((sortNat (x :: xs)).get! ((sortNat (x :: xs)).length / 2)) := by
  unfold medianTimePast
  simp [List.isEmpty, pure, Except.pure, bind, Except.bind]

theorem medianTimePast_index_valid (x : Nat) (xs : List Nat) :
    (sortNat (x :: xs)).length / 2 < (sortNat (x :: xs)).length := by
  rw [sortNat_length, List.length_cons]; omega

-- ============================================================
-- LIVE: timestamp gate — trichotomy + complete partition
-- ============================================================

theorem timestampBounds_trichotomy (mtp ts : Nat) :
    (timestampBounds mtp ts = .ok ()) ∨
    (timestampBounds mtp ts = .error "BLOCK_ERR_TIMESTAMP_OLD") ∨
    (timestampBounds mtp ts = .error "BLOCK_ERR_TIMESTAMP_FUTURE") := by
  unfold timestampBounds
  split
  · exact Or.inr (Or.inl rfl)
  · split
    · exact Or.inr (Or.inr rfl)
    · exact Or.inl rfl

theorem timestampBounds_complete (mtp ts : Nat) :
    (timestampBounds mtp ts = .ok () ∧ mtp < ts ∧ ts ≤ mtp + MAX_FUTURE_DRIFT) ∨
    (timestampBounds mtp ts = .error "BLOCK_ERR_TIMESTAMP_OLD" ∧ ts ≤ mtp) ∨
    (timestampBounds mtp ts = .error "BLOCK_ERR_TIMESTAMP_FUTURE" ∧
      mtp < ts ∧ mtp + MAX_FUTURE_DRIFT < ts) := by
  rcases timestampBounds_trichotomy mtp ts with h | h | h
  · exact Or.inl ⟨h, (timestampBounds_ok_iff mtp ts).mp h⟩
  · exact Or.inr (Or.inl ⟨h, (timestampBounds_old_iff mtp ts).mp h⟩)
  · exact Or.inr (Or.inr ⟨h, (timestampBounds_future_iff mtp ts).mp h⟩)

private theorem except_unit_bind_pure_eq_self (x : Except String Unit) :
    (match x with
    | .error err => .error err
    | .ok _ => .ok ()) = x := by
  cases x <;> rfl

-- ============================================================
-- LIVE: validateBlockBasicCheck — timestamp stage on the top-level path
-- ============================================================

/-- Exact post-prefix decomposition of the real `validateBlockBasicCheck`
    timestamp stage. Once parse/pow/target/linkage/merkle/witness checks
    have passed on the live path, the remaining suffix is exactly:
    derive `medianTimePast`, apply `timestampBounds`, then run nonce replay. -/
theorem validateBlockBasicCheck_timestamp_stage
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (blockHeight : Nat)
    (prevTimestamps : List Nat)
    (pb : ParsedBlock)
    (witnessRoot gotCommit : Bytes)
    (hParse : BlockBasicV1.parseBlock blockBytes = .ok pb)
    (hPow : BlockBasicV1.powCheck pb.header = .ok ())
    (hTarget :
      match expectedTarget with
      | none => True
      | some exp => pb.header.target = exp)
    (hPrev :
      match expectedPrevHash with
      | none => True
      | some exp => pb.header.prevHash = exp)
    (hMerkle : BlockBasicV1.merkleRootTxids pb.txids = .ok pb.header.merkleRoot)
    (hWmr : BlockBasicV1.witnessMerkleRootWtxids pb.wtxids = .ok witnessRoot)
    (hCommit : BlockBasicV1.findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit)
    (hEq : gotCommit = BlockBasicV1.witnessCommitmentHash witnessRoot) :
    validateBlockBasicCheck blockBytes expectedPrevHash expectedTarget blockHeight prevTimestamps =
      (do
        let mtp ← medianTimePast prevTimestamps
        timestampBounds mtp pb.header.timestamp
        nonceReplayCheck pb.txs) := by
  have hCommitFalse : (gotCommit != BlockBasicV1.witnessCommitmentHash witnessRoot) = false := by
    subst hEq
    exact bytes_bne_self_false _
  cases expectedTarget with
  | none =>
      cases expectedPrevHash with
      | none =>
          simp [validateBlockBasicCheck, enforceSigSuiteActivation, Bind.bind, Except.bind,
            Pure.pure, Except.pure, hParse, hPow, hMerkle, hWmr, hCommit, hCommitFalse,
            bytes_bne_self_false]
          cases hMtp : medianTimePast prevTimestamps with
          | error err => simp [hMtp, except_unit_bind_pure_eq_self]
          | ok mtp =>
              cases hTs : timestampBounds mtp pb.header.timestamp with
              | error err => simp [hMtp, hTs, except_unit_bind_pure_eq_self]
              | ok u =>
                  cases hNonce : nonceReplayCheck pb.txs with
                  | error err => simp [hTs, hNonce]
                  | ok u' => simp [hTs, hNonce]
      | some prev =>
          simp at hPrev
          have hPrevFalse : (pb.header.prevHash != prev) = false := by
            subst hPrev
            exact bytes_bne_self_false _
          simp [validateBlockBasicCheck, enforceSigSuiteActivation, Bind.bind, Except.bind,
            Pure.pure, Except.pure, hParse, hPow, hPrevFalse, hMerkle, hWmr, hCommit,
            hCommitFalse, bytes_bne_self_false]
          cases hMtp : medianTimePast prevTimestamps with
          | error err => simp [hMtp, except_unit_bind_pure_eq_self]
          | ok mtp =>
              cases hTs : timestampBounds mtp pb.header.timestamp with
              | error err => simp [hMtp, hTs, except_unit_bind_pure_eq_self]
              | ok u =>
                  cases hNonce : nonceReplayCheck pb.txs with
                  | error err => simp [hTs, hNonce]
                  | ok u' => simp [hTs, hNonce]
  | some target =>
      simp at hTarget
      have hTargetFalse : (pb.header.target != target) = false := by
        subst hTarget
        exact bytes_bne_self_false _
      cases expectedPrevHash with
      | none =>
          simp [validateBlockBasicCheck, enforceSigSuiteActivation, Bind.bind, Except.bind,
            Pure.pure, Except.pure, hParse, hPow, hTargetFalse, hMerkle, hWmr, hCommit,
            hCommitFalse, bytes_bne_self_false]
          cases hMtp : medianTimePast prevTimestamps with
          | error err => simp [hMtp, except_unit_bind_pure_eq_self]
          | ok mtp =>
              cases hTs : timestampBounds mtp pb.header.timestamp with
              | error err => simp [hMtp, hTs, except_unit_bind_pure_eq_self]
              | ok u =>
                  cases hNonce : nonceReplayCheck pb.txs with
                  | error err => simp [hTs, hNonce]
                  | ok u' => simp [hTs, hNonce]
      | some prev =>
          simp at hPrev
          have hPrevFalse : (pb.header.prevHash != prev) = false := by
            subst hPrev
            exact bytes_bne_self_false _
          simp [validateBlockBasicCheck, enforceSigSuiteActivation, Bind.bind, Except.bind,
            Pure.pure, Except.pure, hParse, hPow, hTargetFalse, hPrevFalse, hMerkle, hWmr,
            hCommit, hCommitFalse, bytes_bne_self_false]
          cases hMtp : medianTimePast prevTimestamps with
          | error err => simp [hMtp, except_unit_bind_pure_eq_self]
          | ok mtp =>
              cases hTs : timestampBounds mtp pb.header.timestamp with
              | error err => simp [hMtp, hTs, except_unit_bind_pure_eq_self]
              | ok u =>
                  cases hNonce : nonceReplayCheck pb.txs with
                  | error err => simp [hTs, hNonce]
                  | ok u' => simp [hTs, hNonce]

/-- LIVE constrained acceptance on the real block-basic timestamp path:
    once the prefix checks and nonce replay pass, the derived MTP/timestamp
    satisfying the canonical bounds is sufficient for
    `validateBlockBasicCheck` to accept. -/
theorem validateBlockBasicCheck_timestamp_ok_constrained
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (blockHeight : Nat)
    (prevTimestamps : List Nat)
    (pb : ParsedBlock)
    (witnessRoot gotCommit : Bytes)
    (mtp : Nat)
    (hParse : BlockBasicV1.parseBlock blockBytes = .ok pb)
    (hPow : BlockBasicV1.powCheck pb.header = .ok ())
    (hTarget :
      match expectedTarget with
      | none => True
      | some exp => pb.header.target = exp)
    (hPrev :
      match expectedPrevHash with
      | none => True
      | some exp => pb.header.prevHash = exp)
    (hMerkle : BlockBasicV1.merkleRootTxids pb.txids = .ok pb.header.merkleRoot)
    (hWmr : BlockBasicV1.witnessMerkleRootWtxids pb.wtxids = .ok witnessRoot)
    (hCommit : BlockBasicV1.findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit)
    (hEq : gotCommit = BlockBasicV1.witnessCommitmentHash witnessRoot)
    (hMtp : medianTimePast prevTimestamps = .ok mtp)
    (hTs : mtp < pb.header.timestamp ∧ pb.header.timestamp ≤ mtp + MAX_FUTURE_DRIFT)
    (hNonce : nonceReplayCheck pb.txs = .ok ()) :
    validateBlockBasicCheck blockBytes expectedPrevHash expectedTarget blockHeight prevTimestamps =
      .ok () := by
  rw [validateBlockBasicCheck_timestamp_stage blockBytes expectedPrevHash expectedTarget
    blockHeight prevTimestamps pb witnessRoot gotCommit hParse hPow hTarget hPrev hMerkle
    hWmr hCommit hEq, hMtp]
  have hTsOk : timestampBounds mtp pb.header.timestamp = .ok () :=
    (timestampBounds_ok_iff mtp pb.header.timestamp).2 hTs
  simp [hTsOk, hNonce, Bind.bind, Except.bind, Pure.pure, Except.pure]

/-- LIVE constrained rejection on the real block-basic timestamp path:
    after the same preceding live checks, a timestamp at-or-before the derived
    median-time-past rejects with `BLOCK_ERR_TIMESTAMP_OLD`. -/
theorem validateBlockBasicCheck_timestamp_old_rejected_constrained
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (blockHeight : Nat)
    (prevTimestamps : List Nat)
    (pb : ParsedBlock)
    (witnessRoot gotCommit : Bytes)
    (mtp : Nat)
    (hParse : BlockBasicV1.parseBlock blockBytes = .ok pb)
    (hPow : BlockBasicV1.powCheck pb.header = .ok ())
    (hTarget :
      match expectedTarget with
      | none => True
      | some exp => pb.header.target = exp)
    (hPrev :
      match expectedPrevHash with
      | none => True
      | some exp => pb.header.prevHash = exp)
    (hMerkle : BlockBasicV1.merkleRootTxids pb.txids = .ok pb.header.merkleRoot)
    (hWmr : BlockBasicV1.witnessMerkleRootWtxids pb.wtxids = .ok witnessRoot)
    (hCommit : BlockBasicV1.findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit)
    (hEq : gotCommit = BlockBasicV1.witnessCommitmentHash witnessRoot)
    (hMtp : medianTimePast prevTimestamps = .ok mtp)
    (hOld : pb.header.timestamp ≤ mtp) :
    validateBlockBasicCheck blockBytes expectedPrevHash expectedTarget blockHeight prevTimestamps =
      .error "BLOCK_ERR_TIMESTAMP_OLD" := by
  rw [validateBlockBasicCheck_timestamp_stage blockBytes expectedPrevHash expectedTarget
    blockHeight prevTimestamps pb witnessRoot gotCommit hParse hPow hTarget hPrev hMerkle
    hWmr hCommit hEq, hMtp]
  have hTsOld : timestampBounds mtp pb.header.timestamp = .error "BLOCK_ERR_TIMESTAMP_OLD" :=
    (timestampBounds_old_iff mtp pb.header.timestamp).2 hOld
  simp [hTsOld, Bind.bind, Except.bind, Pure.pure, Except.pure]

/-- LIVE constrained rejection on the real block-basic timestamp path:
    after the same preceding live checks, a timestamp beyond the allowed future
    drift rejects with `BLOCK_ERR_TIMESTAMP_FUTURE`. -/
theorem validateBlockBasicCheck_timestamp_future_rejected_constrained
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (blockHeight : Nat)
    (prevTimestamps : List Nat)
    (pb : ParsedBlock)
    (witnessRoot gotCommit : Bytes)
    (mtp : Nat)
    (hParse : BlockBasicV1.parseBlock blockBytes = .ok pb)
    (hPow : BlockBasicV1.powCheck pb.header = .ok ())
    (hTarget :
      match expectedTarget with
      | none => True
      | some exp => pb.header.target = exp)
    (hPrev :
      match expectedPrevHash with
      | none => True
      | some exp => pb.header.prevHash = exp)
    (hMerkle : BlockBasicV1.merkleRootTxids pb.txids = .ok pb.header.merkleRoot)
    (hWmr : BlockBasicV1.witnessMerkleRootWtxids pb.wtxids = .ok witnessRoot)
    (hCommit : BlockBasicV1.findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit)
    (hEq : gotCommit = BlockBasicV1.witnessCommitmentHash witnessRoot)
    (hMtp : medianTimePast prevTimestamps = .ok mtp)
    (hFuture : mtp < pb.header.timestamp ∧ mtp + MAX_FUTURE_DRIFT < pb.header.timestamp) :
    validateBlockBasicCheck blockBytes expectedPrevHash expectedTarget blockHeight prevTimestamps =
      .error "BLOCK_ERR_TIMESTAMP_FUTURE" := by
  rw [validateBlockBasicCheck_timestamp_stage blockBytes expectedPrevHash expectedTarget
    blockHeight prevTimestamps pb witnessRoot gotCommit hParse hPow hTarget hPrev hMerkle
    hWmr hCommit hEq, hMtp]
  have hTsFuture : timestampBounds mtp pb.header.timestamp = .error "BLOCK_ERR_TIMESTAMP_FUTURE" :=
    (timestampBounds_future_iff mtp pb.header.timestamp).2 hFuture
  simp [hTsFuture, Bind.bind, Except.bind, Pure.pure, Except.pure]

end RubinFormal

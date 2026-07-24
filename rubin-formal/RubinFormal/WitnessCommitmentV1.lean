import RubinFormal.BlockValidationOrder

namespace RubinFormal

open BlockBasicV1

namespace WitnessCommitmentV1

theorem coinbaseWitnessReservedValue_size :
    coinbaseWitnessReservedValue.size = 32 := by
  native_decide

theorem witnessMerkleRootWtxids_rewrites_coinbase_slot
    (coinbaseWtxid : Bytes) (rest : List Bytes) :
    witnessMerkleRootWtxids (coinbaseWtxid :: rest) =
      merkleRootTagged (coinbaseWitnessReservedValue :: rest) 0x02 0x03 := by
  simp [witnessMerkleRootWtxids]

theorem checkWitnessCommitment_rejects_mismatched_anchor
    (pb : ParsedBlock)
    (witnessRoot gotCommit : Bytes)
    (hRoot : witnessMerkleRootWtxids pb.wtxids = .ok witnessRoot)
    (hCommit : findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit)
    (hNe : gotCommit ≠ witnessCommitmentHash witnessRoot) :
    checkWitnessCommitment pb = .error "BLOCK_ERR_WITNESS_COMMITMENT" := by
  unfold checkWitnessCommitment
  rw [hRoot, hCommit]
  have hMismatch : (gotCommit != witnessCommitmentHash witnessRoot) = true := by
    cases hBool : (gotCommit != witnessCommitmentHash witnessRoot) with
    | true =>
        exact rfl
    | false =>
        have hEq : gotCommit = witnessCommitmentHash witnessRoot :=
          RubinFormal.bne_false_eq gotCommit (witnessCommitmentHash witnessRoot) hBool
        exact False.elim (hNe hEq)
  simp only [Bind.bind, Except.bind, Pure.pure, Except.pure]
  rw [hMismatch]
  rfl

theorem checkWitnessCommitment_ok_iff
    (pb : ParsedBlock)
    (witnessRoot gotCommit : Bytes)
    (hRoot : witnessMerkleRootWtxids pb.wtxids = .ok witnessRoot)
    (hCommit : findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit) :
    checkWitnessCommitment pb = .ok () ↔
      gotCommit = witnessCommitmentHash witnessRoot := by
  unfold checkWitnessCommitment
  rw [hRoot, hCommit]
  cases hMismatch : (gotCommit != witnessCommitmentHash witnessRoot) with
  | false =>
      constructor
      · intro _hOk
        exact RubinFormal.bne_false_eq gotCommit (witnessCommitmentHash witnessRoot) hMismatch
      · intro _hEq
        simp [Bind.bind, Except.bind, Pure.pure, Except.pure, hMismatch, ite_false]
  | true =>
      constructor
      · intro hOk
        simp [Bind.bind, Except.bind, Pure.pure, Except.pure, hMismatch, ite_true] at hOk
      · intro hEq
        have hFalse : (gotCommit != witnessCommitmentHash witnessRoot) = false := by
          subst hEq; exact bytes_bne_self_false _
        rw [hFalse] at hMismatch
        cases hMismatch

theorem checkWitnessCommitment_accepts_matching_anchor
    (pb : ParsedBlock)
    (witnessRoot gotCommit : Bytes)
    (hRoot : witnessMerkleRootWtxids pb.wtxids = .ok witnessRoot)
    (hCommit : findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit)
    (hEq : gotCommit = witnessCommitmentHash witnessRoot) :
    checkWitnessCommitment pb = .ok () := by
  exact (checkWitnessCommitment_ok_iff pb witnessRoot gotCommit hRoot hCommit).2 hEq

private theorem merkleGate_reduces_to_checkWitnessCommitment
    (pb : ParsedBlock)
    (hMerkle : merkleRootTxids pb.txids = .ok pb.header.merkleRoot) :
    (do
      let mr ← merkleRootTxids pb.txids
      if mr != pb.header.merkleRoot then
        throw "BLOCK_ERR_MERKLE_INVALID"
      checkWitnessCommitment pb) = checkWitnessCommitment pb := by
  rw [hMerkle]
  have hSelf : (pb.header.merkleRoot != pb.header.merkleRoot) = false :=
    bytes_bne_self_false _
  simp [Bind.bind, Except.bind, Pure.pure, Except.pure, hSelf, ite_false]

theorem validateBlockBasic_witness_stage
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (pb : ParsedBlock)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hTarget :
      match expectedTarget with
      | none => True
      | some exp => pb.header.target = exp)
    (hPrev :
      match expectedPrevHash with
      | none => True
      | some exp => pb.header.prevHash = exp)
    (hMerkle : merkleRootTxids pb.txids = .ok pb.header.merkleRoot) :
    validateBlockBasic blockBytes expectedPrevHash expectedTarget = checkWitnessCommitment pb := by
  cases expectedTarget with
  | none =>
      cases expectedPrevHash with
      | none =>
          have hTail := merkleGate_reduces_to_checkWitnessCommitment pb hMerkle
          simpa [validateBlockBasic, Bind.bind, Except.bind, Pure.pure, Except.pure,
            hParse, hPow] using hTail
      | some prev =>
          simp at hPrev
          have hPrevFalse : (pb.header.prevHash != prev) = false := by
            subst hPrev; exact bytes_bne_self_false _
          have hTail := merkleGate_reduces_to_checkWitnessCommitment pb hMerkle
          simpa [validateBlockBasic, Bind.bind, Except.bind, Pure.pure, Except.pure,
            hParse, hPow, hPrevFalse] using hTail
  | some target =>
      simp at hTarget
      have hTargetFalse : (pb.header.target != target) = false := by
        subst hTarget; exact bytes_bne_self_false _
      cases expectedPrevHash with
      | none =>
          have hTail := merkleGate_reduces_to_checkWitnessCommitment pb hMerkle
          simpa [validateBlockBasic, Bind.bind, Except.bind, Pure.pure, Except.pure,
            hParse, hPow, hTargetFalse] using hTail
      | some prev =>
          simp at hPrev
          have hPrevFalse : (pb.header.prevHash != prev) = false := by
            subst hPrev; exact bytes_bne_self_false _
          have hTail := merkleGate_reduces_to_checkWitnessCommitment pb hMerkle
          simpa [validateBlockBasic, Bind.bind, Except.bind, Pure.pure, Except.pure,
            hParse, hPow, hTargetFalse, hPrevFalse] using hTail

theorem validateBlockBasic_accepts_matching_anchor
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (pb : ParsedBlock)
    (witnessRoot gotCommit : Bytes)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hTarget :
      match expectedTarget with
      | none => True
      | some exp => pb.header.target = exp)
    (hPrev :
      match expectedPrevHash with
      | none => True
      | some exp => pb.header.prevHash = exp)
    (hMerkle : merkleRootTxids pb.txids = .ok pb.header.merkleRoot)
    (hRoot : witnessMerkleRootWtxids pb.wtxids = .ok witnessRoot)
    (hCommit : findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit)
    (hEq : gotCommit = witnessCommitmentHash witnessRoot) :
    validateBlockBasic blockBytes expectedPrevHash expectedTarget = .ok () := by
  rw [validateBlockBasic_witness_stage blockBytes expectedPrevHash expectedTarget pb
    hParse hPow hTarget hPrev hMerkle]
  exact checkWitnessCommitment_accepts_matching_anchor pb witnessRoot gotCommit hRoot hCommit hEq

theorem validateBlockBasic_rejects_mismatched_anchor
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (pb : ParsedBlock)
    (witnessRoot gotCommit : Bytes)
    (hParse : parseBlock blockBytes = .ok pb)
    (hPow : powCheck pb.header = .ok ())
    (hTarget :
      match expectedTarget with
      | none => True
      | some exp => pb.header.target = exp)
    (hPrev :
      match expectedPrevHash with
      | none => True
      | some exp => pb.header.prevHash = exp)
    (hMerkle : merkleRootTxids pb.txids = .ok pb.header.merkleRoot)
    (hRoot : witnessMerkleRootWtxids pb.wtxids = .ok witnessRoot)
    (hCommit : findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit)
    (hNe : gotCommit ≠ witnessCommitmentHash witnessRoot) :
    validateBlockBasic blockBytes expectedPrevHash expectedTarget =
      .error "BLOCK_ERR_WITNESS_COMMITMENT" := by
  rw [validateBlockBasic_witness_stage blockBytes expectedPrevHash expectedTarget pb
    hParse hPow hTarget hPrev hMerkle]
  exact checkWitnessCommitment_rejects_mismatched_anchor pb witnessRoot gotCommit hRoot hCommit hNe

end WitnessCommitmentV1

end RubinFormal

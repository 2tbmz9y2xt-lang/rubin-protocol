import RubinFormal.BlockBasicV1
import RubinFormal.ConnectBlockStrong
import RubinFormal.BytesEqLemmas

namespace RubinFormal

open BlockBasicV1

/-- Proof-only decomposition of the Merkle and witness-commitment tail. -/
def validateBlockBasicMerkleWitnessTail
    (pb : ParsedBlock) : Except String Unit := do
  let mr ← merkleRootTxids pb.txids
  if mr != pb.header.merkleRoot then
    throw "BLOCK_ERR_MERKLE_INVALID"
  let wmr ← witnessMerkleRootWtxids pb.wtxids
  let expectCommit := witnessCommitmentHash wmr
  let gotCommit ← findCoinbaseAnchorCommitment pb.coinbaseTx
  if gotCommit != expectCommit then
    throw "BLOCK_ERR_WITNESS_COMMITMENT"
  pure ()

/-- Proof-only decomposition of the post-PoW tail. -/
def validateBlockBasicAfterPow
    (pb : ParsedBlock)
    (expectedPrevHash expectedTarget : Option Bytes) : Except String Unit := do
  match expectedTarget with
  | none => pure ()
  | some exp =>
      if pb.header.target != exp then
        throw "BLOCK_ERR_TARGET_INVALID"
  match expectedPrevHash with
  | none => pure ()
  | some exp =>
      if pb.header.prevHash != exp then
        throw "BLOCK_ERR_LINKAGE_INVALID"
  validateBlockBasicMerkleWitnessTail pb

/-- Proof-only decomposition of the post-parse tail. -/
def validateBlockBasicTail
    (pb : ParsedBlock)
    (expectedPrevHash expectedTarget : Option Bytes) : Except String Unit := do
  powCheck pb.header
  validateBlockBasicAfterPow pb expectedPrevHash expectedTarget

theorem bool_gate_pass
    {ε α : Type}
    {cond : Bool}
    {err : ε}
    {next : Except ε α}
    {x : α}
    (h : (if cond then Except.error err else next) = .ok x) :
    cond = false := by
  cases hCond : cond with
  | false =>
      rfl
  | true =>
      simp [hCond] at h

theorem validateBlockBasic_parses
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (hOk : validateBlockBasic blockBytes expectedPrevHash expectedTarget = .ok ()) :
    ∃ pb,
      parseBlock blockBytes = .ok pb ∧
      validateBlockBasicTail pb expectedPrevHash expectedTarget = .ok () := by
  unfold validateBlockBasic at hOk
  rcases except_bind_eq_ok hOk with ⟨pb, hParse, hTail⟩
  have hTail' : validateBlockBasicTail pb expectedPrevHash expectedTarget = .ok () := by
    simpa [validateBlockBasicTail, validateBlockBasicAfterPow,
      validateBlockBasicMerkleWitnessTail] using hTail
  exact ⟨pb, hParse, hTail'⟩

theorem validateBlockBasicTail_pow_passes
    (pb : ParsedBlock)
    (expectedPrevHash expectedTarget : Option Bytes)
    (hTail : validateBlockBasicTail pb expectedPrevHash expectedTarget = .ok ()) :
    powCheck pb.header = .ok () ∧
    validateBlockBasicAfterPow pb expectedPrevHash expectedTarget = .ok () := by
  unfold validateBlockBasicTail at hTail
  rcases except_bind_eq_ok hTail with ⟨u, hPow, hAfterPow⟩
  cases u
  exact ⟨hPow, hAfterPow⟩

theorem validateBlockBasic_pow_passes
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (hOk : validateBlockBasic blockBytes expectedPrevHash expectedTarget = .ok ()) :
    ∃ pb,
      parseBlock blockBytes = .ok pb ∧
      powCheck pb.header = .ok () ∧
      validateBlockBasicAfterPow pb expectedPrevHash expectedTarget = .ok () := by
  rcases validateBlockBasic_parses blockBytes expectedPrevHash expectedTarget hOk with
    ⟨pb, hParse, hTail⟩
  have ⟨hPow, hAfterPow⟩ :=
    validateBlockBasicTail_pow_passes pb expectedPrevHash expectedTarget hTail
  exact ⟨pb, hParse, hPow, hAfterPow⟩

theorem merkle_witness_of_tail
    (pb : ParsedBlock)
    (hTail : validateBlockBasicMerkleWitnessTail pb = .ok ()) :
    ∃ mr wmr gotCommit,
      merkleRootTxids pb.txids = .ok mr ∧
      mr = pb.header.merkleRoot ∧
      witnessMerkleRootWtxids pb.wtxids = .ok wmr ∧
      findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit ∧
      gotCommit = witnessCommitmentHash wmr := by
  unfold validateBlockBasicMerkleWitnessTail at hTail
  rcases except_bind_eq_ok hTail with ⟨mr, hMr, hAfterMr⟩
  have hMrGate :
      (if mr != pb.header.merkleRoot then
        Except.error "BLOCK_ERR_MERKLE_INVALID"
      else
        do
          let wmr ← witnessMerkleRootWtxids pb.wtxids
          let expectCommit := witnessCommitmentHash wmr
          let gotCommit ← findCoinbaseAnchorCommitment pb.coinbaseTx
          if gotCommit != expectCommit then
            throw "BLOCK_ERR_WITNESS_COMMITMENT"
          pure ()) = .ok () := by
    simpa using hAfterMr
  have hMrFalse : (mr != pb.header.merkleRoot) = false := bool_gate_pass hMrGate
  have hMrEq : mr = pb.header.merkleRoot := bne_false_eq mr pb.header.merkleRoot hMrFalse
  have hAfterMerkle :
      (do
        let wmr ← witnessMerkleRootWtxids pb.wtxids
        let expectCommit := witnessCommitmentHash wmr
        let gotCommit ← findCoinbaseAnchorCommitment pb.coinbaseTx
        if gotCommit != expectCommit then
          throw "BLOCK_ERR_WITNESS_COMMITMENT"
        pure ()) = .ok () := by
    simpa [hMrFalse] using hAfterMr
  change
      (witnessMerkleRootWtxids pb.wtxids >>= fun wmr =>
        do
          let expectCommit := witnessCommitmentHash wmr
          let gotCommit ← findCoinbaseAnchorCommitment pb.coinbaseTx
          if gotCommit != expectCommit then
            throw "BLOCK_ERR_WITNESS_COMMITMENT"
          pure ()) = .ok () at hAfterMerkle
  rcases except_bind_eq_ok hAfterMerkle with ⟨wmr, hWmr, hAfterWmr⟩
  have hAfterWmr' :
      (findCoinbaseAnchorCommitment pb.coinbaseTx >>= fun gotCommit =>
        if gotCommit != witnessCommitmentHash wmr then
          Except.error "BLOCK_ERR_WITNESS_COMMITMENT"
        else
          .ok ()) = .ok () := by
    simpa using hAfterWmr
  rcases except_bind_eq_ok hAfterWmr' with ⟨gotCommit, hGotCommit, hAfterGotCommit⟩
  have hCommitFalse : (gotCommit != witnessCommitmentHash wmr) = false :=
    bool_gate_pass hAfterGotCommit
  have hCommitEq : gotCommit = witnessCommitmentHash wmr :=
    bne_false_eq gotCommit (witnessCommitmentHash wmr) hCommitFalse
  exact ⟨mr, wmr, gotCommit, hMr, hMrEq, hWmr, hGotCommit, hCommitEq⟩

theorem section25_order_complete
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (hOk : validateBlockBasic blockBytes expectedPrevHash expectedTarget = .ok ()) :
    ∃ pb mr wmr gotCommit,
      parseBlock blockBytes = .ok pb ∧
      powCheck pb.header = .ok () ∧
      (match expectedTarget with
      | none => True
      | some exp => pb.header.target = exp) ∧
      (match expectedPrevHash with
      | none => True
      | some exp => pb.header.prevHash = exp) ∧
      merkleRootTxids pb.txids = .ok mr ∧
      mr = pb.header.merkleRoot ∧
      witnessMerkleRootWtxids pb.wtxids = .ok wmr ∧
      findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit ∧
      gotCommit = witnessCommitmentHash wmr := by
  rcases validateBlockBasic_pow_passes blockBytes expectedPrevHash expectedTarget hOk with
    ⟨pb, hParse, hPow, hAfterPow⟩
  cases hTgt : expectedTarget with
  | none =>
      have hAfterTarget :
          (do
            match expectedPrevHash with
            | none => pure ()
            | some prev =>
                if pb.header.prevHash != prev then
                  throw "BLOCK_ERR_LINKAGE_INVALID"
            validateBlockBasicMerkleWitnessTail pb) = .ok () := by
        simpa [validateBlockBasicAfterPow, hTgt] using hAfterPow
      cases hPrev : expectedPrevHash with
      | none =>
          have hMerkleTail : validateBlockBasicMerkleWitnessTail pb = .ok () := by
            simpa [hPrev] using hAfterTarget
          rcases merkle_witness_of_tail pb hMerkleTail with
            ⟨mr, wmr, gotCommit, hMr, hMrEq, hWmr, hGotCommit, hCommitEq⟩
          exact ⟨pb, mr, wmr, gotCommit,
            hParse, hPow,
            by simp [hTgt],
            by simp [hPrev],
            hMr, hMrEq, hWmr, hGotCommit, hCommitEq⟩
      | some prev =>
          have hPrevGate :
              (if pb.header.prevHash != prev then
                Except.error "BLOCK_ERR_LINKAGE_INVALID"
              else
                validateBlockBasicMerkleWitnessTail pb) = .ok () := by
            simpa [hPrev] using hAfterTarget
          have hPrevFalse : (pb.header.prevHash != prev) = false := bool_gate_pass hPrevGate
          have hPrevEq : pb.header.prevHash = prev := bne_false_eq pb.header.prevHash prev hPrevFalse
          have hMerkleTail : validateBlockBasicMerkleWitnessTail pb = .ok () := by
            simpa [hPrev, hPrevFalse] using hAfterTarget
          rcases merkle_witness_of_tail pb hMerkleTail with
            ⟨mr, wmr, gotCommit, hMr, hMrEq, hWmr, hGotCommit, hCommitEq⟩
          exact ⟨pb, mr, wmr, gotCommit,
            hParse, hPow,
            by simp [hTgt],
            by simp [hPrev, hPrevEq],
            hMr, hMrEq, hWmr, hGotCommit, hCommitEq⟩
  | some target =>
      have hTargetGate :
          (if pb.header.target != target then
            Except.error "BLOCK_ERR_TARGET_INVALID"
          else
            do
              match expectedPrevHash with
              | none => pure ()
              | some prev =>
                  if pb.header.prevHash != prev then
                    throw "BLOCK_ERR_LINKAGE_INVALID"
              validateBlockBasicMerkleWitnessTail pb) = .ok () := by
        simpa [validateBlockBasicAfterPow, hTgt] using hAfterPow
      have hTargetFalse : (pb.header.target != target) = false := bool_gate_pass hTargetGate
      have hTargetEq : pb.header.target = target := bne_false_eq pb.header.target target hTargetFalse
      have hAfterTarget :
          (do
            match expectedPrevHash with
            | none => pure ()
            | some prev =>
                if pb.header.prevHash != prev then
                  throw "BLOCK_ERR_LINKAGE_INVALID"
            validateBlockBasicMerkleWitnessTail pb) = .ok () := by
        rw [hTargetFalse] at hTargetGate
        simpa using hTargetGate
      cases hPrev : expectedPrevHash with
      | none =>
          have hMerkleTail : validateBlockBasicMerkleWitnessTail pb = .ok () := by
            simpa [hPrev] using hAfterTarget
          rcases merkle_witness_of_tail pb hMerkleTail with
            ⟨mr, wmr, gotCommit, hMr, hMrEq, hWmr, hGotCommit, hCommitEq⟩
          exact ⟨pb, mr, wmr, gotCommit,
            hParse, hPow,
            by simp [hTgt, hTargetEq],
            by simp [hPrev],
            hMr, hMrEq, hWmr, hGotCommit, hCommitEq⟩
      | some prev =>
          have hPrevGate :
              (if pb.header.prevHash != prev then
                Except.error "BLOCK_ERR_LINKAGE_INVALID"
              else
                validateBlockBasicMerkleWitnessTail pb) = .ok () := by
            simpa [hPrev] using hAfterTarget
          have hPrevFalse : (pb.header.prevHash != prev) = false := bool_gate_pass hPrevGate
          have hPrevEq : pb.header.prevHash = prev := bne_false_eq pb.header.prevHash prev hPrevFalse
          have hMerkleTail : validateBlockBasicMerkleWitnessTail pb = .ok () := by
            simpa [hPrev, hPrevFalse] using hAfterTarget
          rcases merkle_witness_of_tail pb hMerkleTail with
            ⟨mr, wmr, gotCommit, hMr, hMrEq, hWmr, hGotCommit, hCommitEq⟩
          exact ⟨pb, mr, wmr, gotCommit,
            hParse, hPow,
            by simp [hTgt, hTargetEq],
            by simp [hPrev, hPrevEq],
            hMr, hMrEq, hWmr, hGotCommit, hCommitEq⟩

def section25AcceptWitness
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes) : Prop :=
  ∃ pb mr wmr gotCommit,
    parseBlock blockBytes = .ok pb ∧
    powCheck pb.header = .ok () ∧
    (match expectedTarget with
    | none => True
    | some exp => pb.header.target = exp) ∧
    (match expectedPrevHash with
    | none => True
    | some exp => pb.header.prevHash = exp) ∧
    merkleRootTxids pb.txids = .ok mr ∧
    mr = pb.header.merkleRoot ∧
    witnessMerkleRootWtxids pb.wtxids = .ok wmr ∧
    findCoinbaseAnchorCommitment pb.coinbaseTx = .ok gotCommit ∧
    gotCommit = witnessCommitmentHash wmr

def section25ValidationTotalStatement : Prop :=
  ∀ (blockBytes : Bytes) (expectedPrevHash expectedTarget : Option Bytes),
    section25AcceptWitness blockBytes expectedPrevHash expectedTarget ∨
      ∃ err, validateBlockBasic blockBytes expectedPrevHash expectedTarget = .error err

theorem validateBlockBasic_accept_or_reject
    (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes) :
    section25AcceptWitness blockBytes expectedPrevHash expectedTarget ∨
      ∃ err, validateBlockBasic blockBytes expectedPrevHash expectedTarget = .error err := by
  cases hRes : validateBlockBasic blockBytes expectedPrevHash expectedTarget with
  | ok u =>
      cases u
      exact Or.inl (section25_order_complete blockBytes expectedPrevHash expectedTarget hRes)
  | error err =>
      exact Or.inr ⟨err, rfl⟩

theorem section25_validation_total_proved : section25ValidationTotalStatement := by
  intro blockBytes expectedPrevHash expectedTarget
  exact validateBlockBasic_accept_or_reject blockBytes expectedPrevHash expectedTarget

end RubinFormal

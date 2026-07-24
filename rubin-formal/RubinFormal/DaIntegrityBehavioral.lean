import RubinFormal.DaIntegrityV1
import RubinFormal.Conformance.CVDaIntegrityReplay

/-!
# DA Set Integrity Behavioral + Refinement Proofs (§21)

LIVE behavioral + universal proofs on `validateDASetIntegrity` and
`validateDaIntegrityGate` (DaIntegrityV1.lean).
Evidence level: machine_checked_universal for the §21 row.
`validateDASetIntegrity_ok_constrained` is a ∀-quantified constrained
theorem decomposing `.ok` into all 4 stages with parse-derived witnesses.
All DA sub-functions recursive (no foldlM/List.range), fully proved
with induction (missing/step/empty). parseDATx error taxonomy fully
machine-checked via 3-phase decomposition (no cross-section assumption).
Combines:

1. Conformance replay: `cv_da_integrity_vectors_pass` (native_decide on real vectors)
2. Gate error propagation: each gate step's error flows to the output deterministically
3. Empty-set acceptance: validateDASetIntegrity on [] = .ok ()
4. Constants: canonical DA parameters

Go equivalent: validateDASetIntegrity (consensus/da_integrity.go)
Rust equivalent: validate_da_set_integrity (rubin-consensus/src/da_integrity.rs)
-/

namespace RubinFormal
open DaIntegrityV1

/-! ## DA constants — behavioral enforcement (§21)

Behavioral boundaries stay wired to the live validators, but the canonical
literal values are also pinned explicitly so symbolic-only rewrites cannot
silently mask constant drift.
-/

/-- CHUNK_BYTES canonical literal pin. -/
theorem da_chunk_bytes_value : DaCoreV1.CHUNK_BYTES = 524288 := rfl

/-- MAX_DA_CHUNK_COUNT canonical literal pin. -/
theorem da_max_chunk_count_value : DaCoreV1.MAX_DA_CHUNK_COUNT = 61 := rfl

/-- Effective chunk-only DA capacity under the canonical per-chunk limits. -/
theorem da_effective_chunk_capacity_value :
    DaCoreV1.MAX_DA_CHUNK_COUNT * DaCoreV1.CHUNK_BYTES = 31981568 := by
  native_decide

/-- Effective chunk-only DA capacity stays within the canonical 32,000,000-byte
    per-block DA limit from Section 4. -/
theorem da_effective_chunk_capacity_within_block_limit :
    DaCoreV1.MAX_DA_CHUNK_COUNT * DaCoreV1.CHUNK_BYTES ≤ 32000000 := by
  native_decide

/-- CHUNK_BYTES boundary: daLen at limit → accepted in kind=2 tx. -/
theorem da_chunk_bytes_boundary_accept :
    BlockBasicV1.applyDaLenChecks 0x02 DaCoreV1.CHUNK_BYTES true = .ok () := by
  unfold BlockBasicV1.applyDaLenChecks
  simp only [show ¬((0x02 : Nat) == 0x00) = true from by native_decide, ite_false,
             show ¬((0x02 : Nat) == 0x01) = true from by native_decide]
  simp only [show ¬(DaCoreV1.CHUNK_BYTES < 1 || DaCoreV1.CHUNK_BYTES > DaCoreV1.CHUNK_BYTES) = true from by native_decide, ite_false]
  rfl

/-- CHUNK_BYTES boundary: daLen at limit+1 → rejected in kind=2 tx. -/
theorem da_chunk_bytes_boundary_reject :
    BlockBasicV1.applyDaLenChecks 0x02 (DaCoreV1.CHUNK_BYTES + 1) true = .error "TX_ERR_PARSE" := by
  unfold BlockBasicV1.applyDaLenChecks
  simp only [show ¬((0x02 : Nat) == 0x00) = true from by native_decide, ite_false,
             show ¬((0x02 : Nat) == 0x01) = true from by native_decide]
  simp only [show (DaCoreV1.CHUNK_BYTES + 1 < 1 || DaCoreV1.CHUNK_BYTES + 1 > DaCoreV1.CHUNK_BYTES) = true from by native_decide, ite_true]
  rfl

/-- MAX_DA_CHUNK_COUNT: chunkCount > limit → guard fires in parseDaCommitCore. -/
theorem da_max_chunk_count_guard_reject (cc : Nat) (h : cc > DaCoreV1.MAX_DA_CHUNK_COUNT) :
    (cc < 1 || cc > DaCoreV1.MAX_DA_CHUNK_COUNT) = true := by
  simp [DaCoreV1.MAX_DA_CHUNK_COUNT] at h ⊢; simp [h]

/-- MAX_DA_CHUNK_COUNT: valid range → guard passes. -/
theorem da_max_chunk_count_guard_accept (cc : Nat) (h1 : cc ≥ 1) (h2 : cc ≤ DaCoreV1.MAX_DA_CHUNK_COUNT) :
    (cc < 1 || cc > DaCoreV1.MAX_DA_CHUNK_COUNT) = false := by
  simp [DaCoreV1.MAX_DA_CHUNK_COUNT] at h2 ⊢
  simp [show ¬(cc < 1) from by omega, show ¬(cc > 61) from by omega]

/-- Total DA capacity bounded: chunkCount * chunkSize ≤ 31_981_568. -/
theorem da_total_bytes_bounded (chunkCount chunkSize : Nat)
    (hCount : chunkCount ≤ DaCoreV1.MAX_DA_CHUNK_COUNT)
    (hSize : chunkSize ≤ DaCoreV1.CHUNK_BYTES) :
    chunkCount * chunkSize ≤ 31981568 := by
  calc chunkCount * chunkSize
      ≤ DaCoreV1.MAX_DA_CHUNK_COUNT * DaCoreV1.CHUNK_BYTES := Nat.mul_le_mul hCount hSize
    _ = 31981568 := da_effective_chunk_capacity_value

/-- COV_TYPE_DA_COMMIT: wrong type → not counted by countDaCommitOutputs. -/
theorem da_wrong_cov_type_not_counted (out : TxOut)
    (h : (out.covenantType == COV_TYPE_DA_COMMIT) = false) :
    (countDaCommitOutputs [out]).1 = 0 := by
  simp only [countDaCommitOutputs, List.foldl, h, ite_false]

/-- COV_TYPE_DA_COMMIT: correct type → counted by countDaCommitOutputs. -/
theorem da_correct_cov_type_counted (out : TxOut)
    (h : (out.covenantType == COV_TYPE_DA_COMMIT) = true) :
    (countDaCommitOutputs [out]).1 = 1 := by
  simp only [countDaCommitOutputs, List.foldl, h, ite_true]

/-! ## Empty set acceptance (LIVE) -/

/-- validateDASetIntegrity on empty tx list = accepted.
    No DA txs = valid empty DA set. -/
theorem da_empty_txs_accepted :
    validateDASetIntegrity [] = .ok () := by
  unfold validateDASetIntegrity
  simp only [List.forIn, Std.RBMap.empty, Std.RBMap.size]
  rfl

/-! ## Batch count rejection (LIVE on validateDaBatchCount) -/

/-- Exceeds batch limit → BLOCK_ERR_DA_BATCH_EXCEEDED. -/
theorem da_batch_exceeded (n : Nat) (h : n > MAX_DA_BATCHES_PER_BLOCK) :
    validateDaBatchCount n = .error "BLOCK_ERR_DA_BATCH_EXCEEDED" := by
  simp only [validateDaBatchCount, h, ite_true]

/-- Within batch limit → accepted. -/
theorem da_batch_ok (n : Nat) (h : ¬(n > MAX_DA_BATCHES_PER_BLOCK)) :
    validateDaBatchCount n = .ok () := by
  simp only [validateDaBatchCount, h, ite_false]

/-- Boundary: MAX (128) is ok. -/
theorem da_batch_at_limit : validateDaBatchCount 128 = .ok () := by
  simp only [validateDaBatchCount, MAX_DA_BATCHES_PER_BLOCK, show ¬(128 > 128) from by omega, ite_false]

/-- Boundary: MAX+1 (129) is rejected. -/
theorem da_batch_over_limit : validateDaBatchCount 129 = .error "BLOCK_ERR_DA_BATCH_EXCEEDED" := by
  simp only [validateDaBatchCount, MAX_DA_BATCHES_PER_BLOCK, show 129 > 128 from by omega, ite_true]

/-! ## Chunk hash verification (LIVE on validateChunkHash) -/

/-- Hash mismatch → BLOCK_ERR_DA_CHUNK_HASH_INVALID. -/
theorem da_chunk_hash_mismatch (payload hash : Bytes) (h : (SHA3.sha3_256 payload != hash) = true) :
    validateChunkHash payload hash = .error "BLOCK_ERR_DA_CHUNK_HASH_INVALID" := by
  simp only [validateChunkHash, h, ite_true]

/-- Hash match → accepted. -/
theorem da_chunk_hash_ok (payload hash : Bytes) (h : (SHA3.sha3_256 payload != hash) = false) :
    validateChunkHash payload hash = .ok () := by
  simp only [validateChunkHash, h, ite_false]

/-! ## Duplicate detection (LIVE on validateNoDuplicateCommit / validateNoDuplicateChunk) -/

/-- Duplicate commit ID → BLOCK_ERR_DA_SET_INVALID. -/
theorem da_duplicate_commit_rejects
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes) (daId : Bytes)
    (h : commits.contains daId = true) :
    validateNoDuplicateCommit commits daId = .error "BLOCK_ERR_DA_SET_INVALID" := by
  simp only [validateNoDuplicateCommit, h, ite_true]

/-- New commit ID → accepted. -/
theorem da_duplicate_commit_ok
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes) (daId : Bytes)
    (h : commits.contains daId = false) :
    validateNoDuplicateCommit commits daId = .ok () := by
  simp only [validateNoDuplicateCommit, h, ite_false]

/-- Duplicate chunk index → BLOCK_ERR_DA_SET_INVALID. -/
theorem da_duplicate_chunk_rejects
    (set : Std.RBMap Nat DaChunkInfo compare) (idx : Nat)
    (h : set.contains idx = true) :
    validateNoDuplicateChunk set idx = .error "BLOCK_ERR_DA_SET_INVALID" := by
  simp only [validateNoDuplicateChunk, h, ite_true]

/-- New chunk index → accepted. -/
theorem da_duplicate_chunk_ok
    (set : Std.RBMap Nat DaChunkInfo compare) (idx : Nat)
    (h : set.contains idx = false) :
    validateNoDuplicateChunk set idx = .ok () := by
  simp only [validateNoDuplicateChunk, h, ite_false]

/-! ## Chunk count match (LIVE on validateChunkCountMatch) -/

/-- Chunk count mismatch → BLOCK_ERR_DA_INCOMPLETE. -/
theorem da_chunk_count_mismatch (setSize chunkCount : Nat) (h : (setSize != chunkCount) = true) :
    validateChunkCountMatch setSize chunkCount = .error "BLOCK_ERR_DA_INCOMPLETE" := by
  simp only [validateChunkCountMatch, h, ite_true]

/-- Chunk count match → accepted. -/
theorem da_chunk_count_ok (setSize chunkCount : Nat) (h : (setSize != chunkCount) = false) :
    validateChunkCountMatch setSize chunkCount = .ok () := by
  simp only [validateChunkCountMatch, h, ite_false]

/-! ## Commit output validation (LIVE on validateCommitOutput) -/

/-- Wrong commit output count → BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID. -/
theorem da_commit_output_wrong_count (outputs : List TxOut) (payloadCommit : Bytes)
    (h : (countDaCommitOutputs outputs).1 != 1) :
    validateCommitOutput outputs payloadCommit = .error "BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID" := by
  simp only [validateCommitOutput, h, ite_true]

/-- Hash mismatch → BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID. -/
theorem da_commit_output_hash_mismatch (outputs : List TxOut) (payloadCommit : Bytes)
    (hCount : ¬((countDaCommitOutputs outputs).1 != 1))
    (hHash : ((countDaCommitOutputs outputs).2 != payloadCommit) = true) :
    validateCommitOutput outputs payloadCommit = .error "BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID" := by
  simp only [validateCommitOutput, show ((countDaCommitOutputs outputs).1 != 1) = false from
    Bool.eq_false_iff.mpr hCount, ite_false, hHash, ite_true]

/-- Valid commit output → accepted. -/
theorem da_commit_output_ok (outputs : List TxOut) (payloadCommit : Bytes)
    (hCount : ¬((countDaCommitOutputs outputs).1 != 1))
    (hHash : ¬((countDaCommitOutputs outputs).2 != payloadCommit)) :
    validateCommitOutput outputs payloadCommit = .ok () := by
  simp only [validateCommitOutput, show ((countDaCommitOutputs outputs).1 != 1) = false from
    Bool.eq_false_iff.mpr hCount, ite_false, show ((countDaCommitOutputs outputs).2 != payloadCommit) = false from
    Bool.eq_false_iff.mpr hHash, ite_false]

/-! ## Chunk collection (LIVE on collectChunkPayloads) -/

/-- Zero count → result = acc, independent of map content. -/
theorem da_collect_empty (s : Std.RBMap Nat DaChunkInfo compare)
    (acc : Bytes) (start : Nat) :
    collectChunkPayloads s 0 acc start = .ok acc := rfl

/-- Zero count makes result independent of which map is passed. -/
theorem da_collect_zero_map_independent
    (s1 s2 : Std.RBMap Nat DaChunkInfo compare) (acc : Bytes) (start : Nat) :
    collectChunkPayloads s1 0 acc start = collectChunkPayloads s2 0 acc start := rfl

/-- Missing chunk at position → BLOCK_ERR_DA_INCOMPLETE. -/
theorem da_collect_missing (set : Std.RBMap Nat DaChunkInfo compare)
    (n : Nat) (acc : Bytes) (start : Nat)
    (hMiss : set.find? start = none) :
    collectChunkPayloads set (n + 1) acc start = .error "BLOCK_ERR_DA_INCOMPLETE" := by
  simp [collectChunkPayloads, hMiss]

/-- Found chunk → recurse on rest (inductive step). -/
theorem da_collect_step (set : Std.RBMap Nat DaChunkInfo compare)
    (n : Nat) (acc : Bytes) (start : Nat) (ch : DaChunkInfo)
    (hFound : set.find? start = some ch) :
    collectChunkPayloads set (n + 1) acc start =
    collectChunkPayloads set n (acc ++ ch.payload) (start + 1) := by
  simp [collectChunkPayloads, hFound]

/-! ## Orphan chunk detection (LIVE on validateNoOrphanChunks) -/

/-- Orphan chunk at head → BLOCK_ERR_DA_SET_INVALID. -/
theorem da_orphan_chunk_rejects
    (daId : Bytes) (set : Std.RBMap Nat DaChunkInfo compare)
    (rest : List (Bytes × Std.RBMap Nat DaChunkInfo compare))
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (h : commits.contains daId = false) :
    validateNoOrphanChunks ((daId, set) :: rest) commits = .error "BLOCK_ERR_DA_SET_INVALID" := by
  simp only [validateNoOrphanChunks, h, Bool.not_false, ite_true]

/-- Head chunk has commit, check rest recursively. -/
theorem da_orphan_chunk_step
    (daId : Bytes) (set : Std.RBMap Nat DaChunkInfo compare)
    (rest : List (Bytes × Std.RBMap Nat DaChunkInfo compare))
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (h : commits.contains daId = true) :
    validateNoOrphanChunks ((daId, set) :: rest) commits = validateNoOrphanChunks rest commits := by
  simp only [validateNoOrphanChunks, h, Bool.not_true, ite_false]

/-- Empty chunk list → no orphans, regardless of commits map content. -/
theorem da_orphan_chunk_empty (commits : Std.RBMap Bytes DaCommitInfo cmpBytes) :
    validateNoOrphanChunks [] commits = .ok () := rfl

/-- No orphans result is independent of commits when chunks empty. -/
theorem da_no_orphans_commits_independent
    (c1 c2 : Std.RBMap Bytes DaCommitInfo cmpBytes) :
    validateNoOrphanChunks [] c1 = validateNoOrphanChunks [] c2 := rfl


/-! ## Parse loop (LIVE on accumulateDATxs) -/

/-- Empty tx list → returns initial state unchanged. -/
theorem da_accumulate_empty
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes) :
    accumulateDATxs [] commits chunks = .ok (commits, chunks) := rfl

/-- Empty tx list preserves BOTH maps identically (state identity). -/
theorem da_accumulate_empty_state_preserved
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes) :
    (match accumulateDATxs [] commits chunks with
     | .ok (c, ch) => c = commits ∧ ch = chunks
     | .error _ => False) :=
  ⟨rfl, rfl⟩

/-- Parse failure at head → error propagates. -/
theorem da_accumulate_parse_fail
    (txBytes : Bytes) (rest : List Bytes)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (err : String) (hFail : parseDATx txBytes = .error err) :
    accumulateDATxs (txBytes :: rest) commits chunks = .error err := by
  show (match parseDATx txBytes with | .error e => _ | .ok t => _) = _
  rw [hFail]

/-- Commit tx error → propagates through accumulation. -/
theorem da_accumulate_commit_error
    (txBytes : Bytes) (rest : List Bytes)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (t : ParsedDATx) (err : String)
    (hParse : parseDATx txBytes = .ok t)
    (hKind : (t.txKind == 0x01) = true)
    (hFail : processCommitTx t commits = .error err) :
    accumulateDATxs (txBytes :: rest) commits chunks = .error err := by
  show (match parseDATx txBytes with | .error e => _ | .ok t => _) = _
  rw [hParse]
  show (if (t.txKind == 0x01) = true then _ else _) = _
  rw [hKind]; simp only [ite_true]
  show (match processCommitTx t commits with | .error e => _ | .ok nc => _) = _
  rw [hFail]

/-- Commit tx ok → recurse with updated commits. -/
theorem da_accumulate_commit_ok
    (txBytes : Bytes) (rest : List Bytes)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (t : ParsedDATx) (newCommits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (hParse : parseDATx txBytes = .ok t)
    (hKind : (t.txKind == 0x01) = true)
    (hOk : processCommitTx t commits = .ok newCommits) :
    accumulateDATxs (txBytes :: rest) commits chunks =
    accumulateDATxs rest newCommits chunks := by
  show (match parseDATx txBytes with | .error e => _ | .ok t => _) = _
  rw [hParse]
  show (if (t.txKind == 0x01) = true then _ else _) = _
  rw [hKind]; simp only [ite_true]
  show (match processCommitTx t commits with | .error e => _ | .ok nc => _) = _
  rw [hOk]

/-- Chunk tx error → propagates through accumulation. -/
theorem da_accumulate_chunk_error
    (txBytes : Bytes) (rest : List Bytes)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (t : ParsedDATx) (err : String)
    (hParse : parseDATx txBytes = .ok t)
    (hNotCommit : (t.txKind == 0x01) = false)
    (hKind : (t.txKind == 0x02) = true)
    (hFail : processChunkTx t chunks = .error err) :
    accumulateDATxs (txBytes :: rest) commits chunks = .error err := by
  show (match parseDATx txBytes with | .error e => _ | .ok t => _) = _
  rw [hParse]
  show (if (t.txKind == 0x01) = true then _ else _) = _
  rw [hNotCommit]; simp only [ite_false]
  show (if (t.txKind == 0x02) = true then _ else _) = _
  rw [hKind]; simp only [ite_true]
  show (match processChunkTx t chunks with | .error e => _ | .ok nc => _) = _
  rw [hFail]

/-- Chunk tx ok → recurse with updated chunks. -/
theorem da_accumulate_chunk_ok
    (txBytes : Bytes) (rest : List Bytes)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (t : ParsedDATx) (newChunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (hParse : parseDATx txBytes = .ok t)
    (hNotCommit : (t.txKind == 0x01) = false)
    (hKind : (t.txKind == 0x02) = true)
    (hOk : processChunkTx t chunks = .ok newChunks) :
    accumulateDATxs (txBytes :: rest) commits chunks =
    accumulateDATxs rest commits newChunks := by
  show (match parseDATx txBytes with | .error e => _ | .ok t => _) = _
  rw [hParse]
  show (if (t.txKind == 0x01) = true then _ else _) = _
  rw [hNotCommit]; simp only [ite_false]
  show (if (t.txKind == 0x02) = true then _ else _) = _
  rw [hKind]; simp only [ite_true]
  show (match processChunkTx t chunks with | .error e => _ | .ok nc => _) = _
  rw [hOk]

/-- Unknown tx kind → skip, recurse unchanged. -/
theorem da_accumulate_skip
    (txBytes : Bytes) (rest : List Bytes)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (t : ParsedDATx)
    (hParse : parseDATx txBytes = .ok t)
    (hNotCommit : (t.txKind == 0x01) = false)
    (hNotChunk : (t.txKind == 0x02) = false) :
    accumulateDATxs (txBytes :: rest) commits chunks =
    accumulateDATxs rest commits chunks := by
  show (match parseDATx txBytes with | .error e => _ | .ok t => _) = _
  rw [hParse]
  show (if (t.txKind == 0x01) = true then _ else _) = _
  rw [hNotCommit]; simp only [ite_false]
  show (if (t.txKind == 0x02) = true then _ else _) = _
  rw [hNotChunk]; simp only [ite_false]

/-! ## Witness error taxonomy (LIVE on validateWitnessErrors)

parseDATx calls validateWitnessErrors (LIVE sub-function) for non-TX_ERR_PARSE
error codes. This section proves exhaustive error taxonomy + individual rejection. -/

/-- Exhaustive: validateWitnessErrors returns one of 4 error codes or ok. -/
theorem validateWitnessErrors_taxonomy (ws : TxWeightV2.WitnessSectionResult) :
    validateWitnessErrors ws = .error "TX_ERR_WITNESS_OVERFLOW" ∨
    validateWitnessErrors ws = .error "TX_ERR_SIG_ALG_INVALID" ∨
    validateWitnessErrors ws = .error "TX_ERR_SIG_NONCANONICAL" ∨
    validateWitnessErrors ws = .ok () := by
  unfold validateWitnessErrors
  split
  · exact Or.inl rfl
  · split
    · exact Or.inl rfl
    · split
      · exact Or.inr (Or.inl rfl)
      · split
        · exact Or.inr (Or.inr (Or.inl rfl))
        · exact Or.inr (Or.inr (Or.inr rfl))

/-- Witness size overflow → TX_ERR_WITNESS_OVERFLOW. -/
theorem witness_overflow_size_rejects (ws : TxWeightV2.WitnessSectionResult)
    (h : ws.endOff - ws.startOff > TxWeightV2.MAX_WITNESS_BYTES_PER_TX) :
    validateWitnessErrors ws = .error "TX_ERR_WITNESS_OVERFLOW" := by
  simp [validateWitnessErrors, h]

/-- Witness overflow flag → TX_ERR_WITNESS_OVERFLOW. -/
theorem witness_overflow_flag_rejects (ws : TxWeightV2.WitnessSectionResult)
    (h1 : ¬(ws.endOff - ws.startOff > TxWeightV2.MAX_WITNESS_BYTES_PER_TX))
    (h2 : ws.isOverflow = true) :
    validateWitnessErrors ws = .error "TX_ERR_WITNESS_OVERFLOW" := by
  simp [validateWitnessErrors, h1, h2]

/-- Invalid signature algorithm → TX_ERR_SIG_ALG_INVALID. -/
theorem witness_sig_alg_rejects (ws : TxWeightV2.WitnessSectionResult)
    (h1 : ¬(ws.endOff - ws.startOff > TxWeightV2.MAX_WITNESS_BYTES_PER_TX))
    (h2 : ws.isOverflow = false) (h3 : ws.anySigAlgInvalid = true) :
    validateWitnessErrors ws = .error "TX_ERR_SIG_ALG_INVALID" := by
  simp [validateWitnessErrors, h1, h2, h3]

/-- Non-canonical signature → TX_ERR_SIG_NONCANONICAL. -/
theorem witness_sig_noncanonical_rejects (ws : TxWeightV2.WitnessSectionResult)
    (h1 : ¬(ws.endOff - ws.startOff > TxWeightV2.MAX_WITNESS_BYTES_PER_TX))
    (h2 : ws.isOverflow = false) (h3 : ws.anySigAlgInvalid = false)
    (h4 : ws.anySigNoncanonical = true) :
    validateWitnessErrors ws = .error "TX_ERR_SIG_NONCANONICAL" := by
  simp [validateWitnessErrors, h1, h2, h3, h4]

/-- All witness checks pass → ok. -/
theorem witness_all_ok (ws : TxWeightV2.WitnessSectionResult)
    (h1 : ¬(ws.endOff - ws.startOff > TxWeightV2.MAX_WITNESS_BYTES_PER_TX))
    (h2 : ws.isOverflow = false) (h3 : ws.anySigAlgInvalid = false)
    (h4 : ws.anySigNoncanonical = false) :
    validateWitnessErrors ws = .ok () := by
  simp [validateWitnessErrors, h1, h2, h3, h4]

/-! ## parseDATx error taxonomy (machine-checked, no compositional assumptions)

Proved via 3-phase decomposition:
- Phase 1 (parseDATxPhase1): structure parsing, only TX_ERR_PARSE
- Phase 2 (validateWitnessErrors): 4-code taxonomy (already proved above)
- Phase 3 (parseDATxPhase3): payload parsing, only TX_ERR_PARSE
- Composition: parseDATx = Phase1 >>= Phase2 >>= Phase3, taxonomy = union -/

set_option maxHeartbeats 3200000 in
/-- Phase 1 taxonomy: all errors = TX_ERR_PARSE. -/
theorem parseDATxPhase1_taxonomy (tx : Bytes) (err : String)
    (h : parseDATxPhase1 tx = .error err) : err = "TX_ERR_PARSE" := by
  unfold parseDATxPhase1 at h; simp only [] at h
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · exact absurd h (by simp)
  split at h
  next => split at h
          next => cases h; rfl
          next => exact absurd h (by simp)
  next => split at h
          next => cases h; rfl
          next => exact absurd h (by simp)

/-- Phase 3 taxonomy: all errors = TX_ERR_PARSE. -/
theorem parseDATxPhase3_taxonomy (tk daLen : Nat) (c10 : Wire.Cursor) (minDa : Bool) (txSize : Nat)
    (err : String) (h : parseDATxPhase3 tk daLen c10 minDa txSize = .error err) :
    err = "TX_ERR_PARSE" := by
  unfold parseDATxPhase3 at h
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  split at h; · cases h; rfl
  cases h

set_option maxHeartbeats 6400000 in
/-- FULL parseDATx error taxonomy: machine-checked.
    Any error from parseDATx is one of exactly 4 canonical codes. -/
theorem parseDATx_error_taxonomy (tx : Bytes) (err : String)
    (h : parseDATx tx = .error err) :
    err = "TX_ERR_PARSE" ∨
    err = "TX_ERR_WITNESS_OVERFLOW" ∨
    err = "TX_ERR_SIG_ALG_INVALID" ∨
    err = "TX_ERR_SIG_NONCANONICAL" := by
  unfold parseDATx at h
  split at h
  next e _ =>
    have := parseDATxPhase1_taxonomy tx e (by assumption)
    cases h; exact Or.inl this
  next p1 _ =>
    split at h
    next => cases h; exact Or.inl rfl
    next ws _ =>
      split at h
      next e _ =>
        cases h
        have tax := validateWitnessErrors_taxonomy ws
        rcases tax with hOv | hAlg | hNon | hOk
        · have : validateWitnessErrors ws = .error "TX_ERR_WITNESS_OVERFLOW" := hOv; simp_all
        · have : validateWitnessErrors ws = .error "TX_ERR_SIG_ALG_INVALID" := hAlg; simp_all
        · have : validateWitnessErrors ws = .error "TX_ERR_SIG_NONCANONICAL" := hNon; simp_all
        · have : validateWitnessErrors ws = .ok () := hOk; simp_all
      next =>
        split at h
        next => cases h; exact Or.inl rfl
        next _ _ =>
          split at h
          next e _ =>
            have := parseDATxPhase3_taxonomy _ _ _ _ _ e (by assumption)
            cases h; exact Or.inl this
          next => cases h

/-! ## Verify loop (LIVE on verifyCommitIntegrity) -/

/-- Empty commit list → ok, independent of chunks map content. -/
theorem da_verify_empty
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes) :
    verifyCommitIntegrity [] chunks = .ok () := rfl

/-- Verify result independent of chunks when commit list empty. -/
theorem da_verify_empty_chunks_independent
    (ch1 ch2 : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes) :
    verifyCommitIntegrity [] ch1 = verifyCommitIntegrity [] ch2 := rfl

/-- Missing chunk set for commit → BLOCK_ERR_DA_INCOMPLETE. -/
theorem da_verify_missing_set
    (daId : Bytes) (cinfo : DaCommitInfo)
    (rest : List (Bytes × DaCommitInfo))
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (hMiss : chunks.find? daId = none) :
    verifyCommitIntegrity ((daId, cinfo) :: rest) chunks = .error "BLOCK_ERR_DA_INCOMPLETE" := by
  simp [verifyCommitIntegrity, hMiss]

/-- Commit verified → recurse on rest. -/
theorem da_verify_step_ok
    (daId : Bytes) (cinfo : DaCommitInfo)
    (rest : List (Bytes × DaCommitInfo))
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (set : Std.RBMap Nat DaChunkInfo compare)
    (hFound : chunks.find? daId = some set)
    (hCount : (set.size != cinfo.chunkCount) = false)
    (concat : Bytes)
    (hCollect : collectChunkPayloads set cinfo.chunkCount = .ok concat)
    (hOutput : validateCommitOutput cinfo.outputs (SHA3.sha3_256 concat) = .ok ()) :
    verifyCommitIntegrity ((daId, cinfo) :: rest) chunks =
    verifyCommitIntegrity rest chunks := by
  show (match chunks.find? daId with | none => _ | some set => _) = _
  rw [hFound]
  show (match validateChunkCountMatch set.size cinfo.chunkCount with | .error e => _ | .ok () => _) = _
  rw [show validateChunkCountMatch set.size cinfo.chunkCount = .ok () from by
    simp only [validateChunkCountMatch, hCount, ite_false]]
  show (match collectChunkPayloads set cinfo.chunkCount with | .error e => _ | .ok concat => _) = _
  rw [hCollect]
  show (match validateCommitOutput cinfo.outputs (SHA3.sha3_256 concat) with | .error e => _ | .ok () => _) = _
  rw [hOutput]

/-! ## Full pipeline composition (LIVE on validateDASetIntegrity) -/

/-- validateDASetIntegrity on empty list → ok. -/
theorem da_integrity_empty :
    validateDASetIntegrity [] = .ok () := rfl

/-- Empty tx list passes ALL 4 stages of validateDASetIntegrity. -/
theorem da_integrity_empty_all_stages :
    validateDASetIntegrity [] = .ok () ∧
    validateDaBatchCount 0 = .ok () ∧
    validateNoOrphanChunks [] Std.RBMap.empty = .ok () ∧
    verifyCommitIntegrity [] Std.RBMap.empty = .ok () := by
  exact ⟨rfl, by simp [validateDaBatchCount, MAX_DA_BATCHES_PER_BLOCK], rfl, rfl⟩

/-! ## Top-level composition (LIVE on validateDASetIntegrity)

All 4 stages of validateDASetIntegrity proved:
accumulate → batch count → orphan check → verify integrity -/

/-- Accumulation fails → validateDASetIntegrity returns same error. -/
theorem da_integrity_accumulate_error (txs : List Bytes) (err : String)
    (hFail : accumulateDATxs txs Std.RBMap.empty Std.RBMap.empty = .error err) :
    validateDASetIntegrity txs = .error err := by
  simp only [validateDASetIntegrity, hFail]

/-- Batch count exceeded → BLOCK_ERR_DA_BATCH_EXCEEDED. -/
theorem da_integrity_batch_error (txs : List Bytes)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (hAcc : accumulateDATxs txs Std.RBMap.empty Std.RBMap.empty = .ok (commits, chunks))
    (hBatch : commits.size > MAX_DA_BATCHES_PER_BLOCK) :
    validateDASetIntegrity txs = .error "BLOCK_ERR_DA_BATCH_EXCEEDED" := by
  simp only [validateDASetIntegrity, hAcc, validateDaBatchCount, hBatch, ite_true]

/-- Orphan chunks → error propagates. -/
theorem da_integrity_orphan_error (txs : List Bytes)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (hAcc : accumulateDATxs txs Std.RBMap.empty Std.RBMap.empty = .ok (commits, chunks))
    (hBatch : ¬(commits.size > MAX_DA_BATCHES_PER_BLOCK))
    (err : String) (hOrphan : validateNoOrphanChunks chunks.toList commits = .error err) :
    validateDASetIntegrity txs = .error err := by
  simp only [validateDASetIntegrity, hAcc, validateDaBatchCount, hBatch, ite_false, hOrphan]

/-- All pre-checks pass → result = verifyCommitIntegrity. -/
theorem da_integrity_verify_result (txs : List Bytes)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    (hAcc : accumulateDATxs txs Std.RBMap.empty Std.RBMap.empty = .ok (commits, chunks))
    (hBatch : ¬(commits.size > MAX_DA_BATCHES_PER_BLOCK))
    (hOrphan : validateNoOrphanChunks chunks.toList commits = .ok ()) :
    validateDASetIntegrity txs = verifyCommitIntegrity commits.toList chunks := by
  simp only [validateDASetIntegrity, hAcc, validateDaBatchCount, hBatch, ite_false, hOrphan]

/-! ## Gate error propagation (LIVE)

validateDaIntegrityGate = validateBlockBasic >> parseBlock >> validateDASetIntegrity.
Each step's error flows deterministically to the gate output.
-/

/-- Block validation failure → gate returns same error. -/
theorem da_gate_block_error (blockBytes : Bytes) (ph pt : Option Bytes) (err : String)
    (hB : BlockBasicV1.validateBlockBasic blockBytes ph pt = .error err) :
    validateDaIntegrityGate blockBytes ph pt = .error err := by
  unfold validateDaIntegrityGate; rw [hB]; rfl

/-- Block ok + parse failure → gate returns parse error. -/
theorem da_gate_parse_error (blockBytes : Bytes) (ph pt : Option Bytes) (err : String)
    (hB : BlockBasicV1.validateBlockBasic blockBytes ph pt = .ok ())
    (hP : BlockBasicV1.parseBlock blockBytes = .error err) :
    validateDaIntegrityGate blockBytes ph pt = .error err := by
  unfold validateDaIntegrityGate; rw [hB]
  show (do let pb ← BlockBasicV1.parseBlock blockBytes; validateDASetIntegrity pb.txs) = _
  rw [hP]; rfl

/-- Block ok + parse ok + DA integrity failure → gate returns DA error. -/
theorem da_gate_integrity_error (blockBytes : Bytes) (ph pt : Option Bytes)
    (pb : BlockBasicV1.ParsedBlock) (err : String)
    (hB : BlockBasicV1.validateBlockBasic blockBytes ph pt = .ok ())
    (hP : BlockBasicV1.parseBlock blockBytes = .ok pb)
    (hD : validateDASetIntegrity pb.txs = .error err) :
    validateDaIntegrityGate blockBytes ph pt = .error err := by
  unfold validateDaIntegrityGate; rw [hB]
  show (do let pb' ← BlockBasicV1.parseBlock blockBytes; validateDASetIntegrity pb'.txs) = _
  rw [hP]; exact hD

/-- All steps ok → gate ok. -/
theorem da_gate_all_ok (blockBytes : Bytes) (ph pt : Option Bytes)
    (pb : BlockBasicV1.ParsedBlock)
    (hB : BlockBasicV1.validateBlockBasic blockBytes ph pt = .ok ())
    (hP : BlockBasicV1.parseBlock blockBytes = .ok pb)
    (hD : validateDASetIntegrity pb.txs = .ok ()) :
    validateDaIntegrityGate blockBytes ph pt = .ok () := by
  unfold validateDaIntegrityGate; rw [hB]
  show (do let pb' ← BlockBasicV1.parseBlock blockBytes; validateDASetIntegrity pb'.txs) = _
  rw [hP]; exact hD

/-! ## Gate success invariants (LIVE)

Non-trivial: gate success implies ALL sub-steps passed.
Proved by contradiction (if any sub-step failed, gate would fail). -/

/-- Gate success → block validation passed. -/
theorem da_gate_ok_implies_block_ok (blockBytes : Bytes) (ph pt : Option Bytes)
    (hOk : validateDaIntegrityGate blockBytes ph pt = .ok ()) :
    BlockBasicV1.validateBlockBasic blockBytes ph pt = .ok () := by
  cases hBB : BlockBasicV1.validateBlockBasic blockBytes ph pt with
  | ok _ => rfl
  | error e =>
    exfalso; have : validateDaIntegrityGate blockBytes ph pt = .error e := by
      unfold validateDaIntegrityGate; rw [hBB]; rfl
    simp only [this] at hOk

/-- Gate success → parse ok AND DA integrity ok. -/
theorem da_gate_ok_implies_das_ok (blockBytes : Bytes) (ph pt : Option Bytes)
    (hOk : validateDaIntegrityGate blockBytes ph pt = .ok ()) :
    ∃ pb, BlockBasicV1.parseBlock blockBytes = .ok pb ∧
          validateDASetIntegrity pb.txs = .ok () := by
  have hB := da_gate_ok_implies_block_ok blockBytes ph pt hOk
  cases hP : BlockBasicV1.parseBlock blockBytes with
  | error e =>
    exfalso; have : validateDaIntegrityGate blockBytes ph pt = .error e := by
      unfold validateDaIntegrityGate; rw [hB]
      show (do let pb ← BlockBasicV1.parseBlock blockBytes; validateDASetIntegrity pb.txs) = _
      rw [hP]; rfl
    simp only [this] at hOk
  | ok pb =>
    refine ⟨pb, rfl, ?_⟩
    unfold validateDaIntegrityGate at hOk; rw [hB] at hOk
    have hDo : (do let pb' ← BlockBasicV1.parseBlock blockBytes; validateDASetIntegrity pb'.txs) =
               validateDASetIntegrity pb.txs := by rw [hP]; rfl
    rw [hDo] at hOk; exact hOk

/-- Gate success full decomposition: block ok ∧ DA integrity ok. -/
theorem da_gate_ok_conjunction (blockBytes : Bytes) (ph pt : Option Bytes)
    (hOk : validateDaIntegrityGate blockBytes ph pt = .ok ()) :
    BlockBasicV1.validateBlockBasic blockBytes ph pt = .ok () ∧
    ∃ pb, BlockBasicV1.parseBlock blockBytes = .ok pb ∧
          validateDASetIntegrity pb.txs = .ok () :=
  ⟨da_gate_ok_implies_block_ok blockBytes ph pt hOk,
   da_gate_ok_implies_das_ok blockBytes ph pt hOk⟩

/-! ## Conformance replay (existing — referenced, not duplicated)

cv_da_integrity_vectors_pass (CVDaIntegrityReplay.lean):
Proves that ALL conformance vectors from CV-DA pass through
validateDaIntegrityGate via native_decide. Combined with error
propagation theorems, this provides refined_model evidence.
Does NOT cover BLOCK_ERR_DA_BATCH_EXCEEDED (no CV vector with >128 batches).
-/

/-! ## Universal constrained theorem (LIVE on validateDASetIntegrity)

Decomposes a successful validateDASetIntegrity call into all 4 intermediate
parse-derived stages, binding witnesses to the actual accumulateDATxs output. -/

/-- LIVE: If validateDASetIntegrity succeeds, ALL 4 stages passed with
    parse-derived witnesses. Commits and chunks are bound to accumulateDATxs
    output for the given txs — not arbitrary existentials. -/
theorem validateDASetIntegrity_ok_constrained (txs : List Bytes)
    (h : validateDASetIntegrity txs = .ok ()) :
    ∃ (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
      (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes),
      accumulateDATxs txs Std.RBMap.empty Std.RBMap.empty = .ok (commits, chunks) ∧
      ¬(commits.size > MAX_DA_BATCHES_PER_BLOCK) ∧
      validateNoOrphanChunks chunks.toList commits = .ok () ∧
      verifyCommitIntegrity commits.toList chunks = .ok () := by
  unfold validateDASetIntegrity at h
  cases hAcc : accumulateDATxs txs Std.RBMap.empty Std.RBMap.empty with
  | error e => simp [hAcc] at h
  | ok pair =>
    obtain ⟨commits, chunks⟩ := pair
    simp only [hAcc] at h
    cases hBatch : validateDaBatchCount commits.size with
    | error e => simp [hBatch] at h
    | ok u =>
      simp only [hBatch] at h
      cases hOrphan : validateNoOrphanChunks chunks.toList commits with
      | error e => simp [hOrphan] at h
      | ok u2 =>
        simp only [hOrphan] at h
        have hBatchOk : ¬(commits.size > MAX_DA_BATCHES_PER_BLOCK) := by
          unfold validateDaBatchCount at hBatch
          split at hBatch
          · exact (nomatch hBatch)
          · rename_i hle; exact hle
        exact ⟨commits, chunks, rfl, hBatchOk, hOrphan, h⟩

end RubinFormal

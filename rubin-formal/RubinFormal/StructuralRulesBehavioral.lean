import RubinFormal.BytesEqLemmas
import RubinFormal.UtxoApplyGenesisV1

/-!
# Transaction Structural Rules Behavioral Proofs (§16)

Legacy pre-rotation helper-backed theorems on `validateWitnessItemLengths` and
`validateThresholdSigSpendNoCrypto`, plus registry companion theorems that
rebind the spend-side claim surface to the suite-aware helper layer.

File role:
- legacy pre-rotation theorem bundle plus companion rebind layer
- not the authoritative universal live layer for post-rotation spend-side
  semantics
- retained to keep historical scope explicit while the claim surface points at
  the suite-aware companions instead of the hardcoded helpers

## Coverage summary
- R1-R14 legacy pre-rotation helper-backed spend-side properties
- registry companions on the universal helper layer for the same spend-side
  properties
- Concrete examples retained as regression tests.
-/

namespace RubinFormal

open UtxoBasicV1

/-! ## Concrete regression tests -/

/-- Concrete: unknown suite ID 0x05 is rejected. -/
theorem unknown_suite_0x05_rejected :
    UtxoApplyGenesisV1.validateWitnessItemLengths ⟨0x05, ByteArray.empty, ByteArray.empty⟩ 0 =
    .error "TX_ERR_SIG_ALG_INVALID" := by rfl

/-- Concrete: sentinel with non-empty pubkey is rejected. -/
theorem sentinel_nonempty_pubkey_rejected :
    UtxoApplyGenesisV1.validateWitnessItemLengths
      ⟨RubinFormal.SUITE_ID_SENTINEL, ⟨#[0x01]⟩, ByteArray.empty⟩ 0 =
    .error "TX_ERR_PARSE" := by rfl

/-- Concrete: sentinel with empty pubkey+sig is accepted. -/
theorem sentinel_empty_accepted :
    UtxoApplyGenesisV1.validateWitnessItemLengths
      ⟨RubinFormal.SUITE_ID_SENTINEL, ByteArray.empty, ByteArray.empty⟩ 0 =
    .ok () := by rfl

/-! ## R1: Unknown suite — legacy pre-rotation rejection -/

/-- **R1 (legacy pre-rotation):** Any suite ID ∉ {SENTINEL, ML_DSA_87} is
    rejected with TX_ERR_SIG_ALG_INVALID by the hardcoded live
    `validateWitnessItemLengths` path. -/
theorem unknown_suite_rejected_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hNotS : w.suiteId ≠ RubinFormal.SUITE_ID_SENTINEL)
    (hNotM : w.suiteId ≠ UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) :
    UtxoApplyGenesisV1.validateWitnessItemLengths w h = .error "TX_ERR_SIG_ALG_INVALID" := by
  have hS : w.suiteId ≠ 0 := by
    simp [RubinFormal.SUITE_ID_SENTINEL] at hNotS; exact hNotS
  have hM : w.suiteId ≠ 1 := by
    simp [UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87, CovenantGenesisV1.SUITE_ID_ML_DSA_87] at hNotM; exact hNotM
  simp only [UtxoApplyGenesisV1.validateWitnessItemLengths,
    RubinFormal.SUITE_ID_SENTINEL, UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87,
    CovenantGenesisV1.SUITE_ID_ML_DSA_87]
  simp [hS, hM]; rfl

/-! ## R2: Sentinel — legacy pre-rotation non-empty rejection -/

/-- **R2 (legacy pre-rotation):** Sentinel with non-empty pubkey or sig is
    rejected with TX_ERR_PARSE by the hardcoded live
    `validateWitnessItemLengths` path. -/
theorem sentinel_nonempty_rejected_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hS : w.suiteId = RubinFormal.SUITE_ID_SENTINEL)
    (hNE : w.pubkey.size ≠ 0 ∨ w.signature.size ≠ 0) :
    UtxoApplyGenesisV1.validateWitnessItemLengths w h = .error "TX_ERR_PARSE" := by
  simp only [UtxoApplyGenesisV1.validateWitnessItemLengths,
    RubinFormal.SUITE_ID_SENTINEL] at *
  simp only [hS, beq_self_eq_true, ite_true]
  rcases hNE with hp | hs
  · simp [bne_iff_ne, hp, Bool.true_or]; rfl
  · simp [bne_iff_ne, hs, Bool.or_true]; rfl

/-! ## R3: Sentinel — legacy pre-rotation empty acceptance -/

/-- **R3 (legacy pre-rotation):** Sentinel with both empty is accepted by the
    hardcoded live `validateWitnessItemLengths` path. -/
theorem sentinel_empty_accepted_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hS : w.suiteId = RubinFormal.SUITE_ID_SENTINEL)
    (hPE : w.pubkey.size = 0)
    (hSE : w.signature.size = 0) :
    UtxoApplyGenesisV1.validateWitnessItemLengths w h = .ok () := by
  simp only [UtxoApplyGenesisV1.validateWitnessItemLengths,
    RubinFormal.SUITE_ID_SENTINEL] at *
  simp only [hS, beq_self_eq_true, ite_true]
  simp [bne_iff_ne, hPE, hSE]; rfl

/-! ## R4: ML-DSA-87 — legacy pre-rotation wrong pubkey rejection -/

/-- **R4 (legacy pre-rotation):** ML-DSA-87 with wrong pubkey size is
    rejected by the hardcoded live `validateWitnessItemLengths` path. -/
theorem mldsa87_wrong_pubkey_rejected_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hM : w.suiteId = UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87)
    (hBad : w.pubkey.size ≠ UtxoApplyGenesisV1.ML_DSA_87_PUBKEY_BYTES) :
    UtxoApplyGenesisV1.validateWitnessItemLengths w h = .error "TX_ERR_SIG_NONCANONICAL" := by
  simp only [UtxoApplyGenesisV1.validateWitnessItemLengths,
    RubinFormal.SUITE_ID_SENTINEL, UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87,
    UtxoApplyGenesisV1.ML_DSA_87_PUBKEY_BYTES, UtxoApplyGenesisV1.ML_DSA_87_SIG_BYTES,
    CovenantGenesisV1.SUITE_ID_ML_DSA_87] at *
  simp [show w.suiteId ≠ 0 from by omega, hM, bne_iff_ne, hBad, Bool.true_or]; rfl

/-! ## R5: ML-DSA-87 — legacy pre-rotation sig bounds rejection -/

/-- **R5a (legacy pre-rotation):** ML-DSA-87 with empty sig is rejected by
    the hardcoded live `validateWitnessItemLengths` path. -/
theorem mldsa87_empty_sig_rejected_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hM : w.suiteId = UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87)
    (hPOk : w.pubkey.size = UtxoApplyGenesisV1.ML_DSA_87_PUBKEY_BYTES)
    (hSig0 : w.signature.size = 0) :
    UtxoApplyGenesisV1.validateWitnessItemLengths w h = .error "TX_ERR_SIG_NONCANONICAL" := by
  simp only [UtxoApplyGenesisV1.validateWitnessItemLengths,
    RubinFormal.SUITE_ID_SENTINEL, UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87,
    UtxoApplyGenesisV1.ML_DSA_87_PUBKEY_BYTES, UtxoApplyGenesisV1.ML_DSA_87_SIG_BYTES,
    CovenantGenesisV1.SUITE_ID_ML_DSA_87] at *
  simp [show w.suiteId ≠ 0 from by omega, hM, bne_iff_ne, hPOk, hSig0]; rfl

/-- **R5b (legacy pre-rotation):** ML-DSA-87 with sig too large is rejected
    by the hardcoded live `validateWitnessItemLengths` path. -/
theorem mldsa87_sig_too_large_rejected_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hM : w.suiteId = UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87)
    (hPOk : w.pubkey.size = UtxoApplyGenesisV1.ML_DSA_87_PUBKEY_BYTES)
    (hBig : w.signature.size > UtxoApplyGenesisV1.ML_DSA_87_SIG_BYTES + 1) :
    UtxoApplyGenesisV1.validateWitnessItemLengths w h = .error "TX_ERR_SIG_NONCANONICAL" := by
  simp only [UtxoApplyGenesisV1.validateWitnessItemLengths,
    RubinFormal.SUITE_ID_SENTINEL, UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87,
    UtxoApplyGenesisV1.ML_DSA_87_PUBKEY_BYTES, UtxoApplyGenesisV1.ML_DSA_87_SIG_BYTES,
    CovenantGenesisV1.SUITE_ID_ML_DSA_87] at *
  simp [show w.suiteId ≠ 0 from by omega, hM]
  split
  · rfl
  · exfalso; rename_i hf; simp only [bne_iff_ne, hPOk, not_true_eq_false, Bool.false_or,
      Bool.or_eq_true, decide_eq_true_eq] at hf; omega

/-! ## R7: Threshold sig spend — legacy pre-rotation wrong count rejection -/

/-- **R7 (legacy pre-rotation):** Wrong witness count in threshold spend is
    rejected with TX_ERR_PARSE by the hardcoded live
    `validateThresholdSigSpendNoCrypto` path. -/
theorem threshold_wrong_count_rejected_pre_rotation
    (keys : List Bytes) (threshold : Nat)
    (ws : List WitnessItem) (h : Nat) (ctx : String)
    (hMismatch : ws.length ≠ keys.length) :
    UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto keys threshold ws h ctx =
    .error "TX_ERR_PARSE" := by
  unfold UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto
  simp [hMismatch]; rfl

/-! ## R8: Threshold sig spend — legacy pre-rotation unknown suite rejection -/

/-- **R8a (legacy pre-rotation):** If the first witness in a threshold spend
    has unknown suite, the hardcoded live path rejects with
    TX_ERR_SIG_ALG_INVALID — regardless of list length, key content,
    threshold, or block height. -/
theorem threshold_unknown_suite_head_rejected_pre_rotation
    (k : Bytes) (krest : List Bytes) (w : WitnessItem) (wrest : List WitnessItem)
    (h : Nat) (ctx : String) (threshold : Nat)
    (hLen : (w :: wrest).length = (k :: krest).length)
    (hNotS : w.suiteId ≠ RubinFormal.SUITE_ID_SENTINEL)
    (hNotM : w.suiteId ≠ UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) :
    UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto (k :: krest) threshold (w :: wrest) h ctx =
    .error "TX_ERR_SIG_ALG_INVALID" := by
  simp only [UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto,
    RubinFormal.SUITE_ID_SENTINEL, UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87,
    CovenantGenesisV1.SUITE_ID_ML_DSA_87] at *
  have hLen' : wrest.length = krest.length := by simp [List.length] at hLen; omega
  simp [hLen', hNotS, hNotM]
  show Except.error "TX_ERR_SIG_ALG_INVALID" = Except.error "TX_ERR_SIG_ALG_INVALID"; rfl

/-! ## forIn.loop infrastructure for threshold loop induction -/

/-- forIn.loop on cons where body yields → recurse on tail. -/
private theorem forIn_loop_yield {α β : Type}
    {body : α → β → Except String (ForInStep β)}
    {a : α} {as : List α} {b b' : β}
    (hYield : body a b = .ok (.yield b')) :
    List.forIn.loop body (a :: as) b = List.forIn.loop body as b' := by
  show body a b >>= _ = _; rw [hYield]; rfl

/-- forIn.loop on cons where body errors → error propagates. -/
private theorem forIn_loop_error {α β : Type}
    {body : α → β → Except String (ForInStep β)}
    {a : α} {as : List α} {b : β} {e : String}
    (hErr : body a b = .error e) :
    List.forIn.loop body (a :: as) b = (Except.error e : Except String β) := by
  show body a b >>= _ = _; rw [hErr]; rfl

/-- **First-error-wins for forIn on List+Except:** if all elements in `safe`
    prefix yield, and `bad` element errors, the whole forIn returns that error.
    Proved by induction on the prefix list. -/
theorem forIn_loop_safe_then_error
    {body : (WitnessItem × Bytes) → Nat → Except String (ForInStep Nat)}
    (safe : List (WitnessItem × Bytes))
    (bad : WitnessItem × Bytes)
    (rest : List (WitnessItem × Bytes))
    (init : Nat)
    (err : String)
    (hSafe : ∀ (p : WitnessItem × Bytes) (acc : Nat), p ∈ safe →
      ∃ acc', body p acc = .ok (.yield acc'))
    (hBad : ∀ acc, body bad acc = .error err) :
    List.forIn.loop body (safe ++ bad :: rest) init =
    (Except.error err : Except String Nat) := by
  induction safe generalizing init with
  | nil => simp; exact forIn_loop_error (hBad init)
  | cons p ps ih =>
    simp only [List.cons_append]
    have ⟨acc', hYield⟩ := hSafe p init (List.mem_cons_self _ _)
    rw [forIn_loop_yield hYield]
    exact ih acc' (fun q acc hq => hSafe q acc (List.mem_cons_of_mem _ hq))

private def thresholdPairSafe (x : WitnessItem × Bytes) : Prop :=
  x.fst.suiteId = RubinFormal.SUITE_ID_SENTINEL ∨
    (x.fst.suiteId = UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 ∧
      SHA3.sha3_256 x.fst.pubkey = x.snd)

private def thresholdPairUnknownSuite (x : WitnessItem × Bytes) : Prop :=
  x.fst.suiteId ≠ RubinFormal.SUITE_ID_SENTINEL ∧
    x.fst.suiteId ≠ UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87

private def thresholdPairMismatch (x : WitnessItem × Bytes) : Prop :=
  x.fst.suiteId = UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 ∧
    SHA3.sha3_256 x.fst.pubkey ≠ x.snd

private def thresholdBody
    (x : WitnessItem × Bytes) (r : Nat) : Except String (ForInStep Nat) :=
  if x.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL then
    pure (.yield r)
  else if x.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 then
    if SHA3.sha3_256 x.fst.pubkey != x.snd then do
      throw "TX_ERR_SIG_INVALID"
      pure (.yield (r + 1))
    else
      pure (.yield (r + 1))
  else do
    throw "TX_ERR_SIG_ALG_INVALID"
    pure (.yield r)

private theorem thresholdForIn_eq_live (keys : List Bytes) (ws : List WitnessItem) :
    List.forIn (List.zip ws keys) 0
      (fun x r =>
        if x.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL then
          pure (.yield r)
        else if x.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 then
          if SHA3.sha3_256 x.fst.pubkey != x.snd then do
            throw "TX_ERR_SIG_INVALID"
            pure (.yield (r + 1))
          else
            pure (.yield (r + 1))
        else do
          throw "TX_ERR_SIG_ALG_INVALID"
          pure (.yield r))
      = List.forIn (List.zip ws keys) 0 thresholdBody := by
  apply congrArg (fun f => List.forIn (List.zip ws keys) 0 f)
  funext x r
  rfl

set_option maxHeartbeats 1000000 in
private theorem thresholdBody_safe_yield (x : WitnessItem × Bytes) (r : Nat)
    (hSafe : thresholdPairSafe x) :
    ∃ r', thresholdBody x r = .ok (.yield r') := by
  rcases hSafe with hS | ⟨hM, hHash⟩
  · refine ⟨r, ?_⟩
    have hSTrue : (x.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL) = true := by
      simp [hS]
    rw [thresholdBody]
    simp [hSTrue]
    change (Except.ok (ForInStep.yield r) : Except String (ForInStep Nat)) =
      Except.ok (ForInStep.yield r)
    rfl
  · refine ⟨r + 1, ?_⟩
    have hSentNe : x.fst.suiteId ≠ RubinFormal.SUITE_ID_SENTINEL := by
      rw [hM]
      native_decide
    have hSentFalse : (x.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL) = false := by
      simp [hSentNe]
    have hMTrue : (x.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = true := by
      simp [hM]
    have hHashFalse : (SHA3.sha3_256 x.fst.pubkey != x.snd) = false := by
      rw [hHash]
      exact bytes_bne_self_false x.snd
    rw [thresholdBody]
    simp [hSentFalse, hMTrue, hHashFalse, Except.bind]
    change (Except.ok (ForInStep.yield (r + 1)) : Except String (ForInStep Nat)) =
      Except.ok (ForInStep.yield (r + 1))
    rfl

private def thresholdPairIncrement (x : WitnessItem × Bytes) : Nat :=
  if x.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 then 1 else 0

private def thresholdSafeCount : List (WitnessItem × Bytes) → Nat
  | [] => 0
  | x :: xs => thresholdPairIncrement x + thresholdSafeCount xs

private theorem thresholdBody_safe_yield_exact (x : WitnessItem × Bytes) (r : Nat)
    (hSafe : thresholdPairSafe x) :
    thresholdBody x r = .ok (.yield (r + thresholdPairIncrement x)) := by
  rcases hSafe with hS | ⟨hM, hHash⟩
  · have hSTrue : (x.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL) = true := by
      simp [hS]
    have hMFalse : (x.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = false := by
      rw [hS]
      native_decide
    rw [thresholdBody]
    simp [hSTrue, hMFalse, thresholdPairIncrement]
    change (Except.ok (ForInStep.yield r) : Except String (ForInStep Nat)) =
      Except.ok (ForInStep.yield r)
    rfl
  · have hSentNe : x.fst.suiteId ≠ RubinFormal.SUITE_ID_SENTINEL := by
      rw [hM]
      native_decide
    have hSentFalse : (x.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL) = false := by
      simp [hSentNe]
    have hMTrue : (x.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = true := by
      simp [hM]
    have hHashFalse : (SHA3.sha3_256 x.fst.pubkey != x.snd) = false := by
      rw [hHash]
      exact bytes_bne_self_false x.snd
    rw [thresholdBody]
    simp [hSentFalse, hMTrue, hHashFalse, thresholdPairIncrement, Except.bind]
    change (Except.ok (ForInStep.yield (r + 1)) : Except String (ForInStep Nat)) =
      Except.ok (ForInStep.yield (r + 1))
    rfl

private theorem forIn_loop_all_safe_counts
    (safe : List (WitnessItem × Bytes))
    (init : Nat)
    (hSafe : ∀ p ∈ safe, thresholdPairSafe p) :
    List.forIn.loop thresholdBody safe init = Except.ok (init + thresholdSafeCount safe) := by
  induction safe generalizing init with
  | nil =>
      change (Except.ok init : Except String Nat) =
        Except.ok (init + thresholdSafeCount [])
      simp [thresholdSafeCount]
  | cons p ps ih =>
      have hYield : thresholdBody p init = .ok (.yield (init + thresholdPairIncrement p)) := by
        exact thresholdBody_safe_yield_exact p init (hSafe p (List.mem_cons_self _ _))
      rw [forIn_loop_yield hYield]
      have hRest :
          List.forIn.loop thresholdBody ps (init + thresholdPairIncrement p) =
            Except.ok ((init + thresholdPairIncrement p) + thresholdSafeCount ps) := by
        exact ih (init + thresholdPairIncrement p)
          (fun q hq => hSafe q (List.mem_cons_of_mem _ hq))
      rw [hRest]
      simp [thresholdSafeCount, Nat.add_assoc]

private theorem thresholdBody_unknown_suite_error
    (bad : WitnessItem × Bytes) (acc : Nat)
    (hBad : thresholdPairUnknownSuite bad) :
    thresholdBody bad acc = .error "TX_ERR_SIG_ALG_INVALID" := by
  have hNotS : bad.fst.suiteId ≠ RubinFormal.SUITE_ID_SENTINEL := hBad.1
  have hNotM : bad.fst.suiteId ≠ UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 := hBad.2
  have hSentFalse : (bad.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL) = false := by
    simp [hNotS]
  have hMFalse : (bad.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = false := by
    simp [hNotM]
  rw [thresholdBody]
  simp [hSentFalse, hMFalse, Except.bind]
  change (Except.error "TX_ERR_SIG_ALG_INVALID" : Except String (ForInStep Nat)) =
    Except.error "TX_ERR_SIG_ALG_INVALID"
  rfl

private theorem thresholdBody_mismatch_error
    (bad : WitnessItem × Bytes) (acc : Nat)
    (hBad : thresholdPairMismatch bad) :
    thresholdBody bad acc = .error "TX_ERR_SIG_INVALID" := by
  have hM : bad.fst.suiteId = UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 := hBad.1
  have hSentNe : bad.fst.suiteId ≠ RubinFormal.SUITE_ID_SENTINEL := by
    rw [hM]
    native_decide
  have hSentFalse : (bad.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL) = false := by
    simp [hSentNe]
  have hMTrue : (bad.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) = true := by
    simp [hM]
  have hHashTrue : (SHA3.sha3_256 bad.fst.pubkey != bad.snd) = true := by
    cases hCmp : (SHA3.sha3_256 bad.fst.pubkey != bad.snd)
    · exfalso
      have : SHA3.sha3_256 bad.fst.pubkey = bad.snd := by
        exact bytes_bne_false_eq _ _ hCmp
      exact hBad.2 this
    · rfl
  rw [thresholdBody]
  simp [hSentFalse, hMTrue, hHashTrue, Except.bind]
  change (Except.error "TX_ERR_SIG_INVALID" : Except String (ForInStep Nat)) =
    Except.error "TX_ERR_SIG_INVALID"
  rfl

/-- **R8b (legacy pre-rotation):** Any unknown suite appearing anywhere in the
    threshold witness/key zip causes the hardcoded live threshold dispatch to
    reject with TX_ERR_SIG_ALG_INVALID. Earlier safe prefix items may yield,
    but they cannot suppress the first unknown-suite error. -/
theorem threshold_unknown_suite_anywhere_rejected_pre_rotation
    (keys : List Bytes) (threshold : Nat)
    (ws : List WitnessItem) (h : Nat) (ctx : String)
    (safe : List (WitnessItem × Bytes))
    (bad : WitnessItem × Bytes)
    (rest : List (WitnessItem × Bytes))
    (hLen : ws.length = keys.length)
    (hZip : List.zip ws keys = safe ++ bad :: rest)
    (hSafe : ∀ p ∈ safe, thresholdPairSafe p)
    (hBad : thresholdPairUnknownSuite bad) :
    UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto keys threshold ws h ctx =
    .error "TX_ERR_SIG_ALG_INVALID" := by
  have hLenFalse : (ws.length != keys.length) = false := by
    simp [hLen]
  have hLoop : List.forIn.loop thresholdBody (safe ++ bad :: rest) 0 =
      (Except.error "TX_ERR_SIG_ALG_INVALID" : Except String Nat) := by
    apply forIn_loop_safe_then_error
      (safe := safe) (bad := bad) (rest := rest) (init := 0) (err := "TX_ERR_SIG_ALG_INVALID")
    · intro p acc hp
      exact thresholdBody_safe_yield p acc (hSafe p hp)
    · intro acc
      exact thresholdBody_unknown_suite_error bad acc hBad
  simp [UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto, hLenFalse, Except.bind]
  have hFinal :
      (do
        let r ← List.forIn (List.zip ws keys) 0
          (fun x r =>
            if x.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL then
              pure (.yield r)
            else if x.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 then
              if SHA3.sha3_256 x.fst.pubkey != x.snd then do
                throw "TX_ERR_SIG_INVALID"
                pure (.yield (r + 1))
              else
                pure (.yield (r + 1))
            else do
              throw "TX_ERR_SIG_ALG_INVALID"
              pure (.yield r))
        if r < threshold then
          throw "TX_ERR_SIG_INVALID"
        else
          pure ()) = Except.error "TX_ERR_SIG_ALG_INVALID" := by
    rw [thresholdForIn_eq_live]
    rw [hZip]
    simp [List.forIn, hLoop, Except.bind]
    rfl
  simpa using hFinal

/-- **R9 (legacy pre-rotation):** Any ML-DSA-87/key mismatch appearing
    anywhere in the threshold witness/key zip causes the hardcoded live
    threshold dispatch to reject with TX_ERR_SIG_INVALID. Earlier safe prefix
    items may yield, but they cannot suppress the first mismatch error. -/
theorem threshold_hash_mismatch_anywhere_rejected_pre_rotation
    (keys : List Bytes) (threshold : Nat)
    (ws : List WitnessItem) (h : Nat) (ctx : String)
    (safe : List (WitnessItem × Bytes))
    (bad : WitnessItem × Bytes)
    (rest : List (WitnessItem × Bytes))
    (hLen : ws.length = keys.length)
    (hZip : List.zip ws keys = safe ++ bad :: rest)
    (hSafe : ∀ p ∈ safe, thresholdPairSafe p)
    (hBad : thresholdPairMismatch bad) :
    UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto keys threshold ws h ctx =
    .error "TX_ERR_SIG_INVALID" := by
  have hLenFalse : (ws.length != keys.length) = false := by
    simp [hLen]
  have hLoop : List.forIn.loop thresholdBody (safe ++ bad :: rest) 0 =
      (Except.error "TX_ERR_SIG_INVALID" : Except String Nat) := by
    apply forIn_loop_safe_then_error
      (safe := safe) (bad := bad) (rest := rest) (init := 0) (err := "TX_ERR_SIG_INVALID")
    · intro p acc hp
      exact thresholdBody_safe_yield p acc (hSafe p hp)
    · intro acc
      exact thresholdBody_mismatch_error bad acc hBad
  simp [UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto, hLenFalse, Except.bind]
  have hFinal :
      (do
        let r ← List.forIn (List.zip ws keys) 0
          (fun x r =>
            if x.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL then
              pure (.yield r)
            else if x.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 then
              if SHA3.sha3_256 x.fst.pubkey != x.snd then do
                throw "TX_ERR_SIG_INVALID"
                pure (.yield (r + 1))
              else
                pure (.yield (r + 1))
            else do
              throw "TX_ERR_SIG_ALG_INVALID"
              pure (.yield r))
        if r < threshold then
          throw "TX_ERR_SIG_INVALID"
        else
          pure ()) = Except.error "TX_ERR_SIG_INVALID" := by
    rw [thresholdForIn_eq_live]
    rw [hZip]
    simp [List.forIn, hLoop, Except.bind]
    rfl
  simpa using hFinal

/-- **R10 (legacy pre-rotation):** If every threshold witness/key pair is
    structurally safe but the accumulated number of ML-DSA-87 matches stays
    below `threshold`, the hardcoded live validator rejects with
    `TX_ERR_SIG_INVALID`. -/
theorem threshold_below_required_count_rejected_pre_rotation
    (keys : List Bytes) (threshold : Nat)
    (ws : List WitnessItem) (h : Nat) (ctx : String)
    (hLen : ws.length = keys.length)
    (hSafe : ∀ p ∈ List.zip ws keys, thresholdPairSafe p)
    (hBelow : thresholdSafeCount (List.zip ws keys) < threshold) :
    UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto keys threshold ws h ctx =
    .error "TX_ERR_SIG_INVALID" := by
  have hLenFalse : (ws.length != keys.length) = false := by
    simp [hLen]
  have hLoop :
      List.forIn.loop thresholdBody (List.zip ws keys) 0 =
        Except.ok (thresholdSafeCount (List.zip ws keys)) := by
    simpa using forIn_loop_all_safe_counts (safe := List.zip ws keys) (init := 0) hSafe
  simp [UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto, hLenFalse, Except.bind]
  have hFinal :
      (do
        let r ← List.forIn (List.zip ws keys) 0
          (fun x r =>
            if x.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL then
              pure (.yield r)
            else if x.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 then
              if SHA3.sha3_256 x.fst.pubkey != x.snd then do
                throw "TX_ERR_SIG_INVALID"
                pure (.yield (r + 1))
              else
                pure (.yield (r + 1))
            else do
              throw "TX_ERR_SIG_ALG_INVALID"
              pure (.yield r))
        if r < threshold then
          throw "TX_ERR_SIG_INVALID"
        else
          pure ()) = Except.error "TX_ERR_SIG_INVALID" := by
    rw [thresholdForIn_eq_live]
    simp [List.forIn]
    rw [hLoop]
    change
      (if thresholdSafeCount (List.zip ws keys) < threshold then
        Except.error "TX_ERR_SIG_INVALID"
      else
        Except.ok ()) = Except.error "TX_ERR_SIG_INVALID"
    simp [Except.bind, hBelow]
  simpa using hFinal

/-- **R11 (legacy pre-rotation):** If every threshold witness/key pair is
    structurally safe and the accumulated number of ML-DSA-87 matches reaches
    `threshold`, the hardcoded live validator accepts. -/
theorem threshold_required_count_accepts_pre_rotation
    (keys : List Bytes) (threshold : Nat)
    (ws : List WitnessItem) (h : Nat) (ctx : String)
    (hLen : ws.length = keys.length)
    (hSafe : ∀ p ∈ List.zip ws keys, thresholdPairSafe p)
    (hEnough : threshold ≤ thresholdSafeCount (List.zip ws keys)) :
    UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto keys threshold ws h ctx =
    .ok () := by
  have hLenFalse : (ws.length != keys.length) = false := by
    simp [hLen]
  have hLoop :
      List.forIn.loop thresholdBody (List.zip ws keys) 0 =
        Except.ok (thresholdSafeCount (List.zip ws keys)) := by
    simpa using forIn_loop_all_safe_counts (safe := List.zip ws keys) (init := 0) hSafe
  have hNotBelow : ¬ thresholdSafeCount (List.zip ws keys) < threshold := by
    exact Nat.not_lt_of_ge hEnough
  simp [UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto, hLenFalse, Except.bind]
  have hFinal :
      (do
        let r ← List.forIn (List.zip ws keys) 0
          (fun x r =>
            if x.fst.suiteId == RubinFormal.SUITE_ID_SENTINEL then
              pure (.yield r)
            else if x.fst.suiteId == UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87 then
              if SHA3.sha3_256 x.fst.pubkey != x.snd then do
                throw "TX_ERR_SIG_INVALID"
                pure (.yield (r + 1))
              else
                pure (.yield (r + 1))
            else do
              throw "TX_ERR_SIG_ALG_INVALID"
              pure (.yield r))
        if r < threshold then
          throw "TX_ERR_SIG_INVALID"
        else
          pure ()) = Except.ok () := by
    rw [thresholdForIn_eq_live]
    simp [List.forIn]
    rw [hLoop]
    change
      (if thresholdSafeCount (List.zip ws keys) < threshold then
        Except.error "TX_ERR_SIG_INVALID"
      else
        Except.ok ()) = Except.ok ()
    simp [Except.bind, hNotBelow]
  simpa using hFinal

/-- **R12 (legacy pre-rotation):** When vault sponsor checks pass, any
    threshold hash mismatch anywhere propagates through the hardcoded live
    `validateVaultSpend` path as `TX_ERR_SIG_INVALID`. -/
theorem vault_threshold_hash_mismatch_anywhere_rejected_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (safe : List (WitnessItem × Bytes))
    (bad : WitnessItem × Bytes)
    (rest : List (WitnessItem × Bytes))
    (hSponsorOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hLen : vWit.length = vKeys.length)
    (hZip : List.zip vWit vKeys = safe ++ bad :: rest)
    (hSafe : ∀ p ∈ safe, thresholdPairSafe p)
    (hBad : thresholdPairMismatch bad) :
    UtxoApplyGenesisV1.validateVaultSpend true lids covs vOwnLid vKeys vThr vWit h outs wl =
      .error "TX_ERR_SIG_INVALID" := by
  have hSig :
      UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto vKeys vThr vWit h "CORE_VAULT" =
        .error "TX_ERR_SIG_INVALID" := by
    exact threshold_hash_mismatch_anywhere_rejected_pre_rotation
      vKeys vThr vWit h "CORE_VAULT" safe bad rest hLen hZip hSafe hBad
  simp [UtxoApplyGenesisV1.validateVaultSpend, hSponsorOk, hSig]

/-- **R13 (legacy pre-rotation):** When vault sponsor checks pass and the
    zipped threshold witness/key loop stays structurally safe but below
    threshold, the hardcoded live `validateVaultSpend` path rejects with
    `TX_ERR_SIG_INVALID`. -/
theorem vault_threshold_below_required_count_rejected_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (hSponsorOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hLen : vWit.length = vKeys.length)
    (hSafe : ∀ p ∈ List.zip vWit vKeys, thresholdPairSafe p)
    (hBelow : thresholdSafeCount (List.zip vWit vKeys) < vThr) :
    UtxoApplyGenesisV1.validateVaultSpend true lids covs vOwnLid vKeys vThr vWit h outs wl =
      .error "TX_ERR_SIG_INVALID" := by
  have hSig :
      UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto vKeys vThr vWit h "CORE_VAULT" =
        .error "TX_ERR_SIG_INVALID" := by
    exact threshold_below_required_count_rejected_pre_rotation
      vKeys vThr vWit h "CORE_VAULT" hLen hSafe hBelow
  simp [UtxoApplyGenesisV1.validateVaultSpend, hSponsorOk, hSig]

/-- **R14 (legacy pre-rotation):** When vault sponsor checks pass, the
    threshold witness/key loop is structurally safe, enough ML-DSA-87 items
    match, and the whitelist passes, the hardcoded live `validateVaultSpend`
    path accepts. -/
theorem vault_threshold_required_count_accepts_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (hSponsorOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hLen : vWit.length = vKeys.length)
    (hSafe : ∀ p ∈ List.zip vWit vKeys, thresholdPairSafe p)
    (hEnough : vThr ≤ thresholdSafeCount (List.zip vWit vKeys))
    (hWL : UtxoApplyGenesisV1.vaultSpendOutputsAllowed wl outs = true) :
    UtxoApplyGenesisV1.validateVaultSpend true lids covs vOwnLid vKeys vThr vWit h outs wl =
      .ok () := by
  have hSig :
      UtxoApplyGenesisV1.validateThresholdSigSpendNoCrypto vKeys vThr vWit h "CORE_VAULT" =
        .ok () := by
    exact threshold_required_count_accepts_pre_rotation
      vKeys vThr vWit h "CORE_VAULT" hLen hSafe hEnough
  exact UtxoApplyGenesisV1.vault_all_pass lids covs vOwnLid vKeys vThr vWit h outs wl
    hSponsorOk hSig hWL

/-! ## Wave A3 Registry companions — rebind spend-side theorem surface to
    universal helper layer

    **Q-FORMAL-SPEND-COVENANT-FAMILY-REBIND-01** (issue #427).

    Companion theorems that prove the same behavioural properties as R1-R14
    above, but against the **universal helper layer** introduced in Wave A1
    (`validateWitnessItemLengthsRegistry`) and Wave A2
    (`validateThresholdSigSpendRegistry`) at the `PRE_ROTATION_REGISTRY`
    instance. Each companion is trivially derived from its legacy counterpart
    via the corresponding bridge theorem
    (`validateWitnessItemLengths_eq_registry_pre_rotation` /
    `validateThresholdSigSpend_eq_registry_pre_rotation`).

    **Why:** the legacy theorems above prove statements about
    `validateWitnessItemLengths` / `validateThresholdSigSpendNoCrypto`, which
    are the pre-rotation hardcoded ML-DSA-87 functions. Per Wave A3 discipline,
    the §16 spend-side covenant theorem surface must honestly sit on the
    suite-aware helper layer — these companions provide that grounding.

    **Class:** all companions are **BRIDGE** per rubin-formal-executor
    classification. Each transfers a property from legacy to the universal
    Registry helper via the A1/A2/A3 bridge chain.

    **Limitations:** valid only on `PRE_ROTATION_REGISTRY` instance. Post-
    rotation registries with additional suites are not covered — that's
    Wave A4+/F scope. -/

/-! ### R1-R5 Witness item lengths — registry companions -/

/-- **R1 registry companion:** Any suite ID ∉ {SENTINEL, ML_DSA_87} is
    rejected by `validateWitnessItemLengthsRegistry PRE_ROTATION_REGISTRY`
    with TX_ERR_SIG_ALG_INVALID. BRIDGE to `unknown_suite_rejected_pre_rotation`
    via `validateWitnessItemLengths_eq_registry_pre_rotation`. -/
theorem unknown_suite_rejected_registry_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hNotS : w.suiteId ≠ RubinFormal.SUITE_ID_SENTINEL)
    (hNotM : w.suiteId ≠ UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) :
    UtxoApplyGenesisV1.validateWitnessItemLengthsRegistry
        Rotation.PRE_ROTATION_REGISTRY w h =
      .error "TX_ERR_SIG_ALG_INVALID" := by
  rw [← UtxoApplyGenesisV1.validateWitnessItemLengths_eq_registry_pre_rotation]
  exact unknown_suite_rejected_pre_rotation w h hNotS hNotM

/-- **R2 registry companion:** Sentinel with non-empty pubkey or sig is
    rejected with TX_ERR_PARSE. BRIDGE via A1 bridge. -/
theorem sentinel_nonempty_rejected_registry_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hS : w.suiteId = RubinFormal.SUITE_ID_SENTINEL)
    (hNE : w.pubkey.size ≠ 0 ∨ w.signature.size ≠ 0) :
    UtxoApplyGenesisV1.validateWitnessItemLengthsRegistry
        Rotation.PRE_ROTATION_REGISTRY w h =
      .error "TX_ERR_PARSE" := by
  rw [← UtxoApplyGenesisV1.validateWitnessItemLengths_eq_registry_pre_rotation]
  exact sentinel_nonempty_rejected_pre_rotation w h hS hNE

/-- **R3 registry companion:** Sentinel with both empty is accepted.
    BRIDGE via A1 bridge. -/
theorem sentinel_empty_accepted_registry_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hS : w.suiteId = RubinFormal.SUITE_ID_SENTINEL)
    (hPE : w.pubkey.size = 0)
    (hSE : w.signature.size = 0) :
    UtxoApplyGenesisV1.validateWitnessItemLengthsRegistry
        Rotation.PRE_ROTATION_REGISTRY w h =
      .ok () := by
  rw [← UtxoApplyGenesisV1.validateWitnessItemLengths_eq_registry_pre_rotation]
  exact sentinel_empty_accepted_pre_rotation w h hS hPE hSE

/-- **R4 registry companion:** ML-DSA-87 with wrong pubkey size is rejected.
    BRIDGE via A1 bridge. -/
theorem mldsa87_wrong_pubkey_rejected_registry_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hM : w.suiteId = UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87)
    (hBad : w.pubkey.size ≠ UtxoApplyGenesisV1.ML_DSA_87_PUBKEY_BYTES) :
    UtxoApplyGenesisV1.validateWitnessItemLengthsRegistry
        Rotation.PRE_ROTATION_REGISTRY w h =
      .error "TX_ERR_SIG_NONCANONICAL" := by
  rw [← UtxoApplyGenesisV1.validateWitnessItemLengths_eq_registry_pre_rotation]
  exact mldsa87_wrong_pubkey_rejected_pre_rotation w h hM hBad

/-- **R5a registry companion:** ML-DSA-87 with empty sig is rejected.
    BRIDGE via A1 bridge. -/
theorem mldsa87_empty_sig_rejected_registry_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hM : w.suiteId = UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87)
    (hPOk : w.pubkey.size = UtxoApplyGenesisV1.ML_DSA_87_PUBKEY_BYTES)
    (hSig0 : w.signature.size = 0) :
    UtxoApplyGenesisV1.validateWitnessItemLengthsRegistry
        Rotation.PRE_ROTATION_REGISTRY w h =
      .error "TX_ERR_SIG_NONCANONICAL" := by
  rw [← UtxoApplyGenesisV1.validateWitnessItemLengths_eq_registry_pre_rotation]
  exact mldsa87_empty_sig_rejected_pre_rotation w h hM hPOk hSig0

/-- **R5b registry companion:** ML-DSA-87 with sig too large is rejected.
    BRIDGE via A1 bridge. -/
theorem mldsa87_sig_too_large_rejected_registry_pre_rotation
    (w : WitnessItem) (h : Nat)
    (hM : w.suiteId = UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87)
    (hPOk : w.pubkey.size = UtxoApplyGenesisV1.ML_DSA_87_PUBKEY_BYTES)
    (hBig : w.signature.size > UtxoApplyGenesisV1.ML_DSA_87_SIG_BYTES + 1) :
    UtxoApplyGenesisV1.validateWitnessItemLengthsRegistry
        Rotation.PRE_ROTATION_REGISTRY w h =
      .error "TX_ERR_SIG_NONCANONICAL" := by
  rw [← UtxoApplyGenesisV1.validateWitnessItemLengths_eq_registry_pre_rotation]
  exact mldsa87_sig_too_large_rejected_pre_rotation w h hM hPOk hBig

/-! ### R7-R11 Threshold sig spend — registry companions -/

/-- **R7 registry companion:** Wrong witness count in threshold spend is
    rejected with TX_ERR_PARSE. BRIDGE to `threshold_wrong_count_rejected_pre_rotation`
    via `validateThresholdSigSpend_eq_registry_pre_rotation`. -/
theorem threshold_wrong_count_rejected_registry_pre_rotation
    (keys : List Bytes) (threshold : Nat)
    (ws : List WitnessItem) (h : Nat) (ctx : String)
    (hMismatch : ws.length ≠ keys.length) :
    UtxoApplyGenesisV1.validateThresholdSigSpendRegistry
        Rotation.PRE_ROTATION_REGISTRY keys threshold ws h ctx =
      .error "TX_ERR_PARSE" := by
  rw [← UtxoApplyGenesisV1.validateThresholdSigSpend_eq_registry_pre_rotation]
  exact threshold_wrong_count_rejected_pre_rotation keys threshold ws h ctx hMismatch

/-- **R8a registry companion:** Unknown suite at the head of a threshold
    witness list is rejected with TX_ERR_SIG_ALG_INVALID. BRIDGE via A2 bridge. -/
theorem threshold_unknown_suite_head_rejected_registry_pre_rotation
    (k : Bytes) (krest : List Bytes) (w : WitnessItem) (wrest : List WitnessItem)
    (h : Nat) (ctx : String) (threshold : Nat)
    (hLen : (w :: wrest).length = (k :: krest).length)
    (hNotS : w.suiteId ≠ RubinFormal.SUITE_ID_SENTINEL)
    (hNotM : w.suiteId ≠ UtxoApplyGenesisV1.SUITE_ID_ML_DSA_87) :
    UtxoApplyGenesisV1.validateThresholdSigSpendRegistry
        Rotation.PRE_ROTATION_REGISTRY (k :: krest) threshold (w :: wrest) h ctx =
      .error "TX_ERR_SIG_ALG_INVALID" := by
  rw [← UtxoApplyGenesisV1.validateThresholdSigSpend_eq_registry_pre_rotation]
  exact threshold_unknown_suite_head_rejected_pre_rotation
    k krest w wrest h ctx threshold hLen hNotS hNotM

/-- **R8b registry companion:** Any unknown suite appearing anywhere in the
    threshold witness/key zip causes the universal registry helper to reject
    with TX_ERR_SIG_ALG_INVALID. BRIDGE via A2 bridge. -/
theorem threshold_unknown_suite_anywhere_rejected_registry_pre_rotation
    (keys : List Bytes) (threshold : Nat)
    (ws : List WitnessItem) (h : Nat) (ctx : String)
    (safe : List (WitnessItem × Bytes))
    (bad : WitnessItem × Bytes)
    (rest : List (WitnessItem × Bytes))
    (hLen : ws.length = keys.length)
    (hZip : List.zip ws keys = safe ++ bad :: rest)
    (hSafe : ∀ p ∈ safe, thresholdPairSafe p)
    (hBad : thresholdPairUnknownSuite bad) :
    UtxoApplyGenesisV1.validateThresholdSigSpendRegistry
        Rotation.PRE_ROTATION_REGISTRY keys threshold ws h ctx =
      .error "TX_ERR_SIG_ALG_INVALID" := by
  rw [← UtxoApplyGenesisV1.validateThresholdSigSpend_eq_registry_pre_rotation]
  exact threshold_unknown_suite_anywhere_rejected_pre_rotation
    keys threshold ws h ctx safe bad rest hLen hZip hSafe hBad

/-- **R9 registry companion:** Any ML-DSA-87/key hash mismatch appearing
    anywhere in the threshold witness/key zip causes the universal registry
    helper to reject with TX_ERR_SIG_INVALID. BRIDGE via A2 bridge. -/
theorem threshold_hash_mismatch_anywhere_rejected_registry_pre_rotation
    (keys : List Bytes) (threshold : Nat)
    (ws : List WitnessItem) (h : Nat) (ctx : String)
    (safe : List (WitnessItem × Bytes))
    (bad : WitnessItem × Bytes)
    (rest : List (WitnessItem × Bytes))
    (hLen : ws.length = keys.length)
    (hZip : List.zip ws keys = safe ++ bad :: rest)
    (hSafe : ∀ p ∈ safe, thresholdPairSafe p)
    (hBad : thresholdPairMismatch bad) :
    UtxoApplyGenesisV1.validateThresholdSigSpendRegistry
        Rotation.PRE_ROTATION_REGISTRY keys threshold ws h ctx =
      .error "TX_ERR_SIG_INVALID" := by
  rw [← UtxoApplyGenesisV1.validateThresholdSigSpend_eq_registry_pre_rotation]
  exact threshold_hash_mismatch_anywhere_rejected_pre_rotation
    keys threshold ws h ctx safe bad rest hLen hZip hSafe hBad

/-- **R10 registry companion:** If every threshold pair is structurally safe
    but the accumulated ML-DSA-87 match count stays below `threshold`, the
    universal registry helper rejects with TX_ERR_SIG_INVALID. BRIDGE via A2. -/
theorem threshold_below_required_count_rejected_registry_pre_rotation
    (keys : List Bytes) (threshold : Nat)
    (ws : List WitnessItem) (h : Nat) (ctx : String)
    (hLen : ws.length = keys.length)
    (hSafe : ∀ p ∈ List.zip ws keys, thresholdPairSafe p)
    (hBelow : thresholdSafeCount (List.zip ws keys) < threshold) :
    UtxoApplyGenesisV1.validateThresholdSigSpendRegistry
        Rotation.PRE_ROTATION_REGISTRY keys threshold ws h ctx =
      .error "TX_ERR_SIG_INVALID" := by
  rw [← UtxoApplyGenesisV1.validateThresholdSigSpend_eq_registry_pre_rotation]
  exact threshold_below_required_count_rejected_pre_rotation
    keys threshold ws h ctx hLen hSafe hBelow

/-- **R11 registry companion:** If every threshold pair is structurally safe
    and the ML-DSA-87 match count reaches `threshold`, the universal registry
    helper accepts. BRIDGE via A2. -/
theorem threshold_required_count_accepts_registry_pre_rotation
    (keys : List Bytes) (threshold : Nat)
    (ws : List WitnessItem) (h : Nat) (ctx : String)
    (hLen : ws.length = keys.length)
    (hSafe : ∀ p ∈ List.zip ws keys, thresholdPairSafe p)
    (hEnough : threshold ≤ thresholdSafeCount (List.zip ws keys)) :
    UtxoApplyGenesisV1.validateThresholdSigSpendRegistry
        Rotation.PRE_ROTATION_REGISTRY keys threshold ws h ctx =
      .ok () := by
  rw [← UtxoApplyGenesisV1.validateThresholdSigSpend_eq_registry_pre_rotation]
  exact threshold_required_count_accepts_pre_rotation
    keys threshold ws h ctx hLen hSafe hEnough

/-! ### R12-R14 Outer vault propagation — registry companions -/

/-- **R12 registry companion:** When vault sponsor checks pass, any threshold
    hash mismatch anywhere propagates through
    `validateVaultSpendRegistry PRE_ROTATION_REGISTRY` as
    `TX_ERR_SIG_INVALID`. -/
theorem vault_threshold_hash_mismatch_anywhere_rejected_registry_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (safe : List (WitnessItem × Bytes))
    (bad : WitnessItem × Bytes)
    (rest : List (WitnessItem × Bytes))
    (hSponsorOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hLen : vWit.length = vKeys.length)
    (hZip : List.zip vWit vKeys = safe ++ bad :: rest)
    (hSafe : ∀ p ∈ safe, thresholdPairSafe p)
    (hBad : thresholdPairMismatch bad) :
    UtxoApplyGenesisV1.validateVaultSpendRegistry Rotation.PRE_ROTATION_REGISTRY
      true lids covs vOwnLid vKeys vThr vWit h outs wl =
      .error "TX_ERR_SIG_INVALID" := by
  have hSig :
      UtxoApplyGenesisV1.validateThresholdSigSpendRegistry
        Rotation.PRE_ROTATION_REGISTRY vKeys vThr vWit h "CORE_VAULT" =
        .error "TX_ERR_SIG_INVALID" := by
    exact threshold_hash_mismatch_anywhere_rejected_registry_pre_rotation
      vKeys vThr vWit h "CORE_VAULT" safe bad rest hLen hZip hSafe hBad
  exact UtxoApplyGenesisV1.vault_threshold_error_propagates_registry_pre_rotation
    lids covs vOwnLid vKeys vThr vWit h outs wl "TX_ERR_SIG_INVALID"
    hSponsorOk hSig

/-- **R13 registry companion:** When vault sponsor checks pass and the zipped
    threshold witness/key loop stays structurally safe but below threshold,
    `validateVaultSpendRegistry PRE_ROTATION_REGISTRY` rejects with
    `TX_ERR_SIG_INVALID`. -/
theorem vault_threshold_below_required_count_rejected_registry_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (hSponsorOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hLen : vWit.length = vKeys.length)
    (hSafe : ∀ p ∈ List.zip vWit vKeys, thresholdPairSafe p)
    (hBelow : thresholdSafeCount (List.zip vWit vKeys) < vThr) :
    UtxoApplyGenesisV1.validateVaultSpendRegistry Rotation.PRE_ROTATION_REGISTRY
      true lids covs vOwnLid vKeys vThr vWit h outs wl =
      .error "TX_ERR_SIG_INVALID" := by
  have hSig :
      UtxoApplyGenesisV1.validateThresholdSigSpendRegistry
        Rotation.PRE_ROTATION_REGISTRY vKeys vThr vWit h "CORE_VAULT" =
        .error "TX_ERR_SIG_INVALID" := by
    exact threshold_below_required_count_rejected_registry_pre_rotation
      vKeys vThr vWit h "CORE_VAULT" hLen hSafe hBelow
  exact UtxoApplyGenesisV1.vault_threshold_error_propagates_registry_pre_rotation
    lids covs vOwnLid vKeys vThr vWit h outs wl "TX_ERR_SIG_INVALID"
    hSponsorOk hSig

/-- **R14 registry companion:** When vault sponsor checks pass, the threshold
    witness/key loop is structurally safe, enough counted items match, and the
    whitelist passes, `validateVaultSpendRegistry PRE_ROTATION_REGISTRY`
    accepts. -/
theorem vault_threshold_required_count_accepts_registry_pre_rotation
    (lids : List Bytes) (covs : List Nat) (vOwnLid : Bytes)
    (vKeys : List Bytes) (vThr : Nat) (vWit : List WitnessItem) (h : Nat)
    (outs : List UtxoBasicV1.TxOut) (wl : List Bytes)
    (hSponsorOk : (List.zip covs lids).all (fun (cov, lid) =>
      cov == CovenantGenesisV1.COV_TYPE_VAULT || lid == vOwnLid) = true)
    (hLen : vWit.length = vKeys.length)
    (hSafe : ∀ p ∈ List.zip vWit vKeys, thresholdPairSafe p)
    (hEnough : vThr ≤ thresholdSafeCount (List.zip vWit vKeys))
    (hWL : UtxoApplyGenesisV1.vaultSpendOutputsAllowed wl outs = true) :
    UtxoApplyGenesisV1.validateVaultSpendRegistry Rotation.PRE_ROTATION_REGISTRY
      true lids covs vOwnLid vKeys vThr vWit h outs wl =
      .ok () := by
  have hSig :
      UtxoApplyGenesisV1.validateThresholdSigSpendRegistry
        Rotation.PRE_ROTATION_REGISTRY vKeys vThr vWit h "CORE_VAULT" =
        .ok () := by
    exact threshold_required_count_accepts_registry_pre_rotation
      vKeys vThr vWit h "CORE_VAULT" hLen hSafe hEnough
  exact UtxoApplyGenesisV1.vault_all_pass_registry_pre_rotation
    lids covs vOwnLid vKeys vThr vWit h outs wl hSponsorOk hSig hWL

end RubinFormal

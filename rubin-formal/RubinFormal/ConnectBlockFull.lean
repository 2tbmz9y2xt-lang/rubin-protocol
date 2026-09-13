import RubinFormal.ConnectBlockStrong
import RubinFormal.CoinbaseBehavioral
import RubinFormal.TxContextBehavioral

/-!
# Full Block Connection with Coinbase (§18/§19)

Models the complete block connection path including:
1. Coinbase vault check and UTXO seeding
2. Non-coinbase transaction validation over the seeded map (via connectBlockTxs)
3. Coinbase value bound after successful transaction fees

Written with explicit match (no do) for formal proof access.
-/

namespace RubinFormal

open UtxoBasicV1 SubsidyV1

/-- Full block connection result. -/
structure ConnectBlockResult where
  utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint
  sumFees : Nat

/-- Full block connection pipeline. -/
def connectBlockFull
    (nonCoinbaseTxs : List Bytes)
    (coinbaseOutputs : List CovenantGenesisV1.TxOut)
    (coinbaseTxid : Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat) (chainId : Bytes) (subsidy : Nat)
    : Except String ConnectBlockResult :=
  match validateCoinbaseApplyOutputs coinbaseOutputs with
  | .error e => .error e
  | .ok () =>
    let seeded := addCoinbaseOutputs coinbaseOutputs coinbaseTxid height utxoMap
    match connectBlockTxs nonCoinbaseTxs seeded height blockTimestamp chainId with
    | .error e => .error e
    | .ok (sumFees, postTxUtxos) =>
      match validateCoinbaseValueBound coinbaseOutputs subsidy sumFees with
      | .error e => .error e
      | .ok () =>
        .ok { utxoMap := postTxUtxos
            , sumFees := sumFees }

/-! ## Helper: extract connectBlockTxs success -/

private theorem connectBlockFull_txs_ok
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub = .ok result) :
    ∃ postTxUtxos,
      connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid =
        .ok (result.sumFees, postTxUtxos) := by
  simp only [connectBlockFull] at hOk
  match hVault : validateCoinbaseApplyOutputs couts with
  | .error _ => simp [hVault] at hOk
  | .ok () =>
    simp [hVault] at hOk
    match hTxs : connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid with
    | .error _ => simp [hTxs] at hOk
    | .ok (sf, ptx) =>
      simp [hTxs] at hOk
      match hBound : validateCoinbaseValueBound couts sub sf with
      | .error _ => simp [hBound] at hOk
      | .ok () =>
        simp [hBound] at hOk
        obtain ⟨_, rfl⟩ := hOk
        exact ⟨ptx, rfl⟩

/-! ## Non-coinbase behavioral proofs -/

/-- Full connection success → non-coinbase conservation + no-double-spend. -/
theorem connectBlockFull_preserves_noncoinbase_invariants
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub = .ok result) :
    utxo_conserved nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid ∧
    no_double_spend nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid := by
  obtain ⟨ptx, hTxs⟩ := connectBlockFull_txs_ok _ _ _ _ _ _ _ _ _ hOk
  exact ⟨utxo_conservation_theorem _ _ _ _ _ _ _ hTxs,
         no_double_spend_theorem _ _ _ _ _ _ _ hTxs⟩

/-- Full connection success → coinbase value ≤ subsidy + fees. -/
theorem connectBlockFull_coinbase_bound
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub = .ok result) :
    ¬(sumCoinbaseOutputs couts > sub + result.sumFees) := by
  simp only [connectBlockFull] at hOk
  match hVault : validateCoinbaseApplyOutputs couts with
  | .error _ => simp [hVault] at hOk
  | .ok () =>
    simp [hVault] at hOk
    match hTxs : connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid with
    | .error _ => simp [hTxs] at hOk
    | .ok (sf, ptx) =>
      simp [hTxs] at hOk
      match hBound : validateCoinbaseValueBound couts sub sf with
      | .error _ => simp [hBound] at hOk
      | .ok () =>
        simp [hBound] at hOk
        obtain ⟨_, rfl⟩ := hOk
        simp only [validateCoinbaseValueBound] at hBound
        by_cases hGt : sumCoinbaseOutputs couts > sub + sf
        · simp [hGt] at hBound
        · exact hGt

/-- Full connection success → no CORE_VAULT in coinbase. -/
theorem connectBlockFull_no_vault
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub = .ok result) :
    couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = false := by
  by_cases hAny : couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = true
  · have hVault : validateCoinbaseApplyOutputs couts = .error "BLOCK_ERR_COINBASE_INVALID" :=
      coinbase_no_vault_rejects couts hAny
    simp [connectBlockFull, hVault] at hOk
  · exact Bool.eq_false_iff.mpr (fun hh => hAny hh)

/-! ## Error branch proofs -/

/-- Non-coinbase tx failure → full connect rejected with same error. -/
theorem connectBlockFull_rejects_bad_txs
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (err : String)
    (hVault : validateCoinbaseApplyOutputs couts = .ok ())
    (hFail : connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid = .error err) :
    connectBlockFull nctxs couts ctxid utxos h bt cid sub = .error err := by
  simp [connectBlockFull, hVault, hFail]

/-- Coinbase exceeds subsidy+fees → full connect rejected. -/
theorem connectBlockFull_rejects_oversized_coinbase
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (sumFees : Nat) (postTxUtxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hVault : validateCoinbaseApplyOutputs couts = .ok ())
    (hTxs : connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid = .ok (sumFees, postTxUtxos))
    (hOver : sumCoinbaseOutputs couts > sub + sumFees) :
    connectBlockFull nctxs couts ctxid utxos h bt cid sub =
    .error "BLOCK_ERR_SUBSIDY_EXCEEDED" := by
  simp [connectBlockFull, hVault, hTxs, validateCoinbaseValueBound, hOver]

/-- CORE_VAULT in coinbase → full connect rejected. -/
theorem connectBlockFull_rejects_vault_coinbase
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (hVault : couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = true) :
    connectBlockFull nctxs couts ctxid utxos h bt cid sub =
    .error "BLOCK_ERR_COINBASE_INVALID" := by
  simp [connectBlockFull, validateCoinbaseApplyOutputs, hVault]

/-! ## Structural ordering -/

/-- Coinbase outputs are seeded before non-coinbase transaction processing. -/
private theorem coinbase_seeded_before_noncoinbase
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub = .ok result) :
    ∃ sf ptx,
      connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid = .ok (sf, ptx) := by
  obtain ⟨ptx, hTxs⟩ := connectBlockFull_txs_ok _ _ _ _ _ _ _ _ _ hOk
  exact ⟨result.sumFees, ptx, hTxs⟩

/-! ## Private ordering evidence -/

private theorem vault_dominates_later_tx_and_subsidy_failures
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (txErr : String) (sumFees : Nat)
    (hVault : couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = true)
    (hTxFail : connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid = .error txErr)
    (hBoundFail : validateCoinbaseValueBound couts sub sumFees = .error "BLOCK_ERR_SUBSIDY_EXCEEDED") :
    connectBlockFull nctxs couts ctxid utxos h bt cid sub =
      .error "BLOCK_ERR_COINBASE_INVALID" ∧
    connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid = .error txErr ∧
    validateCoinbaseValueBound couts sub sumFees = .error "BLOCK_ERR_SUBSIDY_EXCEEDED" := by
  exact ⟨by simp [connectBlockFull, validateCoinbaseApplyOutputs, hVault], hTxFail, hBoundFail⟩

private theorem seeded_spendable_output_is_visible_and_immature
    (out : CovenantGenesisV1.TxOut) (txid : Bytes) (height : Nat)
    (hSpend : isSpendableCoinbaseOutput out = true) :
    addCoinbaseOutputs [out] txid height (Std.RBMap.empty) =
      (Std.RBMap.empty).insert { txid := txid, vout := 0 } (coinbaseUtxoEntry out height) ∧
    validateCoinbaseMaturity (coinbaseUtxoEntry out height) height =
      .error "TX_ERR_COINBASE_IMMATURE" := by
  constructor
  · simp [addCoinbaseOutputs, List.enum, List.enumFrom, hSpend]
  · simp [validateCoinbaseMaturity, coinbaseUtxoEntry, COINBASE_MATURITY]
    omega

private theorem seeded_anchor_and_da_commit_outputs_are_not_inserted
    (anchor daCommit : CovenantGenesisV1.TxOut) (txid : Bytes) (height : Nat)
    (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hAnchor : anchor.covenantType = CovenantGenesisV1.COV_TYPE_ANCHOR)
    (hDaCommit : daCommit.covenantType = CovenantGenesisV1.COV_TYPE_DA_COMMIT) :
    addCoinbaseOutputs [anchor, daCommit] txid height utxos = utxos := by
  simp [addCoinbaseOutputs, List.enum, List.enumFrom, isSpendableCoinbaseOutput, hAnchor, hDaCommit]

private theorem successful_full_connection_uses_post_transaction_seeded_map
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos postTxUtxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (sumFees : Nat)
    (hVault : validateCoinbaseApplyOutputs couts = .ok ())
    (hTxs : connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid =
      .ok (sumFees, postTxUtxos))
    (hBound : validateCoinbaseValueBound couts sub sumFees = .ok ()) :
    connectBlockFull nctxs couts ctxid utxos h bt cid sub =
      .ok { utxoMap := postTxUtxos, sumFees := sumFees } := by
  simp [connectBlockFull, hVault, hTxs, hBound]

/-! ## Error taxonomy (replaces former axiom) -/

/-- Structural correspondence: connectBlockFull returns ONLY canonical
    error codes. Machine-checked exhaustive proof; this does not assert that
    ordinary Lean foundations are absent from its closure. -/
theorem connectBlockFull_error_taxonomy
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (err : String)
    (hFail : connectBlockFull nctxs couts ctxid utxos h bt cid sub = .error err) :
    err = "BLOCK_ERR_SUBSIDY_EXCEEDED" ∨
    err = "BLOCK_ERR_COINBASE_INVALID" ∨
    (∃ txErr,
      connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid = .error txErr ∧
      err = txErr) := by
  simp only [connectBlockFull] at hFail
  by_cases hVault : couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = true
  · have hV : validateCoinbaseApplyOutputs couts = .error "BLOCK_ERR_COINBASE_INVALID" :=
      coinbase_no_vault_rejects couts hVault
    simp [hV] at hFail
    exact Or.inr (Or.inl hFail.symm)
  · have hNotV := Bool.eq_false_iff.mpr (fun hh => hVault hh)
    have hV : validateCoinbaseApplyOutputs couts = .ok () :=
      coinbase_no_vault_accepts couts hNotV
    simp [hV] at hFail
    match hT : connectBlockTxs nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid with
    | .error e =>
      simp [hT] at hFail
      exact Or.inr (Or.inr ⟨e, rfl, hFail.symm⟩)
    | .ok (sf, ptx) =>
      simp [hT] at hFail
      by_cases hOver : sumCoinbaseOutputs couts > sub + sf
      · have hB : validateCoinbaseValueBound couts sub sf = .error "BLOCK_ERR_SUBSIDY_EXCEEDED" :=
          coinbase_value_bound_rejects couts sub sf hOver
        simp [hB] at hFail
        exact Or.inl hFail.symm
      · have hB : validateCoinbaseValueBound couts sub sf = .ok () :=
          coinbase_value_bound_accepts couts sub sf hOver
        simp [hB] at hFail

/-! ## End-to-end scenario -/

/-- Valid block end-to-end: ALL invariants hold simultaneously.
    Conservation + no-double-spend + coinbase bound + no-vault. -/
theorem valid_block_end_to_end
    (nctxs : List Bytes) (couts : List CovenantGenesisV1.TxOut)
    (ctxid : Bytes) (utxos : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (h bt : Nat) (cid : Bytes) (sub : Nat)
    (result : ConnectBlockResult)
    (hOk : connectBlockFull nctxs couts ctxid utxos h bt cid sub = .ok result) :
    utxo_conserved nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid ∧
    no_double_spend nctxs (addCoinbaseOutputs couts ctxid h utxos) h bt cid ∧
    ¬(sumCoinbaseOutputs couts > sub + result.sumFees) ∧
    couts.any (·.covenantType == CovenantGenesisV1.COV_TYPE_VAULT) = false :=
  ⟨(connectBlockFull_preserves_noncoinbase_invariants _ _ _ _ _ _ _ _ _ hOk).1,
   (connectBlockFull_preserves_noncoinbase_invariants _ _ _ _ _ _ _ _ _ hOk).2,
   connectBlockFull_coinbase_bound _ _ _ _ _ _ _ _ _ hOk,
   connectBlockFull_no_vault _ _ _ _ _ _ _ _ _ hOk⟩

/-! ## Vault error propagation (R14 integration)

Vault rules are enforced per-tx inside connectBlockTxs → applyNonCoinbaseTxBasicState →
applyNonCoinbaseTxBasicNoCrypto → validateVaultSpend (LIVE, line 495).
All vault errors propagate to block level via connectBlockFull_rejects_bad_txs
(generic error propagation). No separate vault-specific wrappers needed. -/

/-! ## Guard lemma

connectBlockFull has exactly 4 outcomes:
1. validateCoinbaseApplyOutputs error → BLOCK_ERR_COINBASE_INVALID
2. connectBlockTxs over the seeded coinbase map error → propagate
3. validateCoinbaseValueBound error → BLOCK_ERR_SUBSIDY_EXCEEDED
4. ok → construct result from the post-transaction seeded map

Adding a 5th validation step requires updating every theorem above.
Lean's exhaustiveness checker enforces this: missing arm → compile error. -/

end RubinFormal

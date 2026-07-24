import RubinFormal.ConnectBlockFull

/-!
# Per-Transaction State Machine (§18)

Decomposes the block-level `connectBlockTxs` fold into per-individual-tx
state transitions. Each theorem operates on `applyNonCoinbaseTxBasicState`
— the LIVE per-tx function that updates the UTXO map.

Combined with block-level ConnectBlockFull.lean, this gives full coverage:
- Block-level: connectBlockFull pipeline (conservation, coinbase, TxContext)
- Per-tx level: state transition, fee extraction, error propagation
-/

namespace RubinFormal

open UtxoBasicV1 SubsidyV1

/-! ## Per-tx state transition -/

/-- Per-tx UTXO state machine: successful apply decomposes into
    prepare (parse + validate) + erase inputs + insert outputs.
    The result `(fee, nextMap)` comes from `PreparedNonCoinbaseTx`. -/
theorem applyTx_state_transition
    (txBytes : Bytes) (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat) (chainId : Bytes)
    (fee : Nat) (nextMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hOk : applyNonCoinbaseTxBasicState txBytes utxoMap height blockTimestamp chainId =
           .ok (fee, nextMap)) :
    ∃ prepared : PreparedNonCoinbaseTx,
      prepareNonCoinbaseTxBasic txBytes utxoMap height blockTimestamp chainId = .ok prepared ∧
      fee = prepared.fee ∧
      nextMap = prepared.nextUtxoMap := by
  unfold applyNonCoinbaseTxBasicState at hOk
  match hPrep : prepareNonCoinbaseTxBasic txBytes utxoMap height blockTimestamp chainId with
  | .error _ => rw [hPrep] at hOk; cases hOk
  | .ok prepared =>
    rw [hPrep] at hOk
    change Except.ok (prepared.fee, prepared.nextUtxoMap) = .ok (fee, nextMap) at hOk
    cases hOk; exact ⟨prepared, rfl, rfl, rfl⟩

/-! ## UTXO map decomposition (eraseInputs + insertOutputs) -/

/-- Per-tx UTXO map structure: prepare decomposes into
    eraseInputs (remove spent) + insertOutputs (add created).
    This is the explicit erase+insert structure, not just "nextMap exists". -/
theorem prepare_tx_utxo_decomposition
    (txBytes : Bytes) (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat) (chainId : Bytes)
    (prepared : PreparedNonCoinbaseTx)
    (hOk : prepareNonCoinbaseTxBasic txBytes utxoMap height blockTimestamp chainId = .ok prepared) :
    ∃ core txid,
      prepareNonCoinbaseTxCore txBytes utxoMap height blockTimestamp chainId = .ok core ∧
      prepared.nextUtxoMap = insertOutputs (eraseInputs utxoMap core.tx.inputs) txid core.tx.outputs height := by
  unfold prepareNonCoinbaseTxBasic at hOk
  match hCore : prepareNonCoinbaseTxCore txBytes utxoMap height blockTimestamp chainId with
  | .error _ => rw [hCore] at hOk; cases hOk
  | .ok core =>
    rw [hCore] at hOk
    change Except.ok _ = Except.ok prepared at hOk
    cases hOk
    exact ⟨core, _, rfl, rfl⟩

/-! ## Error propagation in tx sequence -/

/-- First tx error → entire sequence fails with same error. -/
theorem connectBlockTxs_first_tx_error
    (tx : Bytes) (txs : List Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat) (chainId : Bytes) (err : String)
    (hFail :
      applyNonCoinbaseTxBasicState
          tx utxoMap height blockTimestamp chainId none false = .error err) :
    connectBlockTxs (tx :: txs) utxoMap height blockTimestamp chainId = .error err := by
  simp [connectBlockTxs, hFail]

/-- Later tx error (first succeeds) → sequence fails with later error. -/
theorem connectBlockTxs_later_tx_error
    (tx : Bytes) (txs : List Bytes)
    (utxoMap next : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp fee : Nat) (chainId : Bytes) (err : String)
    (hOk :
      applyNonCoinbaseTxBasicState
          tx utxoMap height blockTimestamp chainId none false = .ok (fee, next))
    (hFail : connectBlockTxs txs next height blockTimestamp chainId = .error err) :
    connectBlockTxs (tx :: txs) utxoMap height blockTimestamp chainId = .error err := by
  simp [connectBlockTxs, hOk, hFail]

/-! ## Fee accumulation -/

/-- Per-tx fees accumulate through the sequence.
    Total fee = fee_1 + fee_2 + ... + fee_n. -/
theorem connectBlockTxs_fee_accumulates
    (tx : Bytes) (txs : List Bytes)
    (utxoMap next finalMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp fee feesTail : Nat) (chainId : Bytes)
    (hStep :
      applyNonCoinbaseTxBasicState
          tx utxoMap height blockTimestamp chainId none false = .ok (fee, next))
    (hTail : connectBlockTxs txs next height blockTimestamp chainId = .ok (feesTail, finalMap)) :
    connectBlockTxs (tx :: txs) utxoMap height blockTimestamp chainId =
    .ok (fee + feesTail, finalMap) := by
  simp [connectBlockTxs, hStep, hTail]

/-- Empty tx list → zero fees, unchanged UTXO map. -/
theorem connectBlockTxs_empty_zero_fees
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat) (chainId : Bytes) :
    connectBlockTxs [] utxoMap height blockTimestamp chainId = .ok (0, utxoMap) := rfl

/-! ## Per-tx TxContext (modeling per-tx BuildTxContext in Go) -/

/-- For each individual tx with active ext_ids, buildTxContext produces a bundle.
    In Go, BuildTxContext is called PER-TX inside the parallel loop.
    In our Lean model, connectBlockFull calls it once per block with aggregated totals.
    This theorem bridges: if per-tx ext_ids are active, bundle exists. -/
theorem perTx_txcontext_when_active
    (ids : List Nat) (hIds : ids.length > 0)
    (txTotalIn txTotalOut height : Nat)
    (cd : List (Nat × TxContextContinuing)) :
    (buildTxContext ids txTotalIn txTotalOut height cd).isSome = true :=
  buildTxContext_some ids hIds txTotalIn txTotalOut height cd

/-- For each tx with no active ext_ids, no TxContext bundle. -/
theorem perTx_txcontext_when_inactive
    (txTotalIn txTotalOut height : Nat)
    (cd : List (Nat × TxContextContinuing)) :
    buildTxContext [] txTotalIn txTotalOut height cd = none := rfl

/-! ## UTXO map monotonicity (input consumption + output creation) -/

/-- After processing a tx sequence, the UTXO map reflects all input erasures
    and output insertions. This is the per-tx decomposition:
    processing [tx₁, tx₂, ..., txₙ] is equivalent to
    sequential applyNonCoinbaseTxBasicState calls. -/
theorem connectBlockTxs_sequential_decomposition
    (tx : Bytes) (txs : List Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat) (chainId : Bytes)
    (totalFees : Nat) (finalMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hAll : connectBlockTxs (tx :: txs) utxoMap height blockTimestamp chainId =
            .ok (totalFees, finalMap)) :
    ∃ fee next feesTail,
      applyNonCoinbaseTxBasicState
          tx utxoMap height blockTimestamp chainId none false = .ok (fee, next) ∧
      connectBlockTxs txs next height blockTimestamp chainId = .ok (feesTail, finalMap) ∧
      totalFees = fee + feesTail := by
  simp only [connectBlockTxs] at hAll
  match hStep :
      applyNonCoinbaseTxBasicState
        tx utxoMap height blockTimestamp chainId none false with
  | .error _ => simp [hStep] at hAll
  | .ok (fee, next) =>
    simp [hStep] at hAll
    match hTail : connectBlockTxs txs next height blockTimestamp chainId with
    | .error _ => simp [hTail] at hAll
    | .ok (feesTail, fm) =>
      simp [hTail] at hAll
      obtain ⟨h1, h2⟩ := hAll
      subst h1; subst h2
      exact ⟨fee, next, feesTail, rfl, hTail, rfl⟩

/-! ## Value conservation at per-tx level

Already proved in ConnectBlockStrong.lean:
- `utxo_conserved_tx`: per-tx, inputState.sumIn = sumOutputs + fee
- `utxo_conserved`: recursive over all txs — every tx conserves value
- `connectBlockFull_preserves_noncoinbase_invariants`: block-level proof
  that utxo_conserved AND no_double_spend hold for all non-coinbase txs

These are NOT new — they're existing behavioral theorems.
The value conservation gap is CLOSED by these existing proofs.

Per-tx fee = sumIn - sumOut: proved structurally because
`validateValueConservation` checks sumOut ≤ sumIn BEFORE
computing fee := sumIn - sumOut. So fee ≥ 0 is guaranteed.

Per-tx UTXO map evolution: `prepare_tx_utxo_decomposition` proves
nextMap = insertOutputs(eraseInputs(utxoMap, inputs), outputs).
`no_double_spend` (ConnectBlockStrong) proves inputs are available
and intra-tx unique. Together these give full UTXO map characterization.
-/

/-- Value conservation: per-tx, conservation follows from successful prepare. -/
theorem perTx_conservation_from_prepare
    (txBytes : Bytes) (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat) (chainId : Bytes)
    (prepared : PreparedNonCoinbaseTx)
    (hOk : prepareNonCoinbaseTxBasic txBytes utxoMap height blockTimestamp chainId = .ok prepared) :
    utxo_conserved_tx prepared.tx utxoMap height prepared.fee :=
  prepareNonCoinbaseTxBasic_utxo_conserved txBytes utxoMap height blockTimestamp chainId prepared hOk

/-- No double spend: per-tx, follows from successful prepare. -/
theorem perTx_no_double_spend_from_prepare
    (txBytes : Bytes) (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat) (chainId : Bytes)
    (prepared : PreparedNonCoinbaseTx)
    (hOk : prepareNonCoinbaseTxBasic txBytes utxoMap height blockTimestamp chainId = .ok prepared) :
    no_intra_tx_double_spend prepared.tx :=
  prepareNonCoinbaseTxBasic_no_intra_double_spend txBytes utxoMap height blockTimestamp chainId prepared hOk

end RubinFormal

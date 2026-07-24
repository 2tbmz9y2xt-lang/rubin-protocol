import RubinFormal.ConnectBlockStrong
import RubinFormal.SpendTxEndToEnd

/-!
# UTXO SpendTx Behavioral Proof (§18)

Connects the existing strong theorem surfaces (ConnectBlockStrong,
SpendTxEndToEnd) into a unified behavioral statement about SpendTx
state transitions over the real UTXO-map model.

Main result: `spendTx_behavioral` — if `applyNonCoinbaseTxBasicState`
succeeds, then:
1. All inputs were available in the UTXO map
2. No intra-tx double spend occurred
3. Value conservation holds (sum_in >= sum_out + fee)
4. The output UTXO map is the prepared `nextUtxoMap`
-/

namespace RubinFormal

open RubinFormal.UtxoBasicV1
open RubinFormal.SubsidyV1

/-- Full behavioral statement for a single SpendTx state transition.
    Combines input availability, no-double-spend, value conservation,
    and deterministic UTXO-map output into one theorem. -/
theorem spendTx_behavioral
    (txBytes : Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat)
    (chainId : Bytes)
    (fee : Nat)
    (nextMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hApply :
      applyNonCoinbaseTxBasicState txBytes utxoMap height blockTimestamp chainId = .ok (fee, nextMap)) :
    ∃ prepared,
      prepareNonCoinbaseTxBasic txBytes utxoMap height blockTimestamp chainId = .ok prepared ∧
      prepared.fee = fee ∧
      prepared.nextUtxoMap = nextMap ∧
      inputs_available prepared.tx utxoMap height ∧
      no_intra_tx_double_spend prepared.tx ∧
      utxo_conserved_tx prepared.tx utxoMap height prepared.fee := by
  rcases applyNonCoinbaseTxBasicState_success_prepared
      txBytes utxoMap height blockTimestamp chainId fee nextMap hApply with
    ⟨prepared, hPrep, hFee, hNext⟩
  refine ⟨prepared, hPrep, hFee, hNext, ?_, ?_, ?_⟩
  · exact prepareNonCoinbaseTxBasic_inputs_available
      txBytes utxoMap height blockTimestamp chainId prepared hPrep
  · exact prepareNonCoinbaseTxBasic_no_intra_double_spend
      txBytes utxoMap height blockTimestamp chainId prepared hPrep
  · exact prepareNonCoinbaseTxBasic_utxo_conserved
      txBytes utxoMap height blockTimestamp chainId prepared hPrep

/-- Block-level behavioral statement: `connectBlockTxs` over a list of
    transactions preserves UTXO conservation AND no-double-spend for
    every transaction in the list. Directly reuses the inductive proof
    from ConnectBlockStrong. -/
theorem connectBlockTxs_behavioral
    (txs : List Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat)
    (chainId : Bytes)
    (sumFees : Nat)
    (finalMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hConnect :
      connectBlockTxs txs utxoMap height blockTimestamp chainId = .ok (sumFees, finalMap)) :
    utxo_conserved txs utxoMap height blockTimestamp chainId ∧
    no_double_spend txs utxoMap height blockTimestamp chainId := by
  constructor
  · exact utxo_conservation_theorem txs utxoMap height blockTimestamp chainId sumFees finalMap hConnect
  · exact no_double_spend_theorem txs utxoMap height blockTimestamp chainId sumFees finalMap hConnect

end RubinFormal

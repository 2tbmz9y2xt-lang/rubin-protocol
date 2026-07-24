import RubinFormal.ConnectBlockStrong

/-!
# Value Conservation Behavioral Proofs (§20)

Proves that the real `prepareNonCoinbaseTxBasic` function enforces
`sum_in = sum_out + fee` through the UTXO-map model.
-/

namespace RubinFormal

open UtxoBasicV1

/-- Single-tx value conservation: if prepare succeeds, then resolved input
    sum equals output sum plus fee. This is the real conservation law
    over `scanInputs` and `sumOutputs`. -/
theorem value_conservation_single_tx
    (txBytes : Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat)
    (chainId : Bytes)
    (prepared : PreparedNonCoinbaseTx)
    (hPrep : prepareNonCoinbaseTxBasic txBytes utxoMap height blockTimestamp chainId = .ok prepared) :
    utxo_conserved_tx prepared.tx utxoMap height prepared.fee :=
  prepareNonCoinbaseTxBasic_utxo_conserved txBytes utxoMap height blockTimestamp chainId prepared hPrep

/-- Block-level value conservation: `connectBlockTxs` preserves conservation
    across all transactions in a block. -/
theorem value_conservation_block_txs
    (txs : List Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat)
    (chainId : Bytes)
    (sumFees : Nat)
    (finalMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hConnect : SubsidyV1.connectBlockTxs txs utxoMap height blockTimestamp chainId = .ok (sumFees, finalMap)) :
    utxo_conserved txs utxoMap height blockTimestamp chainId :=
  utxo_conservation_theorem txs utxoMap height blockTimestamp chainId sumFees finalMap hConnect

end RubinFormal

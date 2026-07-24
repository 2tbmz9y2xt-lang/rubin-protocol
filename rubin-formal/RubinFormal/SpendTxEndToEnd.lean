import RubinFormal.ConnectBlockStrong

namespace RubinFormal

open RubinFormal.UtxoBasicV1

theorem spendTx_end_to_end
    (txBytes : Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat)
    (chainId : Bytes) :
    ∀ prepared,
      prepareNonCoinbaseTxBasic txBytes utxoMap height blockTimestamp chainId = .ok prepared →
        inputs_available prepared.tx utxoMap height ∧
        no_intra_tx_double_spend prepared.tx ∧
        utxo_conserved_tx prepared.tx utxoMap height prepared.fee := by
  intro prepared hPrep
  constructor
  · exact prepareNonCoinbaseTxBasic_inputs_available
      txBytes utxoMap height blockTimestamp chainId prepared hPrep
  · constructor
    · exact prepareNonCoinbaseTxBasic_no_intra_double_spend
        txBytes utxoMap height blockTimestamp chainId prepared hPrep
    · exact prepareNonCoinbaseTxBasic_utxo_conserved
        txBytes utxoMap height blockTimestamp chainId prepared hPrep

end RubinFormal

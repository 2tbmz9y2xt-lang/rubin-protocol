import RubinFormal.Refinement.GoTraceV1Check
import RubinFormal.ConnectBlockStrong

namespace RubinFormal

/-! ## Universal UTXO refinement theorems

  The theorems below hold for **any** transaction list and UTXO state
  where `connectBlockTxs` succeeds, proved by induction over the transaction
  list — no axioms, no fixture dependence.

  These are re-exported from `ConnectBlockStrong` into the refinement bridge
  namespace so that the evidence registry can reference a single Lean file. -/

open UtxoBasicV1
open SubsidyV1

/-- Universal UTXO apply refinement: for any transactions and any UTXO state,
    if `connectBlockTxs` succeeds then both UTXO conservation and
    anti-double-spend hold simultaneously.  Proved by combining two independent
    inductive proofs from `ConnectBlockStrong`. -/
theorem utxo_apply_basic_universal_refinement
    (txs : List Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat)
    (chainId : Bytes)
    (sumFees : Nat)
    (finalMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hConnect :
      connectBlockTxs txs utxoMap height blockTimestamp chainId = .ok (sumFees, finalMap)) :
    utxo_conserved txs utxoMap height blockTimestamp chainId ∧
    no_double_spend txs utxoMap height blockTimestamp chainId :=
  ⟨utxo_conservation_theorem txs utxoMap height blockTimestamp chainId sumFees finalMap hConnect,
   no_double_spend_theorem txs utxoMap height blockTimestamp chainId sumFees finalMap hConnect⟩

/-- Chain-level universal UTXO refinement: for any sequence of blocks,
    if `connectBlockSequence` succeeds over the entire chain, then every
    individual block preserves UTXO conservation and anti-double-spend.
    This is the strongest available UTXO refinement theorem — it composes
    block-level guarantees into a chain-wide invariant by induction. -/
theorem utxo_apply_basic_chain_refinement
    (steps : List ChainConnectStep)
    (utxoMap finalMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (hSequence : connectBlockSequence steps utxoMap = .ok finalMap) :
    chainConsistency steps utxoMap :=
  chainConsistency_inductive steps utxoMap finalMap hSequence

end RubinFormal

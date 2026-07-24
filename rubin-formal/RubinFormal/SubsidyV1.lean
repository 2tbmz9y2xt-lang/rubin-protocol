import RubinFormal.Types
import RubinFormal.BlockBasicV1
import RubinFormal.UtxoBasicV1

namespace RubinFormal

namespace SubsidyV1

open RubinFormal
open RubinFormal.BlockBasicV1
open RubinFormal.UtxoBasicV1

-- Consensus constants (mirror clients/go/consensus/constants.go).
-- NOTE (§19.1, PR #420): Go uses *big.Int, Rust uses u128 for subsidy
-- accumulation arithmetic. Lean Nat is unbounded and strictly subsumes
-- both u64 and u128. The formal bound proof that subsidy values fit in
-- machine types is in ArithmeticSafety.lean (blockSubsidy_bounded,
-- subsidy_accumulation_in_u128).
def MINEABLE_CAP : Nat := 4900000000000000
def EMISSION_SPEED_FACTOR : Nat := 20
def TAIL_EMISSION_PER_BLOCK : Nat := 19025875

def blockSubsidy (height : Nat) (alreadyGenerated : Nat) : Nat :=
  if height == 0 then 0
  else if alreadyGenerated >= MINEABLE_CAP then TAIL_EMISSION_PER_BLOCK
  else
    let remaining := MINEABLE_CAP - alreadyGenerated
    let baseReward := Nat.shiftRight remaining EMISSION_SPEED_FACTOR
    if baseReward < TAIL_EMISSION_PER_BLOCK then TAIL_EMISSION_PER_BLOCK else baseReward

def isCanonicalCoinbase (tx : RubinFormal.UtxoBasicV1.Tx) : Bool :=
  if tx.txKind != 0x00 then false
  else if tx.txNonce != 0 then false
  else if tx.inputs.length != 1 then false
  else if tx.witness.length != 0 then false
  else if tx.daPayloadLen != 0 then false
  else
    let i := tx.inputs.get! 0
    isCoinbasePrevout i &&
    i.scriptSig.size == 0 &&
    i.sequence == 0xffffffff

def validateCoinbaseLocktime (coinbaseTxBytes : Bytes) (height : Nat) : Except String Unit := do
  let tx ← parseTx coinbaseTxBytes
  if !isCanonicalCoinbase tx then
    throw "BLOCK_ERR_COINBASE_INVALID"
  if tx.locktime != height then
    throw "BLOCK_ERR_COINBASE_INVALID"
  pure ()

def sumCoinbaseOutputs (coinbaseTxBytes : Bytes) : Except String Nat := do
  let tx ← parseTx coinbaseTxBytes
  pure (sumOutputs tx.outputs)

def validateCoinbaseApplyOutputs (coinbaseTxBytes : Bytes) : Except String Unit := do
  let tx ← parseTx coinbaseTxBytes
  for output in tx.outputs do
    if output.covenantType == CovenantGenesisV1.COV_TYPE_VAULT then
      throw "BLOCK_ERR_COINBASE_INVALID"
  pure ()

def validateCoinbaseValueBound
    (coinbaseTxBytes : Bytes)
    (height : Nat)
    (alreadyGenerated : Nat)
    (sumFees : Nat) : Except String Unit := do
  if height == 0 then
    pure ()
  else
    let sumCoinbase ← sumCoinbaseOutputs coinbaseTxBytes
    let limit := (blockSubsidy height alreadyGenerated) + sumFees
    if sumCoinbase > limit then
      throw "BLOCK_ERR_SUBSIDY_EXCEEDED"
    pure ()

def connectBlockTxs
    (txs : List Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height : Nat)
    (blockTimestamp : Nat)
    (chainId : Bytes) : Except String (Nat × Std.RBMap Outpoint UtxoEntry cmpOutpoint) :=
  match txs with
  | [] => .ok (0, utxoMap)
  | txBytes :: rest =>
      match applyNonCoinbaseTxBasicState
          txBytes utxoMap height blockTimestamp chainId none false with
      | .error e => .error e
      | .ok (fee, next) =>
          match connectBlockTxs rest next height blockTimestamp chainId with
          | .error e => .error e
          | .ok (feesTail, finalMap) => .ok (fee + feesTail, finalMap)

theorem connectBlockTxs_nil
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp : Nat)
    (chainId : Bytes) :
    connectBlockTxs [] utxoMap height blockTimestamp chainId = .ok (0, utxoMap) := by
  rfl

theorem connectBlockTxs_cons
    (tx : Bytes)
    (txs : List Bytes)
    (utxoMap next finalMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height blockTimestamp fee feesTail : Nat)
    (chainId : Bytes)
    (hStep : applyNonCoinbaseTxBasicState
      tx utxoMap height blockTimestamp chainId none false = .ok (fee, next))
    (hTail : connectBlockTxs txs next height blockTimestamp chainId = .ok (feesTail, finalMap)) :
    connectBlockTxs (tx :: txs) utxoMap height blockTimestamp chainId = .ok (fee + feesTail, finalMap) := by
  simp [connectBlockTxs, hStep, hTail]

def connectBlockBasic
    (blockBytes : Bytes)
    (expectedPrevHash : Option Bytes)
    (expectedTarget : Option Bytes)
    (height : Nat)
    (alreadyGenerated : Nat)
    (utxos : List (Outpoint × UtxoEntry))
    (chainId : Bytes) : Except String Unit :=
  match BlockBasicV1.validateBlockBasic blockBytes expectedPrevHash expectedTarget with
  | .error e => .error e
  | .ok () =>
      match BlockBasicV1.parseBlock blockBytes with
      | .error e => .error e
      | .ok pb =>
          match validateCoinbaseLocktime pb.coinbaseTx height with
          | .error e => .error e
          | .ok () =>
              match connectBlockTxs pb.txs.tail (buildUtxoMap utxos) height pb.header.timestamp chainId with
              | .error e => .error e
              | .ok (sumFees, _finalMap) =>
                  match validateCoinbaseValueBound pb.coinbaseTx height alreadyGenerated sumFees with
                  | .error e => .error e
                  | .ok () => validateCoinbaseApplyOutputs pb.coinbaseTx

def connectBlockEndToEndStatement : Prop :=
  ∀ (blockBytes : Bytes)
    (expectedPrevHash expectedTarget : Option Bytes)
    (height alreadyGenerated : Nat)
    (utxos : List (Outpoint × UtxoEntry))
    (chainId : Bytes)
    (pb : BlockBasicV1.ParsedBlock)
    (sumFees : Nat)
    (finalMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint),
      BlockBasicV1.validateBlockBasic blockBytes expectedPrevHash expectedTarget = .ok () →
      BlockBasicV1.parseBlock blockBytes = .ok pb →
      validateCoinbaseLocktime pb.coinbaseTx height = .ok () →
      connectBlockTxs pb.txs.tail (buildUtxoMap utxos) height pb.header.timestamp chainId = .ok (sumFees, finalMap) →
      validateCoinbaseValueBound pb.coinbaseTx height alreadyGenerated sumFees = .ok () →
      validateCoinbaseApplyOutputs pb.coinbaseTx = .ok () →
      connectBlockBasic blockBytes expectedPrevHash expectedTarget height alreadyGenerated utxos chainId = .ok ()

theorem connectBlock_end_to_end_proved : connectBlockEndToEndStatement := by
  intro blockBytes expectedPrevHash expectedTarget height alreadyGenerated utxos chainId pb sumFees finalMap
    hBasic hParse hLock hLoop hBound hApply
  simpa [connectBlockBasic, hBasic, hParse, hLock, hLoop, hBound, hApply]

def blockBasicCheckWithFees
    (blockBytes : Bytes)
    (expectedPrevHash : Option Bytes)
    (expectedTarget : Option Bytes)
    (height : Nat)
    (alreadyGenerated : Nat)
    (sumFees : Nat) : Except String Unit := do
  BlockBasicV1.validateBlockBasic blockBytes expectedPrevHash expectedTarget
  let pb ← BlockBasicV1.parseBlock blockBytes
  validateCoinbaseLocktime pb.coinbaseTx height
  validateCoinbaseValueBound pb.coinbaseTx height alreadyGenerated sumFees
  pure ()

end SubsidyV1

end RubinFormal

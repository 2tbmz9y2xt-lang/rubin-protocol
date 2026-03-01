import RubinFormal.Types
import RubinFormal.BlockBasicV1
import RubinFormal.UtxoBasicV1

namespace RubinFormal

namespace SubsidyV1

open RubinFormal
open RubinFormal.BlockBasicV1
open RubinFormal.UtxoBasicV1

-- Consensus constants (mirror clients/go/consensus/constants.go).
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

def connectBlockBasic
    (blockBytes : Bytes)
    (expectedPrevHash : Option Bytes)
    (expectedTarget : Option Bytes)
    (height : Nat)
    (alreadyGenerated : Nat)
    (utxos : List (Outpoint × UtxoEntry))
    (chainId : Bytes) : Except String Unit := do
  BlockBasicV1.validateBlockBasic blockBytes expectedPrevHash expectedTarget
  let pb ← BlockBasicV1.parseBlock blockBytes
  validateCoinbaseLocktime pb.coinbaseTx height

  let mut utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint := buildUtxoMap utxos
  let mut sumFees : Nat := 0
  for txBytes in pb.txs.drop 1 do
    let (fee, next) ← applyNonCoinbaseTxBasicState txBytes utxoMap height pb.header.timestamp chainId false
    sumFees := sumFees + fee
    utxoMap := next

  validateCoinbaseValueBound pb.coinbaseTx height alreadyGenerated sumFees
  pure ()

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

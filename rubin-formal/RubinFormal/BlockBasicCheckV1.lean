import Std
import RubinFormal.BlockBasicV1
import RubinFormal.ByteWireV2
import RubinFormal.UtxoBasicV1

namespace RubinFormal

open Wire
open RubinFormal.BlockBasicV1

namespace BlockBasicCheckV1

def MAX_FUTURE_DRIFT : Nat := 7200

def enforceSigSuiteActivation (txs : List Bytes) (blockHeight : Nat) : Except String Unit := do
  if blockHeight < RubinFormal.UtxoBasicV1.SLH_DSA_ACTIVATION_HEIGHT then
    for tx in txs do
      let t ← RubinFormal.UtxoBasicV1.parseTx tx
      for w in t.witness do
        if w.suiteId == RubinFormal.UtxoBasicV1.SUITE_ID_SLH_DSA_SHAKE_256F then
          throw "TX_ERR_SIG_ALG_INVALID"
  pure ()

def insertNat (x : Nat) : List Nat → List Nat
  | [] => [x]
  | y :: ys =>
      if x ≤ y then
        x :: y :: ys
      else
        y :: insertNat x ys

def sortNat : List Nat → List Nat
  | [] => []
  | x :: xs => insertNat x (sortNat xs)

def medianTimePast (prevTimestamps : List Nat) : Except String Nat := do
  if prevTimestamps.isEmpty then
    throw "BLOCK_ERR_PARSE"
  let sorted := sortNat prevTimestamps
  pure (sorted.get! (sorted.length / 2))

def timestampBounds (mtp ts : Nat) : Except String Unit := do
  if ts <= mtp then
    throw "BLOCK_ERR_TIMESTAMP_OLD"
  if ts > mtp + MAX_FUTURE_DRIFT then
    throw "BLOCK_ERR_TIMESTAMP_FUTURE"
  pure ()

def txNonceFromTxBytes (tx : Bytes) : Except String Nat := do
  let c0 : Cursor := { bs := tx, off := 0 }
  let (_, c1) ←
    match c0.getU32le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (_, c2) ←
    match c1.getU8? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (nonce64, _) ←
    match c2.getU64le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  pure nonce64.toNat

def anyDuplicate (xs : List Nat) : Bool :=
  let rec go (rest : List Nat) (seen : List Nat) : Bool :=
    match rest with
    | [] => false
    | x :: rs => if seen.contains x then true else go rs (seen ++ [x])
  go xs []

def nonceReplayCheck (txs : List Bytes) : Except String Unit := do
  let mut nonces : List Nat := []
  for tx in txs do
    let n ← txNonceFromTxBytes tx
    nonces := nonces ++ [n]
  if anyDuplicate nonces then
    throw "TX_ERR_NONCE_REPLAY"
  pure ()

def validateBlockBasicCheck
    (blockBytes : Bytes)
    (expectedPrevHash : Option Bytes)
    (expectedTarget : Option Bytes)
    (blockHeight : Nat)
    (prevTimestamps : List Nat) : Except String Unit := do
  let pb ← BlockBasicV1.parseBlock blockBytes

  -- signature suite activation (CV-SIG gate): SLH-DSA MUST NOT appear before activation height.
  enforceSigSuiteActivation pb.txs blockHeight

  -- validate the same basic invariants as BlockBasicV1.validateBlockBasic, but keep pb for extra checks.
  match expectedPrevHash with
  | none => pure ()
  | some exp =>
      if pb.header.prevHash != exp then throw "BLOCK_ERR_LINKAGE_INVALID"

  let mr ← BlockBasicV1.merkleRootTxids pb.txids
  if mr != pb.header.merkleRoot then throw "BLOCK_ERR_MERKLE_INVALID"

  BlockBasicV1.powCheck pb.header

  match expectedTarget with
  | none => pure ()
  | some exp =>
      if pb.header.target != exp then throw "BLOCK_ERR_TARGET_INVALID"

  let wmr ← BlockBasicV1.witnessMerkleRootWtxids pb.wtxids
  let expectCommit := BlockBasicV1.witnessCommitmentHash wmr
  let gotCommit ← BlockBasicV1.findCoinbaseAnchorCommitment pb.coinbaseTx
  if gotCommit != expectCommit then throw "BLOCK_ERR_WITNESS_COMMITMENT"

  -- extra checks used by block_basic_check op in conformance:
  -- - timestamp bounds (MTP + max drift)
  let mtp ← medianTimePast prevTimestamps
  timestampBounds mtp pb.header.timestamp

  -- - intrablock nonce replay check
  nonceReplayCheck pb.txs

  pure ()

end BlockBasicCheckV1

end RubinFormal

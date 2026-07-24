import Std
import RubinFormal.BlockBasicV1
import RubinFormal.ByteWireV2
import RubinFormal.UtxoBasicV1

namespace RubinFormal

open Wire
open RubinFormal.BlockBasicV1

namespace BlockBasicCheckV1

def MAX_FUTURE_DRIFT : Nat := 7200

def enforceSigSuiteActivation (_txs : List Bytes) (_blockHeight : Nat) : Except String Unit :=
  -- Legacy structural no-op: retired profiles, including CORE_EXT, are not active or supported.
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

def timestampBounds (mtp ts : Nat) : Except String Unit :=
  if ts <= mtp then
    .error "BLOCK_ERR_TIMESTAMP_OLD"
  else if ts > mtp + MAX_FUTURE_DRIFT then
    .error "BLOCK_ERR_TIMESTAMP_FUTURE"
  else
    .ok ()

theorem timestampBounds_ok_iff (mtp ts : Nat) :
    timestampBounds mtp ts = .ok () ↔ mtp < ts ∧ ts ≤ mtp + MAX_FUTURE_DRIFT := by
  unfold timestampBounds
  by_cases hOld : ts ≤ mtp
  · have hNotGt : ¬ mtp < ts := Nat.not_lt_of_ge hOld
    simp [hOld, hNotGt]
  · have hGt : mtp < ts := Nat.lt_of_not_ge hOld
    by_cases hFuture : ts > mtp + MAX_FUTURE_DRIFT
    · have hNotLe : ¬ ts ≤ mtp + MAX_FUTURE_DRIFT := Nat.not_le_of_gt hFuture
      simp [hOld, hFuture, hGt, hNotLe]
    · have hLe : ts ≤ mtp + MAX_FUTURE_DRIFT := Nat.le_of_not_gt hFuture
      simp [hOld, hFuture, hGt, hLe]

theorem timestampBounds_old_iff (mtp ts : Nat) :
    timestampBounds mtp ts = .error "BLOCK_ERR_TIMESTAMP_OLD" ↔ ts ≤ mtp := by
  unfold timestampBounds
  by_cases hOld : ts ≤ mtp
  · simp [hOld]
  · have hGt : mtp < ts := Nat.lt_of_not_ge hOld
    by_cases hFuture : ts > mtp + MAX_FUTURE_DRIFT
    · have hErrNe : ("BLOCK_ERR_TIMESTAMP_FUTURE" : String) ≠ "BLOCK_ERR_TIMESTAMP_OLD" := by
        decide
      simp [hOld, hFuture, hGt, hErrNe]
    · simp [hOld, hFuture, hGt]

theorem timestampBounds_future_iff (mtp ts : Nat) :
    timestampBounds mtp ts = .error "BLOCK_ERR_TIMESTAMP_FUTURE" ↔ mtp < ts ∧ mtp + MAX_FUTURE_DRIFT < ts := by
  unfold timestampBounds
  by_cases hOld : ts ≤ mtp
  · have hNotGt : ¬ mtp < ts := Nat.not_lt_of_ge hOld
    have hErrNe : ("BLOCK_ERR_TIMESTAMP_OLD" : String) ≠ "BLOCK_ERR_TIMESTAMP_FUTURE" := by
      decide
    simp [hOld, hNotGt, hErrNe]
  · have hGt : mtp < ts := Nat.lt_of_not_ge hOld
    by_cases hFuture : ts > mtp + MAX_FUTURE_DRIFT
    · simp [hOld, hFuture, hGt]
    · have hNotFuture : ¬ mtp + MAX_FUTURE_DRIFT < ts := hFuture
      simp [hOld, hFuture, hGt, hNotFuture]

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

def anyDuplicateAcc (rest : List Nat) (seen : List Nat) : Bool :=
  match rest with
  | [] => false
  | x :: rs => if seen.contains x then true else anyDuplicateAcc rs (seen ++ [x])

def anyDuplicate (xs : List Nat) : Bool :=
  anyDuplicateAcc xs []

def collectNonces : List Bytes → Except String (List Nat)
  | [] => pure []
  | tx :: rest => do
      let nonce ← txNonceFromTxBytes tx
      let nonces ← collectNonces rest
      pure (nonce :: nonces)

def nonceReplayCheck (txs : List Bytes) : Except String Unit := do
  let nonces ← collectNonces txs
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

  -- Signature-suite activation gate (no-op; kept for legacy structure).
  enforceSigSuiteActivation pb.txs blockHeight

  -- §25 step order (post-PR#418): pow → target → linkage → merkle → witness_commitment → timestamp
  BlockBasicV1.powCheck pb.header

  match expectedTarget with
  | none => pure ()
  | some exp =>
      if pb.header.target != exp then throw "BLOCK_ERR_TARGET_INVALID"

  match expectedPrevHash with
  | none => pure ()
  | some exp =>
      if pb.header.prevHash != exp then throw "BLOCK_ERR_LINKAGE_INVALID"

  let mr ← BlockBasicV1.merkleRootTxids pb.txids
  if mr != pb.header.merkleRoot then throw "BLOCK_ERR_MERKLE_INVALID"

  let wmr ← BlockBasicV1.witnessMerkleRootWtxids pb.wtxids
  let expectCommit := BlockBasicV1.witnessCommitmentHash wmr
  match BlockBasicV1.findCoinbaseAnchorCommitment pb.coinbaseTx with
  | .ok gotCommit =>
      if gotCommit != expectCommit then throw "BLOCK_ERR_WITNESS_COMMITMENT"
  | .error _ =>
      BlockBasicV1.findMatchingCoinbaseAnchorCommitment pb.coinbaseTx expectCommit

  -- extra checks used by block_basic_check op in conformance:
  -- - timestamp bounds (MTP + max drift)
  let mtp ← medianTimePast prevTimestamps
  timestampBounds mtp pb.header.timestamp

  -- - intrablock nonce replay check
  nonceReplayCheck pb.txs

  pure ()

end BlockBasicCheckV1

end RubinFormal

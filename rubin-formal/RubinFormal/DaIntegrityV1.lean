import RubinFormal.Types
import RubinFormal.SHA3_256
import RubinFormal.ByteWireV2
import RubinFormal.TxWeightV2
import RubinFormal.BlockBasicV1

namespace RubinFormal

open Wire

namespace DaIntegrityV1

def MAX_DA_MANIFEST_BYTES_PER_TX : Nat := RubinFormal.TxWeightV2.MAX_DA_MANIFEST_BYTES_PER_TX
def CHUNK_BYTES : Nat := RubinFormal.TxWeightV2.CHUNK_BYTES
def MAX_DA_CHUNK_COUNT : Nat := RubinFormal.TxWeightV2.MAX_DA_CHUNK_COUNT
def MAX_DA_BATCHES_PER_BLOCK : Nat := 128

def COV_TYPE_DA_COMMIT : Nat := 0x0103

def cmpBytes (a b : Bytes) : Ordering :=
  let rec go (xs ys : List UInt8) : Ordering :=
    match xs, ys with
    | [], [] => .eq
    | [], _ => .lt
    | _, [] => .gt
    | x :: xs', y :: ys' =>
        if x < y then .lt else if x > y then .gt else go xs' ys'
  go a.data.toList b.data.toList

structure TxOut where
  covenantType : Nat
  covenantData : Bytes
deriving Repr, DecidableEq

structure DaCommitInfo where
  chunkCount : Nat
  outputs : List TxOut
deriving Repr, DecidableEq

structure DaChunkInfo where
  chunkIndex : Nat
  chunkHash : Bytes
  payload : Bytes
deriving Repr, DecidableEq

structure ParsedDATx where
  txKind : Nat
  commitDaId : Option Bytes
  commitChunkCount : Option Nat
  chunkDaId : Option Bytes
  chunkIndex : Option Nat
  chunkHash : Option Bytes
  outputs : List TxOut
  payload : Bytes
deriving Repr, DecidableEq

def requireMinimal (minimal : Bool) : Option Unit :=
  if minimal then some () else none

def parseOutputsLite (c : Cursor) (n : Nat) : Option (List TxOut × Cursor) := do
  let mut cur := c
  let mut outs : List TxOut := []
  for _ in [0:n] do
    let (_, cur1) ← cur.getBytes? 8
    let (ctRaw, cur2) ← cur1.getBytes? 2
    let covenantType := Wire.u16le? (ctRaw.get! 0) (ctRaw.get! 1)
    let (cdLen, cur3, minimal) ← cur2.getCompactSize?
    let _ ← requireMinimal minimal
    let (cd, cur4) ← cur3.getBytes? cdLen
    outs := outs.concat { covenantType := covenantType, covenantData := cd }
    cur := cur4
  pure (outs, cur)

def parseDaCommitCore (c : Cursor) : Option (Bytes × Nat × Cursor) := do
  let (daId, c1) ← c.getBytes? 32
  let (ccRaw, c2) ← c1.getBytes? 2
  let chunkCount := Wire.u16le? (ccRaw.get! 0) (ccRaw.get! 1)
  if chunkCount < 1 || chunkCount > MAX_DA_CHUNK_COUNT then
    none
  let (_, c3) ← c2.getBytes? 32
  let (_, c4) ← c3.getBytes? 8
  let (_, c5) ← c4.getBytes? 32
  let (_, c6) ← c5.getBytes? 32
  let (_, c7) ← c6.getBytes? 32
  let (_, c8) ← c7.getBytes? 1
  let (sigLen, c9, minimal) ← c8.getCompactSize?
  let _ ← requireMinimal minimal
  if sigLen > MAX_DA_MANIFEST_BYTES_PER_TX then
    none
  let (_, c10) ← c9.getBytes? sigLen
  pure (daId, chunkCount, c10)

def parseDaChunkCore (c : Cursor) : Option (Bytes × Nat × Bytes × Cursor) := do
  let (daId, c1) ← c.getBytes? 32
  let (idxRaw, c2) ← c1.getBytes? 2
  let idx := Wire.u16le? (idxRaw.get! 0) (idxRaw.get! 1)
  let (h, c3) ← c2.getBytes? 32
  pure (daId, idx, h, c3)

def mapWitnessErr (wErr : Wire.TxErr) : Option String :=
  if wErr == .witnessOverflow then some "TX_ERR_WITNESS_OVERFLOW"
  else if wErr == .sigAlgInvalid then some "TX_ERR_SIG_ALG_INVALID"
  else if wErr == .sigNoncanonical then some "TX_ERR_SIG_NONCANONICAL"
  else none

def parseDATx (tx : Bytes) : Except String ParsedDATx := do
  let c0 : Cursor := { bs := tx, off := 0 }
  let (_, c1) ←
    match c0.getU32le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (tkB, c2) ←
    match c1.getU8? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let tk := tkB.toNat
  if !(tk == 0x00 || tk == 0x01 || tk == 0x02) then throw "TX_ERR_PARSE"
  let (_, c3) ←
    match c2.getU64le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (inCount, c4, minIn) ←
    match c3.getCompactSize? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if !minIn then throw "TX_ERR_PARSE"
  let c5 ←
    match RubinFormal.TxWeightV2.parseInputsSkip c4 inCount with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (outCount, c6, minOut) ←
    match c5.getCompactSize? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if !minOut then throw "TX_ERR_PARSE"
  let (outs, c7) ←
    match parseOutputsLite c6 outCount with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (_, c8) ←
    match c7.getU32le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x

  let mut commitDaId : Option Bytes := none
  let mut commitChunkCount : Option Nat := none
  let mut chunkDaId : Option Bytes := none
  let mut chunkIndex : Option Nat := none
  let mut chunkHash : Option Bytes := none
  let c9 ←
    if tk == 0x00 then
      pure c8
    else if tk == 0x01 then
      match parseDaCommitCore c8 with
      | none => throw "TX_ERR_PARSE"
      | some (daId, cc, c') =>
          commitDaId := some daId
          commitChunkCount := some cc
          pure c'
    else
      match parseDaChunkCore c8 with
      | none => throw "TX_ERR_PARSE"
      | some (daId, idx, h, c') =>
          chunkDaId := some daId
          chunkIndex := some idx
          chunkHash := some h
          pure c'

  let (cW, wErr, wStart, wEnd, _ml, _slh) ←
    match RubinFormal.TxWeightV2.parseWitnessSectionForWeight c9 with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let witBytes := wEnd - wStart
  if witBytes > RubinFormal.TxWeightV2.MAX_WITNESS_BYTES_PER_TX then throw "TX_ERR_WITNESS_OVERFLOW"
  match mapWitnessErr wErr with
  | some e => throw e
  | none => pure ()

  let (daLen, c10, minDa) ←
    match cW.getCompactSize? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if !minDa then throw "TX_ERR_PARSE"
  if tk == 0x00 then
    if daLen != 0 then throw "TX_ERR_PARSE"
  else if tk == 0x01 then
    if daLen > MAX_DA_MANIFEST_BYTES_PER_TX then throw "TX_ERR_PARSE"
  else
    if daLen < 1 || daLen > CHUNK_BYTES then throw "TX_ERR_PARSE"
  let (payload, c11) ←
    match c10.getBytes? daLen with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if c11.off != tx.size then
    throw "TX_ERR_PARSE"

  pure {
    txKind := tk
    commitDaId := commitDaId
    commitChunkCount := commitChunkCount
    chunkDaId := chunkDaId
    chunkIndex := chunkIndex
    chunkHash := chunkHash
    outputs := outs
    payload := payload
  }

def validateDASetIntegrity (txs : List Bytes) : Except String Unit := do
  let mut commits : Std.RBMap Bytes DaCommitInfo cmpBytes := Std.RBMap.empty
  let mut chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes := Std.RBMap.empty

  for txBytes in txs do
    let t ← parseDATx txBytes
    if t.txKind == 0x01 then
      let daId ← match t.commitDaId with | some x => pure x | none => throw "TX_ERR_PARSE"
      let cc ← match t.commitChunkCount with | some x => pure x | none => throw "TX_ERR_PARSE"
      if commits.contains daId then
        throw "BLOCK_ERR_DA_SET_INVALID"
      commits := commits.insert daId { chunkCount := cc, outputs := t.outputs }
    else if t.txKind == 0x02 then
      let daId ← match t.chunkDaId with | some x => pure x | none => throw "TX_ERR_PARSE"
      let idx ← match t.chunkIndex with | some x => pure x | none => throw "TX_ERR_PARSE"
      let h ← match t.chunkHash with | some x => pure x | none => throw "TX_ERR_PARSE"
      if SHA3.sha3_256 t.payload != h then
        throw "BLOCK_ERR_DA_CHUNK_HASH_INVALID"
      let set := match chunks.find? daId with | none => Std.RBMap.empty | some m => m
      if set.contains idx then
        throw "BLOCK_ERR_DA_SET_INVALID"
      chunks := chunks.insert daId (set.insert idx { chunkIndex := idx, chunkHash := h, payload := t.payload })

  if commits.size > MAX_DA_BATCHES_PER_BLOCK then
    throw "BLOCK_ERR_DA_BATCH_EXCEEDED"

  for (daId, _) in chunks.toList do
    if !(commits.contains daId) then
      throw "BLOCK_ERR_DA_SET_INVALID"

  for (daId, cinfo) in commits.toList do
    let set? := chunks.find? daId
    let set ← match set? with | none => throw "BLOCK_ERR_DA_INCOMPLETE" | some m => pure m
    if set.size != cinfo.chunkCount then
      throw "BLOCK_ERR_DA_INCOMPLETE"
    let mut concat : Bytes := ByteArray.empty
    for i in [0:cinfo.chunkCount] do
      let ch? := set.find? i
      let ch ← match ch? with | none => throw "BLOCK_ERR_DA_INCOMPLETE" | some x => pure x
      concat := concat ++ ch.payload
    let payloadCommit := SHA3.sha3_256 concat

    let mut daCommitOutputs : Nat := 0
    let mut got : Bytes := ByteArray.empty
    for o in cinfo.outputs do
      if o.covenantType == COV_TYPE_DA_COMMIT then
        daCommitOutputs := daCommitOutputs + 1
        if o.covenantData.size == 32 then
          got := o.covenantData
    if daCommitOutputs != 1 then
      throw "BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID"
    if got != payloadCommit then
      throw "BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID"

  pure ()

def validateDaIntegrityGate
    (blockBytes : Bytes)
    (expectedPrevHash : Option Bytes)
    (expectedTarget : Option Bytes) : Except String Unit := do
  BlockBasicV1.validateBlockBasic blockBytes expectedPrevHash expectedTarget
  let pb ← BlockBasicV1.parseBlock blockBytes
  validateDASetIntegrity pb.txs

end DaIntegrityV1

end RubinFormal

import RubinFormal.Types
import RubinFormal.SHA3_256
import RubinFormal.ByteWireV2
import RubinFormal.TxWeightV2
import RubinFormal.DaCoreV1
import RubinFormal.BlockBasicV1

namespace RubinFormal

open Wire

namespace DaIntegrityV1

def MAX_DA_MANIFEST_BYTES_PER_TX : Nat := RubinFormal.DaCoreV1.MAX_DA_MANIFEST_BYTES_PER_TX
def CHUNK_BYTES : Nat := RubinFormal.DaCoreV1.CHUNK_BYTES
def MAX_DA_CHUNK_COUNT : Nat := RubinFormal.DaCoreV1.MAX_DA_CHUNK_COUNT
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
  duplicate : Bool := false
deriving Repr, DecidableEq

structure DaChunkInfo where
  chunkIndex : Nat
  chunkHash : Bytes
  payload : Bytes
  duplicate : Bool := false
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

/-- Validate witness-section errors after structural parsing in `parseDATx`.
    Returns witness overflow, invalid algorithm, noncanonical signature, or success. -/
def validateWitnessErrors (ws : TxWeightV2.WitnessSectionResult) : Except String Unit :=
  if ws.endOff - ws.startOff > TxWeightV2.MAX_WITNESS_BYTES_PER_TX then
    .error "TX_ERR_WITNESS_OVERFLOW"
  else if ws.isOverflow then
    .error "TX_ERR_WITNESS_OVERFLOW"
  else if ws.anySigAlgInvalid then
    .error "TX_ERR_SIG_ALG_INVALID"
  else if ws.anySigNoncanonical then
    .error "TX_ERR_SIG_NONCANONICAL"
  else .ok ()

/-- Phase 1: structure parsing + DA core fields. Only TX_ERR_PARSE.
    Explicit match (no do) for formal taxonomy proof. -/
structure DATxPhase1Result where
  tk : Nat
  outs : List TxOut
  commitDaId : Option Bytes
  commitChunkCount : Option Nat
  chunkDaId : Option Bytes
  chunkIndex : Option Nat
  chunkHash : Option Bytes
  witnessCursor : Cursor

def parseDATxPhase1 (tx : Bytes) : Except String DATxPhase1Result :=
  let c0 : Cursor := { bs := tx, off := 0 }
  match c0.getU32le? with
  | none => .error "TX_ERR_PARSE"
  | some (_, c1) =>
    match c1.getU8? with
    | none => .error "TX_ERR_PARSE"
    | some (tkB, c2) =>
      let tk := tkB.toNat
      if !(tk == 0x00 || tk == 0x01 || tk == 0x02) then .error "TX_ERR_PARSE"
      else match c2.getU64le? with
        | none => .error "TX_ERR_PARSE"
        | some (_, c3) =>
          match c3.getCompactSize? with
          | none => .error "TX_ERR_PARSE"
          | some (inCount, c4, minIn) =>
            if !minIn then .error "TX_ERR_PARSE"
            else match TxWeightV2.parseInputsSkip c4 inCount with
              | none => .error "TX_ERR_PARSE"
              | some c5 =>
                match c5.getCompactSize? with
                | none => .error "TX_ERR_PARSE"
                | some (outCount, c6, minOut) =>
                  if !minOut then .error "TX_ERR_PARSE"
                  else match parseOutputsLite c6 outCount with
                    | none => .error "TX_ERR_PARSE"
                    | some (outs, c7) =>
                      match c7.getU32le? with
                      | none => .error "TX_ERR_PARSE"
                      | some (_, c8) =>
                        if tk == 0x00 then
                          .ok { tk, outs, commitDaId := none, commitChunkCount := none,
                                chunkDaId := none, chunkIndex := none, chunkHash := none,
                                witnessCursor := c8 }
                        else if tk == 0x01 then
                          match parseDaCommitCore c8 with
                          | none => .error "TX_ERR_PARSE"
                          | some (daId, cc, c') =>
                            .ok { tk, outs, commitDaId := some daId, commitChunkCount := some cc,
                                  chunkDaId := none, chunkIndex := none, chunkHash := none,
                                  witnessCursor := c' }
                        else
                          match parseDaChunkCore c8 with
                          | none => .error "TX_ERR_PARSE"
                          | some (daId, idx, h, c') =>
                            .ok { tk, outs, commitDaId := none, commitChunkCount := none,
                                  chunkDaId := some daId, chunkIndex := some idx,
                                  chunkHash := some h, witnessCursor := c' }

/-- Phase 3: DA payload parsing. Only TX_ERR_PARSE.
    Explicit match (no do) for formal taxonomy proof. -/
def parseDATxPhase3 (tk daLen : Nat) (c10 : Cursor) (minDa : Bool) (txSize : Nat)
    : Except String (Bytes × Cursor) :=
  if !minDa then .error "TX_ERR_PARSE"
  else if tk == 0x00 && daLen != 0 then .error "TX_ERR_PARSE"
  else if tk == 0x01 && daLen > MAX_DA_MANIFEST_BYTES_PER_TX then .error "TX_ERR_PARSE"
  else if tk != 0x00 && tk != 0x01 && (daLen < 1 || daLen > CHUNK_BYTES) then .error "TX_ERR_PARSE"
  else match c10.getBytes? daLen with
    | none => .error "TX_ERR_PARSE"
    | some (payload, c11) =>
      if c11.off != txSize then .error "TX_ERR_PARSE"
      else .ok (payload, c11)

/-- Compose phases into parseDATx.
    Phase 1 (structure) → Phase 2 (witness) → Phase 3 (payload). -/
def parseDATx (tx : Bytes) : Except String ParsedDATx :=
  match parseDATxPhase1 tx with
  | .error e => .error e
  | .ok p1 =>
    match TxWeightV2.parseWitnessSectionForWeight p1.witnessCursor with
    | none => .error "TX_ERR_PARSE"
    | some ws =>
      match validateWitnessErrors ws with
      | .error e => .error e
      | .ok () =>
        match ws.cursor.getCompactSize? with
        | none => .error "TX_ERR_PARSE"
        | some (daLen, c10, minDa) =>
          match parseDATxPhase3 p1.tk daLen c10 minDa tx.size with
          | .error e => .error e
          | .ok (payload, _) =>
            .ok { txKind := p1.tk
                , commitDaId := p1.commitDaId
                , commitChunkCount := p1.commitChunkCount
                , chunkDaId := p1.chunkDaId
                , chunkIndex := p1.chunkIndex
                , chunkHash := p1.chunkHash
                , outputs := p1.outs
                , payload := payload }

/-- Parse each bounded block transaction exactly once, preserving order. -/
def parseDATxs : List Bytes → Except String (List ParsedDATx)
  | [] => .ok []
  | tx :: rest => do pure ((← parseDATx tx) :: (← parseDATxs rest))

/-- Enforce the live per-block DA batch limit. -/
def validateDaBatchCount (commitCount : Nat) : Except String Unit :=
  if commitCount > MAX_DA_BATCHES_PER_BLOCK then
    Except.error "BLOCK_ERR_DA_BATCH_EXCEEDED"
  else Except.ok ()

/-- Require every collected chunk set to have a matching commit. -/
def validateNoOrphanChunks
    (chunkList : List (Bytes × Std.RBMap Nat DaChunkInfo compare))
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes) : Except String Unit :=
  match chunkList with
  | [] => .ok ()
  | (daId, _) :: rest =>
    if !(commits.contains daId) then .error "BLOCK_ERR_DA_SET_INVALID"
    else validateNoOrphanChunks rest commits

/-- Require the embedded chunk hash to match its payload. -/
def validateChunkHash (payload hash : Bytes) : Except String Unit :=
  if SHA3.sha3_256 payload != hash then
    Except.error "BLOCK_ERR_DA_CHUNK_HASH_INVALID"
  else Except.ok ()

/-- Compatibility proof leaf for duplicate commit lookup.
    The live pipeline marks duplicates during collection and does not call it. -/
def validateNoDuplicateCommit
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes) (daId : Bytes) : Except String Unit :=
  if commits.contains daId then Except.error "BLOCK_ERR_DA_SET_INVALID"
  else Except.ok ()

/-- Compatibility proof leaf for duplicate chunk lookup.
    The live pipeline marks duplicates during collection and does not call it. -/
def validateNoDuplicateChunk
    (set : Std.RBMap Nat DaChunkInfo compare) (idx : Nat) : Except String Unit :=
  if set.contains idx then Except.error "BLOCK_ERR_DA_INCOMPLETE"
  else Except.ok ()

/-- Count DA_COMMIT outputs and extract the single commit hash.
    Returns (count, hash_or_empty). Pure function for proof access. -/
def countDaCommitOutputs (outputs : List TxOut) : Nat × Bytes :=
  outputs.foldl (fun (acc : Nat × Bytes) o =>
    if o.covenantType == COV_TYPE_DA_COMMIT then
      let count := acc.1 + 1
      let got := if o.covenantData.size == 32 then o.covenantData else acc.2
      (count, got)
    else acc
  ) (0, ByteArray.empty)

/-- Require exactly one DA_COMMIT output with the expected payload commitment. -/
def validateCommitOutput (outputs : List TxOut) (payloadCommit : Bytes)
    : Except String Unit :=
  let (count, got) := countDaCommitOutputs outputs
  if count != 1 then Except.error "BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID"
  else if got != payloadCommit then Except.error "BLOCK_ERR_DA_PAYLOAD_COMMIT_INVALID"
  else Except.ok ()

/-- Require the collected chunk count to match the commit declaration. -/
def validateChunkCountMatch (setSize chunkCount : Nat) : Except String Unit :=
  if setSize != chunkCount then Except.error "BLOCK_ERR_DA_INCOMPLETE"
  else Except.ok ()

/-- Collect payloads in index order, rejecting a missing index. -/
def collectChunkPayloads
    (set : Std.RBMap Nat DaChunkInfo compare) (count : Nat)
    (acc : Bytes := ByteArray.empty) (start : Nat := 0)
    : Except String Bytes :=
  match count with
  | 0 => .ok acc
  | n + 1 =>
    match set.find? start with
    | none => .error "BLOCK_ERR_DA_INCOMPLETE"
    | some ch => collectChunkPayloads set n (acc ++ ch.payload) (start + 1)

/-- Collect one commit, retaining the first record and marking a duplicate ID.
    Structural errors are selected only after the full collection. -/
def processCommitTx
    (t : ParsedDATx)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    : Except String (Std.RBMap Bytes DaCommitInfo cmpBytes) :=
  match t.commitDaId with
  | none => .error "TX_ERR_PARSE"
  | some daId =>
    match t.commitChunkCount with
    | none => .error "TX_ERR_PARSE"
    | some cc =>
      match commits.find? daId with
      | none => .ok (commits.insert daId { chunkCount := cc, outputs := t.outputs })
      | some old => .ok (commits.insert daId { old with duplicate := true })

/-- Collect one chunk, retaining the first record and marking a duplicate index.
    Hashes are checked globally before this structural collection. -/
def processChunkTx
    (t : ParsedDATx)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    : Except String (Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes) :=
  match t.chunkDaId with
  | none => .error "TX_ERR_PARSE"
  | some daId =>
    match t.chunkIndex with
    | none => .error "TX_ERR_PARSE"
    | some idx =>
      match t.chunkHash with
      | none => .error "TX_ERR_PARSE"
      | some h =>
        let set := match chunks.find? daId with | none => Std.RBMap.empty | some m => m
        match set.find? idx with
        | none => .ok (chunks.insert daId (set.insert idx { chunkIndex := idx, chunkHash := h, payload := t.payload }))
        | some old => .ok (chunks.insert daId (set.insert idx { old with duplicate := true }))

/-- Bounded structural collection after the global chunk-hash pass.
    It records duplicate IDs and indices without selecting a step-11 error. -/
def accumulateDATxs
    (txs : List ParsedDATx)
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes)
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    : Except String (Std.RBMap Bytes DaCommitInfo cmpBytes ×
                      Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes) :=
  match txs with
  | [] => .ok (commits, chunks)
  | t :: rest =>
    if t.txKind == 0x01 then
      match processCommitTx t commits with
      | .error e => .error e
      | .ok newCommits => accumulateDATxs rest newCommits chunks
    else if t.txKind == 0x02 then
      match processChunkTx t chunks with
      | .error e => .error e
      | .ok newChunks => accumulateDATxs rest commits newChunks
    else accumulateDATxs rest commits chunks

/-- Complete global step 10 in transaction order before structural collection. -/
def validateAllChunkHashes (txs : List ParsedDATx) : Except String Unit := do
  for t in txs do
    if t.txKind == 0x02 then
      match t.chunkHash with
      | none => throw "TX_ERR_PARSE"
      | some h => validateChunkHash t.payload h

def validateNoCollectedDuplicateCommits
    (commits : Std.RBMap Bytes DaCommitInfo cmpBytes) : Except String Unit :=
  if commits.toList.any (fun x => x.2.duplicate) then .error "BLOCK_ERR_DA_SET_INVALID"
  else .ok ()

def validateNoCollectedDuplicateChunks
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes) : Except String Unit :=
  if chunks.toList.any (fun x => x.2.toList.any (fun y => y.2.duplicate)) then .error "BLOCK_ERR_DA_INCOMPLETE"
  else .ok ()

def validateChunkIndexes
    (set : Std.RBMap Nat DaChunkInfo compare) (count start : Nat) : Except String Unit := do
  for offset in [0:count] do
    match set.find? (start + offset) with
    | none => throw "BLOCK_ERR_DA_INCOMPLETE"
    | some _ => pure ()

def validateRequiredChunkIndexes
    (commitList : List (Bytes × DaCommitInfo))
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    : Except String Unit := do
  for (daId, cinfo) in commitList do
    match chunks.find? daId with
    | none => throw "BLOCK_ERR_DA_INCOMPLETE"
    | some set => do
      validateChunkCountMatch set.size cinfo.chunkCount
      validateChunkIndexes set cinfo.chunkCount 0

def validateCommitChunkCounts (commitList : List (Bytes × DaCommitInfo)) : Except String Unit := do
  for (_, cinfo) in commitList do
    if cinfo.chunkCount < 1 || cinfo.chunkCount > MAX_DA_CHUNK_COUNT then
      throw "TX_ERR_PARSE"

/-- Global step 12: payload commitments run only after structural success. -/
def verifyCommitIntegrity
    (commitList : List (Bytes × DaCommitInfo))
    (chunks : Std.RBMap Bytes (Std.RBMap Nat DaChunkInfo compare) cmpBytes)
    : Except String Unit :=
  match commitList with
  | [] => .ok ()
  | (daId, cinfo) :: rest =>
    match chunks.find? daId with
    | none => .error "BLOCK_ERR_DA_INCOMPLETE"
    | some set =>
      match collectChunkPayloads set cinfo.chunkCount with
      | .error e => .error e
      | .ok concat =>
        let payloadCommit := SHA3.sha3_256 concat
        match validateCommitOutput cinfo.outputs payloadCommit with
        | .error e => .error e
        | .ok () => verifyCommitIntegrity rest chunks

/-- Full DA integrity: step 10 hash pass; collection; ordered global step 11;
    then step 12 payload commitments. -/
def validateDASetIntegrity (txs : List Bytes) : Except String Unit := do
  let parsed ← parseDATxs txs
  validateAllChunkHashes parsed
  let (commits, chunks) ← accumulateDATxs parsed Std.RBMap.empty Std.RBMap.empty
  validateNoOrphanChunks chunks.toList commits
  validateNoCollectedDuplicateCommits commits
  validateNoCollectedDuplicateChunks chunks
  validateRequiredChunkIndexes commits.toList chunks
  validateDaBatchCount commits.size
  validateCommitChunkCounts commits.toList
  verifyCommitIntegrity commits.toList chunks

def validateDaIntegrityGate
    (blockBytes : Bytes)
    (expectedPrevHash : Option Bytes)
    (expectedTarget : Option Bytes) : Except String Unit := do
  BlockBasicV1.validateBlockBasic blockBytes expectedPrevHash expectedTarget
  let pb ← BlockBasicV1.parseBlock blockBytes
  validateDASetIntegrity pb.txs

end DaIntegrityV1

end RubinFormal

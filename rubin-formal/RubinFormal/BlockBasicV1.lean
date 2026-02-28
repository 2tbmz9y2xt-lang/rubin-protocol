import RubinFormal.Types
import RubinFormal.SHA3_256
import RubinFormal.ByteWireV2
import RubinFormal.MerkleV2
import RubinFormal.PowV1
import RubinFormal.TxWeightV2

namespace RubinFormal

open Wire

namespace BlockBasicV1

def COV_TYPE_ANCHOR : Nat := 0x0002

def witnessPrefix : Bytes :=
  -- ASCII("RUBIN-WITNESS/")
  RubinFormal.bytes #[
    0x52,0x55,0x42,0x49,0x4e,0x2d,0x57,0x49,0x54,0x4e,0x45,0x53,0x53,0x2f
  ]

structure BlockHeader where
  version : Nat
  prevHash : Bytes
  merkleRoot : Bytes
  timestamp : Nat
  target : Bytes
  nonce : Nat
deriving Repr, DecidableEq

structure ParsedBlock where
  header : BlockHeader
  txs : List Bytes
  txids : List Bytes
  wtxids : List Bytes
  coinbaseTx : Bytes
deriving Repr, DecidableEq

def parseHeader (c : Cursor) : Except String (BlockHeader × Cursor) := do
  let (ver, c1) ←
    match c.getU32le? with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  let (prev, c2) ←
    match c1.getBytes? 32 with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  let (mr, c3) ←
    match c2.getBytes? 32 with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  let (ts64, c4) ←
    match c3.getU64le? with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  let (tgt, c5) ←
    match c4.getBytes? 32 with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  let (nonce64, c6) ←
    match c5.getU64le? with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  pure ({ version := ver, prevHash := prev, merkleRoot := mr, timestamp := ts64.toNat, target := tgt, nonce := nonce64.toNat }, c6)

def headerBytes (h : BlockHeader) : Bytes :=
  -- Re-serialize per CANONICAL §10.1
  let u32le (n : Nat) : Bytes :=
    let b0 : UInt8 := UInt8.ofNat (n % 256)
    let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
    let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
    let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
    RubinFormal.bytes #[b0, b1, b2, b3]
  let u64le (n : Nat) : Bytes :=
    let b0 : UInt8 := UInt8.ofNat (n % 256)
    let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
    let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
    let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
    let b4 : UInt8 := UInt8.ofNat ((n / 4294967296) % 256)
    let b5 : UInt8 := UInt8.ofNat ((n / 1099511627776) % 256)
    let b6 : UInt8 := UInt8.ofNat ((n / 281474976710656) % 256)
    let b7 : UInt8 := UInt8.ofNat ((n / 72057594037927936) % 256)
    RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7]
  u32le h.version ++ h.prevHash ++ h.merkleRoot ++ u64le h.timestamp ++ h.target ++ u64le h.nonce

def bytesToNatBE32? (bs : Bytes) : Option Nat :=
  RubinFormal.PowV1.bytesToNatBE32? bs

def powCheck (h : BlockHeader) : Except String Unit := do
  -- target range + pow check (CANONICAL §10.3)
  let _ ← RubinFormal.PowV1.powCheck (headerBytes h) h.target
  pure ()

  def parseTxFromCursor (c : Cursor) : Except String (Nat × Bytes × Bytes × Bytes × Cursor) := do
  let start := c.off
  let (ver, c1) ←
    match c.getU32le? with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  let (tkB, c2) ←
    match c1.getU8? with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  let tk := tkB.toNat
  if !(tk == 0x00 || tk == 0x01 || tk == 0x02) then throw "TX_ERR_PARSE"
  let (_, c3) ←
    match c2.getU64le? with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  let (inCount, c4, minIn) ←
    match c3.getCompactSize? with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  if !minIn then throw "TX_ERR_PARSE"
  match RubinFormal.TxWeightV2.parseInputsSkip c4 inCount with
  | none => throw "BLOCK_ERR_PARSE"
  | some c5 =>
    let (outCount, c6, minOut) ←
      match c5.getCompactSize? with
      | none => throw "BLOCK_ERR_PARSE"
      | some x => pure x
    if !minOut then throw "TX_ERR_PARSE"
    let (c7, _anchorBytes) ←
      match RubinFormal.TxWeightV2.parseOutputsForAnchor c6 outCount with
      | none => throw "BLOCK_ERR_PARSE"
      | some x => pure x
    let (_, c8) ←
      match c7.getU32le? with
      | none => throw "BLOCK_ERR_PARSE"
      | some x => pure x
    let (c9, _daCoreLen) ←
      match RubinFormal.DaCoreV1.parseDaCoreFieldsWithBytes tk c8 with
      | none => throw "TX_ERR_PARSE"
      | some x => pure x
    let coreEnd := c9.off
    let (cW, wErr, wStart, wEnd, _ml, _slh) ←
      match RubinFormal.TxWeightV2.parseWitnessSectionForWeight c9 with
      | none => throw "TX_ERR_PARSE"
      | some x => pure x
    let witBytes := wEnd - wStart
    if witBytes > RubinFormal.TxWeightV2.MAX_WITNESS_BYTES_PER_TX then throw "TX_ERR_WITNESS_OVERFLOW"
    if wErr == .witnessOverflow then throw "TX_ERR_WITNESS_OVERFLOW"
    if wErr == .sigAlgInvalid then throw "TX_ERR_SIG_ALG_INVALID"
    if wErr == .sigNoncanonical then throw "TX_ERR_SIG_NONCANONICAL"
    let (daLen, c10, minDa) ←
      match cW.getCompactSize? with
      | none => throw "BLOCK_ERR_PARSE"
      | some x => pure x
    if !minDa then throw "TX_ERR_PARSE"
    if tk == 0x00 then
      if daLen != 0 then throw "TX_ERR_PARSE"
    else if tk == 0x01 then
      if daLen > RubinFormal.DaCoreV1.MAX_DA_MANIFEST_BYTES_PER_TX then throw "TX_ERR_PARSE"
    else
      if daLen < 1 || daLen > RubinFormal.DaCoreV1.CHUNK_BYTES then throw "TX_ERR_PARSE"
    let (_, c11) ←
      match c10.getBytes? daLen with
      | none => throw "BLOCK_ERR_PARSE"
      | some x => pure x
    let endOff := c11.off
    let core := c.bs.extract start coreEnd
    let full := c.bs.extract start endOff
    let txid := SHA3.sha3_256 core
    let wtxid := SHA3.sha3_256 full
    pure (inCount, txid, wtxid, full, { c with off := endOff })

def parseBlock (blockBytes : Bytes) : Except String ParsedBlock := do
  let c0 : Cursor := { bs := blockBytes, off := 0 }
  let (hdr, c1) ← parseHeader c0
  let (txCount, c2, minimal) ←
    match c1.getCompactSize? with
    | none => throw "BLOCK_ERR_PARSE"
    | some x => pure x
  if !minimal then throw "BLOCK_ERR_PARSE"
  if txCount == 0 then throw "BLOCK_ERR_PARSE"
  let mut cur := c2
  let mut txs : List Bytes := []
  let mut txids : List Bytes := []
  let mut wtxids : List Bytes := []
  let mut coinbaseTx : Bytes := ByteArray.empty
  let mut anyZeroInputs : Bool := false
  for idx in [0:txCount] do
    let (inCount, txid, wtxid, fullTx, cur') ← parseTxFromCursor cur
    if inCount == 0 then
      anyZeroInputs := true
    if idx == 0 then
      coinbaseTx := fullTx
    txs := txs.concat fullTx
    txids := txids.concat txid
    wtxids := wtxids.concat wtxid
    cur := cur'
  if cur.off != blockBytes.size then
    throw "BLOCK_ERR_PARSE"
  if anyZeroInputs then
    throw "TX_ERR_PARSE"
  pure { header := hdr, txs := txs, txids := txids, wtxids := wtxids, coinbaseTx := coinbaseTx }

def merkleRootTxids (txids : List Bytes) : Except String Bytes := do
  if txids.isEmpty then throw "BLOCK_ERR_PARSE"
  match RubinFormal.Merkle.merkleRoot txids with
  | some r => pure r
  | none => throw "BLOCK_ERR_PARSE"

def merkleRootTagged (ids : List Bytes) (leafTag nodeTag : UInt8) : Except String Bytes := do
  if ids.isEmpty then throw "BLOCK_ERR_PARSE"
  let leaf := fun (x : Bytes) => SHA3.sha3_256 ((ByteArray.empty.push leafTag) ++ x)
  let node := fun (l r : Bytes) => SHA3.sha3_256 ((ByteArray.empty.push nodeTag) ++ l ++ r)
  let mut level : List Bytes := ids.map leaf
  while level.length > 1 do
    let mut nxt : List Bytes := []
    let mut i : Nat := 0
    while i < level.length do
      if i == level.length - 1 then
        nxt := nxt.concat (level.get! i)
        i := i + 1
      else
        nxt := nxt.concat (node (level.get! i) (level.get! (i+1)))
        i := i + 2
    level := nxt
  pure (level.get! 0)

def witnessMerkleRootWtxids (wtxids : List Bytes) : Except String Bytes := do
  if wtxids.isEmpty then throw "BLOCK_ERR_PARSE"
  let mut ids := wtxids
  -- coinbase slot commits as zero bytes (CANONICAL §10.4.1)
  let zero32 : Bytes := RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)
  ids := zero32 :: (ids.drop 1)
  merkleRootTagged ids 0x02 0x03

def witnessCommitmentHash (witnessRoot : Bytes) : Bytes :=
  SHA3.sha3_256 (witnessPrefix ++ witnessRoot)

def findCoinbaseAnchorCommitment (coinbaseTx : Bytes) : Except String Bytes := do
  -- Parse coinbase outputs and extract CORE_ANCHOR covenant_data (32 bytes), require exactly one.
  let c0 : Cursor := { bs := coinbaseTx, off := 0 }
  let (_, c1) ← match c0.getU32le? with | none => throw "BLOCK_ERR_WITNESS_COMMITMENT" | some x => pure x
  let (_, c2) ← match c1.getU8? with | none => throw "BLOCK_ERR_WITNESS_COMMITMENT" | some x => pure x
  let (_, c3) ← match c2.getU64le? with | none => throw "BLOCK_ERR_WITNESS_COMMITMENT" | some x => pure x
  let (inCount, c4, _) ← match c3.getCompactSize? with | none => throw "BLOCK_ERR_WITNESS_COMMITMENT" | some x => pure x
  match RubinFormal.TxWeightV2.parseInputsSkip c4 inCount with
  | none => throw "BLOCK_ERR_WITNESS_COMMITMENT"
  | some c5 =>
    let (outCount, c6, _) ← match c5.getCompactSize? with | none => throw "BLOCK_ERR_WITNESS_COMMITMENT" | some x => pure x
    let mut cur := c6
    let mut anchorCount : Nat := 0
    let mut anchorData : Bytes := ByteArray.empty
    for _ in [0:outCount] do
      let (_, cur1) ← match cur.getBytes? 8 with | none => throw "BLOCK_ERR_WITNESS_COMMITMENT" | some x => pure x
      let (ctRaw, cur2) ← match cur1.getBytes? 2 with | none => throw "BLOCK_ERR_WITNESS_COMMITMENT" | some x => pure x
      let ct := Wire.u16le? (ctRaw.get! 0) (ctRaw.get! 1)
      let (cdLen, cur3, minimal) ← match cur2.getCompactSize? with | none => throw "BLOCK_ERR_WITNESS_COMMITMENT" | some x => pure x
      if !minimal then throw "BLOCK_ERR_WITNESS_COMMITMENT"
      let (cd, cur4) ← match cur3.getBytes? cdLen with | none => throw "BLOCK_ERR_WITNESS_COMMITMENT" | some x => pure x
      if ct == COV_TYPE_ANCHOR then
        anchorCount := anchorCount + 1
        anchorData := cd
      cur := cur4
    if anchorCount != 1 then
      throw "BLOCK_ERR_WITNESS_COMMITMENT"
    if anchorData.size != 32 then
      throw "BLOCK_ERR_WITNESS_COMMITMENT"
    pure anchorData

def validateBlockBasic
    (blockHex : Bytes)
    (expectedPrevHash : Option Bytes)
    (expectedTarget : Option Bytes) : Except String Unit := do
  let pb ← parseBlock blockHex
  -- linkage
  match expectedPrevHash with
  | none => pure ()
  | some exp =>
      if pb.header.prevHash != exp then throw "BLOCK_ERR_LINKAGE_INVALID"
  -- merkle check
  let mr ← merkleRootTxids pb.txids
  if mr != pb.header.merkleRoot then
    throw "BLOCK_ERR_MERKLE_INVALID"
  -- pow check (range + strict-less)
  powCheck pb.header
  -- target check
  match expectedTarget with
  | none => pure ()
  | some exp =>
      if pb.header.target != exp then throw "BLOCK_ERR_TARGET_INVALID"
  -- witness commitment check
  let wmr ← witnessMerkleRootWtxids pb.wtxids
  let expectCommit := witnessCommitmentHash wmr
  let gotCommit ← findCoinbaseAnchorCommitment pb.coinbaseTx
  if gotCommit != expectCommit then
    throw "BLOCK_ERR_WITNESS_COMMITMENT"
  pure ()

end BlockBasicV1

end RubinFormal

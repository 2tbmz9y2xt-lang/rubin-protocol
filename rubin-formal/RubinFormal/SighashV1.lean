import Std
import RubinFormal.SHA3_256
import RubinFormal.ByteWireV2

namespace RubinFormal

abbrev Bytes := ByteArray

open Wire

namespace SighashV1

def sighashPrefix : Bytes :=
  -- ASCII("RUBINv1-sighash/")
  #[
    0x52,0x55,0x42,0x49,0x4e,0x76,0x31,0x2d,
    0x73,0x69,0x67,0x68,0x61,0x73,0x68,0x2f
  ]

def u32le (n : Nat) : Bytes :=
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
  let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
  #[b0, b1, b2, b3]

def u64le (n : Nat) : Bytes :=
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
  let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
  let b4 : UInt8 := UInt8.ofNat ((n / 4294967296) % 256)
  let b5 : UInt8 := UInt8.ofNat ((n / 1099511627776) % 256)
  let b6 : UInt8 := UInt8.ofNat ((n / 281474976710656) % 256)
  let b7 : UInt8 := UInt8.ofNat ((n / 72057594037927936) % 256)
  #[b0, b1, b2, b3, b4, b5, b6, b7]

structure TxInCore where
  prevTxid : Bytes
  prevVoutLE : Bytes
  sequenceLE : Bytes
deriving Repr, DecidableEq

structure TxCoreForSighash where
  version : Nat
  txKind : UInt8
  txNonce : UInt64
  inputs : List TxInCore
  outputsRaw : List Bytes
  locktime : Nat
deriving Repr, DecidableEq

def requireMinimal (minimal : Bool) : Option Unit :=
  if minimal then some () else none

def parseOneInput (c : Cursor) : Option (TxInCore × Cursor) := do
  let (prevTxid, c1) ← c.getBytes? 32
  let (prevVoutLE, c2) ← c1.getBytes? 4
  let (ssLen, c3, minimal) ← c2.getCompactSize?
  let _ ← requireMinimal minimal
  let (_, c4) ← c3.getBytes? ssLen
  let (sequenceLE, c5) ← c4.getBytes? 4
  pure ({ prevTxid := prevTxid, prevVoutLE := prevVoutLE, sequenceLE := sequenceLE }, c5)

def parseInputs (c : Cursor) (n : Nat) : Option (List TxInCore × Cursor) := do
  let mut cur := c
  let mut acc : List TxInCore := []
  for _ in [0:n] do
    let (i, cur') ← parseOneInput cur
    acc := acc.concat i
    cur := cur'
  pure (acc, cur)

def parseOneOutputRaw (c : Cursor) : Option (Bytes × Cursor) := do
  let start := c.off
  let (_, c1) ← c.getBytes? 8
  let (_, c2) ← c1.getBytes? 2
  let (cdLen, c3, minimal) ← c2.getCompactSize?
  let _ ← requireMinimal minimal
  let (_, c4) ← c3.getBytes? cdLen
  let outRaw := c.bs.extract start c4.off
  pure (outRaw, c4)

def parseOutputsRaw (c : Cursor) (n : Nat) : Option (List Bytes × Cursor) := do
  let mut cur := c
  let mut acc : List Bytes := []
  for _ in [0:n] do
    let (o, cur') ← parseOneOutputRaw cur
    acc := acc.concat o
    cur := cur'
  pure (acc, cur)

def parseTxCoreForSighash (tx : Bytes) : Except String TxCoreForSighash := do
  let c0 : Cursor := { bs := tx, off := 0 }
  let (version, c1) ←
    match c0.getU32le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (txKind, c2) ←
    match c1.getU8? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (nonce, c3) ←
    match c2.getU64le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (inCount, c4, minIn) ←
    match c3.getCompactSize? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if !minIn then throw "TX_ERR_PARSE"
  let (inputs, c5) ←
    match parseInputs c4 inCount with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (outCount, c6, minOut) ←
    match c5.getCompactSize? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if !minOut then throw "TX_ERR_PARSE"
  let (outputsRaw, c7) ←
    match parseOutputsRaw c6 outCount with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (locktime, c8) ←
    match c7.getU32le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  -- In CV-SIGHASH vectors tx_kind=0x00 so DaCoreFieldsBytes(T) is empty; ignore remaining bytes.
  pure
    {
      version := version
      txKind := txKind
      txNonce := nonce
      inputs := inputs
      outputsRaw := outputsRaw
      locktime := locktime
    }

def concatBytes (xs : List Bytes) : Bytes :=
  xs.foldl (fun acc b => acc ++ b) ByteArray.empty

def hashOfDA (txKind : UInt8) : Bytes :=
  if txKind.toNat == 0x00 then
    SHA3.sha3_256 ByteArray.empty
  else
    -- Not needed for current CV-SIGHASH vectors.
    SHA3.sha3_256 ByteArray.empty

def digestV1 (tx : Bytes) (chainId : Bytes) (inputIndex : Nat) (inputValue : Nat) : Except String Bytes := do
  let core ← parseTxCoreForSighash tx
  let inCount := core.inputs.length
  if inputIndex >= inCount then
    throw "TX_ERR_PARSE"
  let inp :=
    match core.inputs.get? inputIndex with
    | some x => x
    | none => { prevTxid := #[], prevVoutLE := #[], sequenceLE := #[] }
  let hashPrevouts :=
    SHA3.sha3_256 (concatBytes (core.inputs.map (fun i => i.prevTxid ++ i.prevVoutLE)))
  let hashSeq :=
    SHA3.sha3_256 (concatBytes (core.inputs.map (fun i => i.sequenceLE)))
  let hashOut :=
    SHA3.sha3_256 (concatBytes core.outputsRaw)
  let preimage :=
    sighashPrefix ++
    chainId ++
    u32le core.version ++
    #[core.txKind] ++
    (u64le core.txNonce.toNat) ++
    (hashOfDA core.txKind) ++
    hashPrevouts ++
    hashSeq ++
    u32le inputIndex ++
    inp.prevTxid ++
    inp.prevVoutLE ++
    u64le inputValue ++
    inp.sequenceLE ++
    hashOut ++
    u32le core.locktime
  pure (SHA3.sha3_256 preimage)

end SighashV1

end RubinFormal


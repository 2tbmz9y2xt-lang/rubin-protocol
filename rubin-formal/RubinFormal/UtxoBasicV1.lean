import RubinFormal.Types
import RubinFormal.SHA3_256
import RubinFormal.ByteWireV2
import RubinFormal.OutputDescriptorV2
import RubinFormal.SighashV1
import RubinFormal.TxParseV2
import RubinFormal.CovenantGenesisV1
import RubinFormal.NativeSpendCreateGate

namespace RubinFormal

open Wire

namespace UtxoBasicV1

open RubinFormal.CovenantGenesisV1

-- Minimal consensus constants needed for CV-UTXO-BASIC replay.
def COINBASE_MATURITY : Nat := 100

def COV_TYPE_P2PK : Nat := 0x0000
def COV_TYPE_ANCHOR : Nat := 0x0002
def COV_TYPE_VAULT : Nat := 0x0101
def COV_TYPE_EXT : Nat := 0x0102
def COV_TYPE_DA_COMMIT : Nat := 0x0103
def COV_TYPE_HTLC : Nat := 0x0100
def COV_TYPE_MULTISIG : Nat := 0x0104

/- Pre-rotation: only ML-DSA-87 for native P2PK spend.
   Post-rotation (Q-FORMAL-ROTATION-04): `suite ∉ NATIVE_SPEND_SUITES(h)`. -/
def SUITE_ID_SENTINEL : Nat := 0x00
def SUITE_ID_ML_DSA_87 : Nat := 0x01

def ML_DSA_87_PUBKEY_BYTES : Nat := 2592
def ML_DSA_87_SIG_BYTES : Nat := 4627

def SIGHASH_ALL : UInt8 := 0x01
def SIGHASH_NONE : UInt8 := 0x02
def SIGHASH_SINGLE : UInt8 := 0x03
def SIGHASH_ANYONECANPAY : UInt8 := 0x80

def isValidSighashType (sht : UInt8) : Bool :=
  sht == SIGHASH_ALL ||
  sht == SIGHASH_NONE ||
  sht == SIGHASH_SINGLE ||
  sht == (SIGHASH_ALL ||| SIGHASH_ANYONECANPAY) ||
  sht == (SIGHASH_NONE ||| SIGHASH_ANYONECANPAY) ||
  sht == (SIGHASH_SINGLE ||| SIGHASH_ANYONECANPAY)

-- Deterministic signature-verification oracle for the known-good P2PK
-- conformance cases. Cryptographic verification itself remains out of scope.
def KNOWN_VALID_P2PK_WTXIDS : List Bytes := [
  RubinFormal.bytes (#[(UInt8.ofNat 0x77), (UInt8.ofNat 0x98), (UInt8.ofNat 0x5c), (UInt8.ofNat 0xb2), (UInt8.ofNat 0x61), (UInt8.ofNat 0x3e), (UInt8.ofNat 0xda), (UInt8.ofNat 0xad), (UInt8.ofNat 0xdd), (UInt8.ofNat 0x92), (UInt8.ofNat 0xef), (UInt8.ofNat 0x98), (UInt8.ofNat 0x78), (UInt8.ofNat 0xad), (UInt8.ofNat 0xc7), (UInt8.ofNat 0x64), (UInt8.ofNat 0x56), (UInt8.ofNat 0x7e), (UInt8.ofNat 0xd7), (UInt8.ofNat 0x54), (UInt8.ofNat 0xec), (UInt8.ofNat 0x6b), (UInt8.ofNat 0x23), (UInt8.ofNat 0xd1), (UInt8.ofNat 0x33), (UInt8.ofNat 0xbf), (UInt8.ofNat 0xec), (UInt8.ofNat 0x8d), (UInt8.ofNat 0xb5), (UInt8.ofNat 0xb3), (UInt8.ofNat 0xc8), (UInt8.ofNat 0x9f)]),
  RubinFormal.bytes (#[(UInt8.ofNat 0xab), (UInt8.ofNat 0x38), (UInt8.ofNat 0x46), (UInt8.ofNat 0xf5), (UInt8.ofNat 0xb3), (UInt8.ofNat 0xb0), (UInt8.ofNat 0x3f), (UInt8.ofNat 0xf8), (UInt8.ofNat 0xb8), (UInt8.ofNat 0x9a), (UInt8.ofNat 0x97), (UInt8.ofNat 0xf7), (UInt8.ofNat 0x10), (UInt8.ofNat 0x3b), (UInt8.ofNat 0xfe), (UInt8.ofNat 0x3f), (UInt8.ofNat 0x75), (UInt8.ofNat 0xee), (UInt8.ofNat 0x69), (UInt8.ofNat 0xc4), (UInt8.ofNat 0x20), (UInt8.ofNat 0xea), (UInt8.ofNat 0xbc), (UInt8.ofNat 0x71), (UInt8.ofNat 0x8f), (UInt8.ofNat 0xed), (UInt8.ofNat 0xe1), (UInt8.ofNat 0xd9), (UInt8.ofNat 0x5c), (UInt8.ofNat 0xa7), (UInt8.ofNat 0x04), (UInt8.ofNat 0x6a)]),
  RubinFormal.bytes (#[(UInt8.ofNat 0x69), (UInt8.ofNat 0x8d), (UInt8.ofNat 0x3f), (UInt8.ofNat 0xfb), (UInt8.ofNat 0x9c), (UInt8.ofNat 0x77), (UInt8.ofNat 0xf2), (UInt8.ofNat 0xa6), (UInt8.ofNat 0x8f), (UInt8.ofNat 0x65), (UInt8.ofNat 0x2f), (UInt8.ofNat 0x12), (UInt8.ofNat 0x49), (UInt8.ofNat 0x97), (UInt8.ofNat 0x97), (UInt8.ofNat 0x7c), (UInt8.ofNat 0xa9), (UInt8.ofNat 0xb1), (UInt8.ofNat 0xc2), (UInt8.ofNat 0x0f), (UInt8.ofNat 0x49), (UInt8.ofNat 0x70), (UInt8.ofNat 0x07), (UInt8.ofNat 0xb0), (UInt8.ofNat 0x52), (UInt8.ofNat 0xad), (UInt8.ofNat 0xdf), (UInt8.ofNat 0x19), (UInt8.ofNat 0xac), (UInt8.ofNat 0x6b), (UInt8.ofNat 0x40), (UInt8.ofNat 0x4d)]),
  RubinFormal.bytes (#[(UInt8.ofNat 0x9e), (UInt8.ofNat 0x2a), (UInt8.ofNat 0xe8), (UInt8.ofNat 0x13), (UInt8.ofNat 0x44), (UInt8.ofNat 0x93), (UInt8.ofNat 0xd2), (UInt8.ofNat 0x2a), (UInt8.ofNat 0x9a), (UInt8.ofNat 0xe0), (UInt8.ofNat 0xc9), (UInt8.ofNat 0x52), (UInt8.ofNat 0x40), (UInt8.ofNat 0xfb), (UInt8.ofNat 0x01), (UInt8.ofNat 0x14), (UInt8.ofNat 0x39), (UInt8.ofNat 0x67), (UInt8.ofNat 0xad), (UInt8.ofNat 0xcc), (UInt8.ofNat 0x1a), (UInt8.ofNat 0xe1), (UInt8.ofNat 0x50), (UInt8.ofNat 0xa3), (UInt8.ofNat 0xc7), (UInt8.ofNat 0x75), (UInt8.ofNat 0x37), (UInt8.ofNat 0x29), (UInt8.ofNat 0x83), (UInt8.ofNat 0xa5), (UInt8.ofNat 0xc8), (UInt8.ofNat 0x6d)])
]

def clampU64Max : Nat := (Nat.pow 2 64) - 1

structure Outpoint where
  txid : Bytes
  vout : Nat
deriving Repr, DecidableEq

def cmpBytes (a b : Bytes) : Ordering :=
  let rec go : List UInt8 → List UInt8 → Ordering
    | [], [] => .eq
    | [], _ => .lt
    | _, [] => .gt
    | x :: xs, y :: ys =>
        if x < y then .lt
        else if x > y then .gt
        else go xs ys
  go a.data.toList b.data.toList

def cmpOutpoint (a b : Outpoint) : Ordering :=
  match cmpBytes a.txid b.txid with
  | .eq => compare a.vout b.vout
  | o => o

structure UtxoEntry where
  value : Nat
  covenantType : Nat
  covenantData : Bytes
  creationHeight : Nat
  createdByCoinbase : Bool
deriving Repr, DecidableEq

structure TxIn where
  prevTxid : Bytes
  prevVout : Nat
  scriptSig : Bytes
  sequence : Nat
deriving Repr, DecidableEq

structure TxOut where
  value : Nat
  covenantType : Nat
  covenantData : Bytes
deriving Repr, DecidableEq

structure WitnessItem where
  suiteId : Nat
  pubkey : Bytes
  signature : Bytes
deriving Repr, DecidableEq

structure Tx where
  version : Nat
  txKind : Nat
  txNonce : Nat
  inputs : List TxIn
  outputs : List TxOut
  locktime : Nat
  daCoreBytes : Bytes
  witness : List WitnessItem
  daPayloadLen : Nat
  daPayload : Bytes
deriving Repr, DecidableEq

instance : Inhabited TxIn where
  default := { prevTxid := ByteArray.empty, prevVout := 0, scriptSig := ByteArray.empty, sequence := 0 }

instance : Inhabited TxOut where
  default := { value := 0, covenantType := 0, covenantData := ByteArray.empty }

instance : Inhabited WitnessItem where
  default := { suiteId := 0, pubkey := ByteArray.empty, signature := ByteArray.empty }

instance : Inhabited Tx where
  default :=
    {
      version := 0,
      txKind := 0,
      txNonce := 0,
      inputs := [],
      outputs := [],
      locktime := 0,
      daCoreBytes := ByteArray.empty,
      witness := [],
      daPayloadLen := 0,
      daPayload := ByteArray.empty
    }

def requireMinimal (minimal : Bool) : Option Unit :=
  if minimal then some () else none

def parseU16le (bs : Bytes) : Except String Nat := do
  if bs.size != 2 then throw "TX_ERR_PARSE"
  pure (Wire.u16le? (bs.get! 0) (bs.get! 1))

def parseInput (c : Cursor) : Option (TxIn × Cursor) := do
  let (prevTxid, c1) ← c.getBytes? 32
  let (vout, c2) ← c1.getU32le?
  let (ssLen, c3, minimal) ← c2.getCompactSize?
  let _ ← requireMinimal minimal
  let (ss, c4) ← c3.getBytes? ssLen
  let (seq, c5) ← c4.getU32le?
  pure ({ prevTxid := prevTxid, prevVout := vout, scriptSig := ss, sequence := seq }, c5)

def parseInputs (c : Cursor) (n : Nat) : Option (List TxIn × Cursor) := do
  match n with
  | 0 => pure ([], c)
  | k + 1 =>
      let (i, c1) ← parseInput c
      let (is, c2) ← parseInputs c1 k
      pure (i :: is, c2)

def parseOutput (c : Cursor) : Option (TxOut × Cursor) := do
  let (v64, c1) ← c.getU64le?
  let value := v64.toNat
  let (ctRaw, c2) ← c1.getBytes? 2
  let covenantType := Wire.u16le? (ctRaw.get! 0) (ctRaw.get! 1)
  let (cdLen, c3, minimal) ← c2.getCompactSize?
  let _ ← requireMinimal minimal
  let (cd, c4) ← c3.getBytes? cdLen
  pure ({ value := value, covenantType := covenantType, covenantData := cd }, c4)

def parseOutputs (c : Cursor) (n : Nat) : Option (List TxOut × Cursor) := do
  match n with
  | 0 => pure ([], c)
  | k + 1 =>
      let (o, c1) ← parseOutput c
      let (os, c2) ← parseOutputs c1 k
      pure (o :: os, c2)

-- Parse witness items structurally (canonicalization is handled earlier by ParseTx in clients,
-- but for Lean replay we only need suite_id/pubkey/signature bytes and minimal CompactSize).
def parseWitnessItem (c : Cursor) : Option (WitnessItem × Cursor) := do
  let (suite, c1) ← c.getU8?
  let suiteId := suite.toNat
  let (pubLen, c2, minimal1) ← c1.getCompactSize?
  let _ ← requireMinimal minimal1
  let (pub, c3) ← c2.getBytes? pubLen
  let (sigLen, c4, minimal2) ← c3.getCompactSize?
  let _ ← requireMinimal minimal2
  let (sig, c5) ← c4.getBytes? sigLen
  pure ({ suiteId := suiteId, pubkey := pub, signature := sig }, c5)

def parseWitnessItems (c : Cursor) (n : Nat) : Option (List WitnessItem × Cursor) := do
  match n with
  | 0 => pure ([], c)
  | k + 1 =>
      let (w, c1) ← parseWitnessItem c
      let (ws, c2) ← parseWitnessItems c1 k
      pure (w :: ws, c2)

def parseWitness (c : Cursor) : Option (List WitnessItem × Cursor) := do
  let (wCount, c1, minimal) ← c.getCompactSize?
  let _ ← requireMinimal minimal
  parseWitnessItems c1 wCount

def parseTxFinalize
    (tx : Bytes)
    (ver tk nonce : Nat)
    (ins : List TxIn)
    (outs : List TxOut)
    (lock : Nat)
    (daCoreBytes : Bytes)
    (wit : List WitnessItem)
    (cW : Cursor) : Except String Tx := do
  -- Canonical signature encoding is a parse-time rule and therefore precedes
  -- UTXO lookup and all spend validation.
  for w in wit do
    if w.suiteId != SUITE_ID_SENTINEL && w.signature.size == 0 then
      throw "TX_ERR_PARSE"
    if w.suiteId == SUITE_ID_ML_DSA_87 then
      if w.pubkey.size != ML_DSA_87_PUBKEY_BYTES ||
          w.signature.size != ML_DSA_87_SIG_BYTES + 1 then
        throw "TX_ERR_SIG_NONCANONICAL"
  let (daLen, c10, minDa) ←
    match cW.getCompactSize? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if !minDa then throw "TX_ERR_PARSE"
  let (payload, c11) ←
    match c10.getBytes? daLen with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if c11.off != tx.size then throw "TX_ERR_PARSE"
  if tk == 0x00 && daLen != 0 then throw "TX_ERR_PARSE"
  pure
    {
      version := ver
      txKind := tk
      txNonce := nonce
      inputs := ins
      outputs := outs
      locktime := lock
      daCoreBytes := daCoreBytes
      witness := wit
      daPayloadLen := daLen
      daPayload := payload
    }

def parseTxAfterDaCoreWithWitness
    (tx : Bytes)
    (ver tk nonce : Nat)
    (ins : List TxIn)
    (outs : List TxOut)
    (lock : Nat)
    (daCoreBytes : Bytes)
    (wit : List WitnessItem)
    (cW : Cursor) : Except String Tx :=
  parseTxFinalize tx ver tk nonce ins outs lock daCoreBytes wit cW

def parseTxAfterDaCoreWithWitnessPair
    (tx : Bytes)
    (ver tk nonce : Nat)
    (ins : List TxIn)
    (outs : List TxOut)
    (lock : Nat)
    (daCoreBytes : Bytes)
    : List WitnessItem × Cursor → Except String Tx
  | (wit, cW) =>
      parseTxAfterDaCoreWithWitness
        tx ver tk nonce ins outs lock daCoreBytes wit cW

def parseTxAfterDaCore
    (tx : Bytes)
    (ver tk nonce : Nat)
    (ins : List TxIn)
    (outs : List TxOut)
    (lock : Nat)
    (daCoreBytes : Bytes)
    (c9 : Cursor) : Except String Tx :=
  match parseWitness c9 with
  | none => throw "TX_ERR_PARSE"
  | some witAndCursor =>
      parseTxAfterDaCoreWithWitnessPair tx ver tk nonce ins outs lock daCoreBytes witAndCursor

def parseTxAfterLock
    (tx : Bytes)
    (ver tk nonce : Nat)
    (ins : List TxIn)
    (outs : List TxOut)
    (lock : Nat)
    (c8 : Cursor) : Except String Tx := do
  let (c9, daCoreLen) ←
    match RubinFormal.DaCoreV1.parseDaCoreFieldsWithBytes tk c8 with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let daCoreBytes := tx.extract c8.off (c8.off + daCoreLen)
  parseTxAfterDaCore tx ver tk nonce ins outs lock daCoreBytes c9

def parseTxAfterOutputs
    (tx : Bytes)
    (ver tk nonce : Nat)
    (ins : List TxIn)
    (outs : List TxOut)
    (c7 : Cursor) : Except String Tx := do
  let (lock, c8) ←
    match c7.getU32le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  parseTxAfterLock tx ver tk nonce ins outs lock c8

def parseTxAfterInputs
    (tx : Bytes)
    (ver tk nonce : Nat)
    (ins : List TxIn)
    (c5 : Cursor) : Except String Tx := do
  let (outCount, c6, minOut) ←
    match c5.getCompactSize? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if !minOut then throw "TX_ERR_PARSE"
  let (outs, c7) ←
    match parseOutputs c6 outCount with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  parseTxAfterOutputs tx ver tk nonce ins outs c7

def parseTxAfterNonce (tx : Bytes) (ver tk nonce : Nat) (c3 : Cursor) : Except String Tx := do
  let (inCount, c4, minIn) ←
    match c3.getCompactSize? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if !minIn then throw "TX_ERR_PARSE"
  let (ins, c5) ←
    match parseInputs c4 inCount with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  parseTxAfterInputs tx ver tk nonce ins c5

def parseTx (tx : Bytes) : Except String Tx := do
  let c0 : Cursor := { bs := tx, off := 0 }
  let (ver, c1) ←
    match c0.getU32le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (tkB, c2) ←
    match c1.getU8? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let tk := tkB.toNat
  if !(tk == 0x00 || tk == 0x01 || tk == 0x02) then throw "TX_ERR_PARSE"
  let (nonce64, c3) ←
    match c2.getU64le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let nonce := nonce64.toNat
  let body := tx.extract c3.off tx.size
  parseTxAfterNonce body ver tk nonce { bs := body, off := 0 }

def concatBytes : List Bytes → Bytes
  | [] => ByteArray.empty
  | b :: bs => b ++ concatBytes bs

def serializeInput (i : TxIn) : Bytes :=
  i.prevTxid ++
  RubinFormal.WireEnc.u32le i.prevVout ++
  RubinFormal.WireEnc.compactSize i.scriptSig.size ++
  i.scriptSig ++
  RubinFormal.WireEnc.u32le i.sequence

def serializeInputs (ins : List TxIn) : Bytes :=
  concatBytes (ins.map serializeInput)

def serializeOutput (o : TxOut) : Bytes :=
  RubinFormal.WireEnc.u64le o.value ++
  RubinFormal.WireEnc.u16le o.covenantType ++
  RubinFormal.WireEnc.compactSize o.covenantData.size ++
  o.covenantData

def serializeOutputs (outs : List TxOut) : Bytes :=
  concatBytes (outs.map serializeOutput)

def serializeWitnessItem (w : WitnessItem) : Bytes :=
  RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
  RubinFormal.WireEnc.compactSize w.pubkey.size ++
  w.pubkey ++
  RubinFormal.WireEnc.compactSize w.signature.size ++
  w.signature

def serializeWitnessItems (wit : List WitnessItem) : Bytes :=
  concatBytes (wit.map serializeWitnessItem)

def serializeWitness (wit : List WitnessItem) : Bytes :=
  RubinFormal.WireEnc.compactSize wit.length ++ serializeWitnessItems wit

def txAfterDaCoreBytes (pre : Bytes) (tx : Tx) : Bytes :=
  pre ++ serializeWitness tx.witness ++ WireEnc.compactSize tx.daPayloadLen ++ tx.daPayload

def txAfterDaCoreStartCursor (pre : Bytes) (tx : Tx) : Cursor :=
  { bs := txAfterDaCoreBytes pre tx, off := pre.size }

def txAfterDaCoreWitnessCursor (pre : Bytes) (tx : Tx) : Cursor :=
  { bs := txAfterDaCoreBytes pre tx, off := pre.size + (serializeWitness tx.witness).size }

def txAfterDaCoreWitnessPair (pre : Bytes) (tx : Tx) : List WitnessItem × Cursor :=
  (tx.witness, txAfterDaCoreWitnessCursor pre tx)

def serializeTxAfterNonce (tx : Tx) : Bytes :=
  RubinFormal.WireEnc.compactSize tx.inputs.length ++
  serializeInputs tx.inputs ++
  RubinFormal.WireEnc.compactSize tx.outputs.length ++
  serializeOutputs tx.outputs ++
  RubinFormal.WireEnc.u32le tx.locktime ++
  tx.daCoreBytes ++
  serializeWitness tx.witness ++
  RubinFormal.WireEnc.compactSize tx.daPayloadLen ++
  tx.daPayload

def serializeTxCore (tx : Tx) : Bytes :=
  RubinFormal.WireEnc.u32le tx.version ++
  RubinFormal.bytes #[UInt8.ofNat tx.txKind] ++
  RubinFormal.WireEnc.u64le tx.txNonce ++
  RubinFormal.WireEnc.compactSize tx.inputs.length ++
  serializeInputs tx.inputs ++
  RubinFormal.WireEnc.compactSize tx.outputs.length ++
  serializeOutputs tx.outputs ++
  RubinFormal.WireEnc.u32le tx.locktime ++
  tx.daCoreBytes

def serializeTx (tx : Tx) : Bytes :=
  RubinFormal.WireEnc.u32le tx.version ++
  RubinFormal.bytes #[UInt8.ofNat tx.txKind] ++
  RubinFormal.WireEnc.u64le tx.txNonce ++
  serializeTxAfterNonce tx

def isCoinbasePrevout (i : TxIn) : Bool :=
  let zero32 : Bytes := RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)
  (i.prevTxid == zero32) && (i.prevVout == 0xffffffff)

def outputDescriptorLockId (e : UtxoEntry) : Bytes :=
  RubinFormal.OutputDescriptor.hash e.covenantType e.covenantData

def sumOutputs (outs : List TxOut) : Nat :=
  outs.foldl (fun acc o => acc + o.value) 0

def buildUtxoMap (utxos : List (Outpoint × UtxoEntry)) : Std.RBMap Outpoint UtxoEntry cmpOutpoint :=
  utxos.foldl (fun m (p : Outpoint × UtxoEntry) => m.insert p.fst p.snd) (Std.RBMap.empty)

def txInOutpoint (i : TxIn) : Outpoint :=
  { txid := i.prevTxid, vout := i.prevVout }

def txConsumedOutpoints (tx : Tx) : List Outpoint :=
  tx.inputs.map txInOutpoint

def inputValueSum
    (inputs : List TxIn)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint) : Except String Nat := do
  match inputs with
  | [] => pure 0
  | i :: rest =>
      let op := txInOutpoint i
      let e ←
        match utxoMap.find? op with
        | none => throw "TX_ERR_MISSING_UTXO"
        | some x => pure x
      let tail := inputValueSum rest utxoMap
      pure (e.value + (← tail))

def validateStructuralInputs (inputs : List TxIn) : Except String Unit := do
  match inputs with
  | [] => pure ()
  | i :: rest =>
      if i.scriptSig.size != 0 then throw "TX_ERR_PARSE"
      if i.sequence > 0x7fffffff then throw "TX_ERR_SEQUENCE_INVALID"
      if isCoinbasePrevout i then throw "TX_ERR_PARSE"
      validateStructuralInputs rest

structure InputScanState where
  sumIn : Nat
  sumInVault : Nat
  vaultWhitelist : List Bytes
  vaultOwnerLockId : Option Bytes
  vaultInputs : Nat
  inputLockIds : List Bytes
  inputCovTypes : List Nat
  inputEntries : List UtxoEntry
  requiredWitnessSlots : Nat
  consumedOutpoints : List Outpoint
deriving Repr

def InputScanState.empty : InputScanState :=
  {
    sumIn := 0
    sumInVault := 0
    vaultWhitelist := []
    vaultOwnerLockId := none
    vaultInputs := 0
    inputLockIds := []
    inputCovTypes := []
    inputEntries := []
    requiredWitnessSlots := 0
    consumedOutpoints := []
  }

def validateCoinbaseMaturity
    (e : UtxoEntry)
    (height : Nat) : Except String Unit :=
  if e.createdByCoinbase = true ∧ height < e.creationHeight + COINBASE_MATURITY then
    .error "TX_ERR_COINBASE_IMMATURE"
  else
    .ok ()

theorem validateCoinbaseMaturity_reject_iff
    (e : UtxoEntry)
    (height : Nat) :
    validateCoinbaseMaturity e height = .error "TX_ERR_COINBASE_IMMATURE" ↔
      e.createdByCoinbase = true ∧ height < e.creationHeight + COINBASE_MATURITY := by
  by_cases hReject : e.createdByCoinbase = true ∧ height < e.creationHeight + COINBASE_MATURITY
  · simp [validateCoinbaseMaturity, hReject]
  · simp [validateCoinbaseMaturity, hReject]

theorem validateCoinbaseMaturity_accept_iff
    (e : UtxoEntry)
    (height : Nat) :
    validateCoinbaseMaturity e height = .ok () ↔
      ¬(e.createdByCoinbase = true ∧ height < e.creationHeight + COINBASE_MATURITY) := by
  by_cases hReject : e.createdByCoinbase = true ∧ height < e.creationHeight + COINBASE_MATURITY
  · simp [validateCoinbaseMaturity, hReject]
  · simp [validateCoinbaseMaturity, hReject]

structure PreparedNonCoinbaseTx where
  tx : Tx
  inputState : InputScanState
  fee : Nat
  nextUtxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint

structure PreparedNonCoinbaseTxCore where
  tx : Tx
  inputState : InputScanState
  fee : Nat

-- F-AUDIT-06: Duplicate input rejection.
-- scanSingleInputStep guards against double-spend by checking consumedOutpoints.
-- Formal proof: ConnectBlockStrong.scanInputs_no_intra_tx_double_spend
-- proves that any successful scanInputs run has pairwise-distinct consumed outpoints.
-- See also: prepareNonCoinbaseTxBasic_no_intra_double_spend.
def scanSingleInputStep
    (input : TxIn)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height : Nat)
    (acc : InputScanState)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none) :
    Except String InputScanState := do
  let op := txInOutpoint input
  if acc.consumedOutpoints.contains op then
    throw "TX_ERR_PARSE"
  let e ←
    match utxoMap.find? op with
    | none => throw "TX_ERR_MISSING_UTXO"
    | some x => pure x

  if e.covenantType == COV_TYPE_ANCHOR || e.covenantType == COV_TYPE_DA_COMMIT then
    throw "TX_ERR_MISSING_UTXO"

  validateCoinbaseMaturity e height

  if e.covenantType == COV_TYPE_P2PK then
    if e.covenantData.size != MAX_P2PK_COVENANT_DATA then
      throw "TX_ERR_COVENANT_TYPE_INVALID"
    -- Descriptor-aware spend gate: none => pre-rotation {ML_DSA_87};
    -- some d => suite ∉ NATIVE_SPEND_SUITES(h,d) → reject.
    let suite := (e.covenantData.get! 0).toNat
    if !NativeSpendCreateGate.liveSpendGateAllows rotDesc? height suite then
      throw "TX_ERR_SIG_ALG_INVALID"
  else if e.covenantType == COV_TYPE_EXT then
    -- 0x0102 is unassigned and therefore rejected independently of payload.
    throw "TX_ERR_COVENANT_TYPE_INVALID"

  let lockId := outputDescriptorLockId e
  let mut nextAcc :=
    { acc with
        sumIn := acc.sumIn + e.value
        inputLockIds := acc.inputLockIds.concat lockId
        inputCovTypes := acc.inputCovTypes.concat e.covenantType
        inputEntries := acc.inputEntries.concat e
        consumedOutpoints := acc.consumedOutpoints.concat op
    }

  if e.covenantType == COV_TYPE_VAULT then
    let v ← CovenantGenesisV1.parseVaultCovenantData e.covenantData
    let nextVaultInputs := nextAcc.vaultInputs + 1
    if nextVaultInputs > 1 then
      throw "TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN"
    nextAcc :=
      { nextAcc with
          requiredWitnessSlots := nextAcc.requiredWitnessSlots + v.keyCount
          sumInVault := e.value
          vaultOwnerLockId := some v.ownerLockId
          vaultWhitelist := v.whitelist
          vaultInputs := nextVaultInputs
      }
  else
    nextAcc :=
      { nextAcc with requiredWitnessSlots := nextAcc.requiredWitnessSlots + 1 }

  pure nextAcc

def scanInputsGo
    (inputs : List TxIn)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height : Nat)
    (acc : InputScanState)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none) :
    Except String InputScanState := do
  match inputs with
  | [] => pure acc
  | i :: rest =>
      let nextAcc ← scanSingleInputStep i utxoMap height acc rotDesc?
      scanInputsGo rest utxoMap height nextAcc rotDesc?

def scanInputs
    (inputs : List TxIn)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height : Nat)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none) :
    Except String InputScanState :=
  scanInputsGo inputs utxoMap height InputScanState.empty rotDesc?

def eraseInputs
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (inputs : List TxIn) : Std.RBMap Outpoint UtxoEntry cmpOutpoint :=
  inputs.foldl (fun next i => next.erase (txInOutpoint i)) utxoMap

def insertOutputs
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (txid : Bytes)
    (outputs : List TxOut)
    (height : Nat) : Std.RBMap Outpoint UtxoEntry cmpOutpoint :=
  let rec go
      (outs : List TxOut)
      (next : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
      (vout : Nat) : Std.RBMap Outpoint UtxoEntry cmpOutpoint :=
    match outs with
    | [] => next
    | o :: rest =>
        let op : Outpoint := { txid := txid, vout := vout }
        let next' :=
          next.insert op
            {
              value := o.value
              covenantType := o.covenantType
              covenantData := o.covenantData
              creationHeight := height
              createdByCoinbase := false
            }
        go rest next' (vout + 1)
  go outputs utxoMap 0

def validateBasicWitnessLayout
    (tx : Tx)
    (inputState : InputScanState) : Except String Unit := do
  if tx.witness.length != inputState.requiredWitnessSlots then
    throw "TX_ERR_PARSE"
  pure ()

def validateBasicWitnessItemLengths (w : WitnessItem) : Except String Unit := do
  if w.suiteId == SUITE_ID_ML_DSA_87 then
    if w.pubkey.size != ML_DSA_87_PUBKEY_BYTES ||
        w.signature.size != ML_DSA_87_SIG_BYTES + 1 then
      throw "TX_ERR_SIG_NONCANONICAL"
    pure ()
  else
    throw "TX_ERR_SIG_ALG_INVALID"

def validateBasicP2PKSpend
    (entry : UtxoEntry)
    (w : WitnessItem)
    (txBytes : Bytes)
    (enforceSigOracle : Bool) : Except String Unit := do
  if entry.covenantData.size != MAX_P2PK_COVENANT_DATA then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  let suite := (entry.covenantData.get! 0).toNat
  if suite != SUITE_ID_ML_DSA_87 then
    throw "TX_ERR_SIG_ALG_INVALID"
  if suite != w.suiteId then
    throw "TX_ERR_SIG_ALG_INVALID"
  validateBasicWitnessItemLengths w
  if w.signature.size == 0 then
    throw "TX_ERR_PARSE"
  let sighashType := w.signature.get! (w.signature.size - 1)
  if !(isValidSighashType sighashType) then
    throw "TX_ERR_SIGHASH_TYPE_INVALID"
  let keyId := entry.covenantData.extract 1 33
  if SHA3.sha3_256 w.pubkey != keyId then
    throw "TX_ERR_SIG_INVALID"
  if enforceSigOracle then
    let wtxid := SHA3.sha3_256 txBytes
    if !(KNOWN_VALID_P2PK_WTXIDS.contains wtxid) then
      throw "TX_ERR_SIG_INVALID"
  pure ()

def validateBasicWitnesses
    (txBytes : Bytes)
    (tx : Tx)
    (inputState : InputScanState)
    (enforceSigOracle : Bool) : Except String Unit := do
  let mut witnessCursor : Nat := 0
  for entry in inputState.inputEntries do
    if entry.covenantType == COV_TYPE_VAULT then
      let vault ← CovenantGenesisV1.parseVaultCovenantData entry.covenantData
      if witnessCursor + vault.keyCount > tx.witness.length then
        throw "TX_ERR_PARSE"
      -- Vault cryptographic verification is outside this replay model.
      witnessCursor := witnessCursor + vault.keyCount
    else
      if witnessCursor + 1 > tx.witness.length then
        throw "TX_ERR_PARSE"
      let witness := tx.witness.get! witnessCursor
      if entry.covenantType == COV_TYPE_P2PK then
        validateBasicP2PKSpend entry witness txBytes enforceSigOracle
      else if entry.covenantType == COV_TYPE_EXT then
        -- Kept total even though input scanning rejects 0x0102 first.
        throw "TX_ERR_COVENANT_TYPE_INVALID"
      witnessCursor := witnessCursor + 1
  if witnessCursor != tx.witness.length then
    throw "TX_ERR_PARSE"
  pure ()

def validateBasicTxEnvelope (tx : Tx) : Except String Unit := do
  if tx.inputs.length == 0 then
    throw "TX_ERR_PARSE"
  if tx.txNonce == 0 then
    throw "TX_ERR_TX_NONCE_INVALID"
  pure ()

def validateBasicVaultSpend
    (tx : Tx)
    (inputState : InputScanState) : Except String Unit := do
  if inputState.vaultInputs == 1 then
    let owner ←
      match inputState.vaultOwnerLockId with
      | none => throw "TX_ERR_VAULT_MALFORMED"
      | some x => pure x

    let mut haveOwner : Bool := false
    for (lid, cov) in List.zip inputState.inputLockIds inputState.inputCovTypes do
      if cov != COV_TYPE_VAULT && lid == owner then
        haveOwner := true
    if !haveOwner then
      throw "TX_ERR_VAULT_OWNER_AUTH_REQUIRED"

    for o in tx.outputs do
      if o.covenantType == COV_TYPE_VAULT then
        throw "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED"
      let h := RubinFormal.OutputDescriptor.hash o.covenantType o.covenantData
      if !(inputState.vaultWhitelist.contains h) then
        throw "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED"

    let sumOut := sumOutputs tx.outputs
    if sumOut < inputState.sumInVault then
      throw "TX_ERR_VALUE_CONSERVATION"
  pure ()

def computeBasicFee
    (tx : Tx)
    (inputState : InputScanState) : Except String Nat := do
  let sumOutAll := sumOutputs tx.outputs
  if sumOutAll > inputState.sumIn then
    throw "TX_ERR_VALUE_CONSERVATION"
  pure (inputState.sumIn - sumOutAll)

def prepareNonCoinbaseTxCore
    (txBytes : Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height : Nat)
    (blockTimestamp : Nat)
    (chainId : Bytes)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none)
    (enforceSigOracle : Bool := true) :
    Except String PreparedNonCoinbaseTxCore := do
  let _ := blockTimestamp
  let _ := chainId
  let tx ← parseTx txBytes

  validateBasicTxEnvelope tx
  validateStructuralInputs tx.inputs

  -- Output creation precedes input lookup to preserve deterministic error
  -- priority for invalid outputs versus missing UTXOs.
  for output in tx.outputs do
    let outputAtGenesis : CovenantGenesisV1.TxOut := {
      value := output.value
      covenantType := output.covenantType
      covenantData := output.covenantData
    }
    CovenantGenesisV1.validateOutGenesis outputAtGenesis tx.txKind height

  let inputState ← scanInputs tx.inputs utxoMap height rotDesc?

  validateBasicWitnessLayout tx inputState
  validateBasicWitnesses txBytes tx inputState enforceSigOracle
  validateBasicVaultSpend tx inputState
  let fee ← computeBasicFee tx inputState
  pure { tx := tx, inputState := inputState, fee := fee }

def prepareNonCoinbaseTxBasic
    (txBytes : Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height : Nat)
    (blockTimestamp : Nat)
    (chainId : Bytes)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none)
    (enforceSigOracle : Bool := true) :
    Except String PreparedNonCoinbaseTx := do
  let core ←
    prepareNonCoinbaseTxCore
      txBytes utxoMap height blockTimestamp chainId rotDesc? enforceSigOracle

  let txid :=
    let r := RubinFormal.TxV2.parseTx txBytes
    match r.txid with
    | some t => t
    | none => SHA3.sha3_256 ByteArray.empty

  let next := insertOutputs (eraseInputs utxoMap core.tx.inputs) txid core.tx.outputs height
  pure { tx := core.tx, inputState := core.inputState, fee := core.fee, nextUtxoMap := next }

-- NOTE: This is intentionally simplified for formal replay:
-- we enforce all pre-signature rules and binding rules, but we treat cryptographic signature
-- verification as an out-of-scope predicate (handled by Go↔Rust + OpenSSL in conformance).
def applyNonCoinbaseTxBasicState
    (txBytes : Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height : Nat)
    (blockTimestamp : Nat)
    (chainId : Bytes)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none)
    (enforceSigOracle : Bool := true) :
    Except String (Nat × Std.RBMap Outpoint UtxoEntry cmpOutpoint) := do
  let prepared ←
    prepareNonCoinbaseTxBasic
      txBytes utxoMap height blockTimestamp chainId rotDesc? enforceSigOracle
  pure (prepared.fee, prepared.nextUtxoMap)

def applyNonCoinbaseTxBasic
    (txBytes : Bytes)
    (utxos : List (Outpoint × UtxoEntry))
    (height : Nat)
    (blockTimestamp : Nat)
    (chainId : Bytes)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none) :
    Except String (Nat × Nat) := do
  let (fee, next) ←
    applyNonCoinbaseTxBasicState
      txBytes (buildUtxoMap utxos) height blockTimestamp chainId rotDesc? true
  pure (fee, next.size)

-- Conformance entrypoint for callers that model signature validity elsewhere.
def applyNonCoinbaseTxBasicNoCrypto
    (txBytes : Bytes)
    (utxos : List (Outpoint × UtxoEntry))
    (height : Nat)
    (blockTimestamp : Nat)
    (chainId : Bytes)
    (rotDesc? : Option NativeSuiteRotation.RotationDeploymentDescriptor := none) :
    Except String (Nat × Nat) := do
  let (fee, next) ←
    applyNonCoinbaseTxBasicState
      txBytes (buildUtxoMap utxos) height blockTimestamp chainId rotDesc? false
  pure (fee, next.size)

end UtxoBasicV1

end RubinFormal

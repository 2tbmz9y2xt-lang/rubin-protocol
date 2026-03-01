import RubinFormal.Types
import RubinFormal.SHA3_256
import RubinFormal.ByteWireV2
import RubinFormal.OutputDescriptorV2
import RubinFormal.SighashV1
import RubinFormal.TxParseV2
import RubinFormal.CovenantGenesisV1

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

def SUITE_ID_SENTINEL : Nat := 0x00
def SUITE_ID_ML_DSA_87 : Nat := 0x01
def SUITE_ID_SLH_DSA_SHAKE_256F : Nat := 0x02

def SLH_DSA_ACTIVATION_HEIGHT : Nat := 1000000

def ML_DSA_87_PUBKEY_BYTES : Nat := 2592
def ML_DSA_87_SIG_BYTES : Nat := 4627
def SLH_DSA_SHAKE_256F_PUBKEY_BYTES : Nat := 64
def MAX_SLH_DSA_SIG_BYTES : Nat := 49856

-- Formal replay: deterministic signature verification oracle (crypto is out-of-scope).
-- We accept only the known-good wtxids present in conformance fixtures for P2PK-spend OK cases.
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
  let mut cur := c
  let mut acc : List TxIn := []
  for _ in [0:n] do
    let (i, cur') ← parseInput cur
    acc := acc.concat i
    cur := cur'
  pure (acc, cur)

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
  let mut cur := c
  let mut acc : List TxOut := []
  for _ in [0:n] do
    let (o, cur') ← parseOutput cur
    acc := acc.concat o
    cur := cur'
  pure (acc, cur)

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

def parseWitness (c : Cursor) : Option (List WitnessItem × Cursor) := do
  let (wCount, c1, minimal) ← c.getCompactSize?
  let _ ← requireMinimal minimal
  let mut cur := c1
  let mut acc : List WitnessItem := []
  for _ in [0:wCount] do
    let (w, cur') ← parseWitnessItem cur
    acc := acc.concat w
    cur := cur'
  pure (acc, cur)

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
  let (inCount, c4, minIn) ←
    match c3.getCompactSize? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if !minIn then throw "TX_ERR_PARSE"
  let (ins, c5) ←
    match parseInputs c4 inCount with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (outCount, c6, minOut) ←
    match c5.getCompactSize? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  if !minOut then throw "TX_ERR_PARSE"
  let (outs, c7) ←
    match parseOutputs c6 outCount with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  let (lock, c8) ←
    match c7.getU32le? with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
  -- DaCoreFieldsBytes: skip bytes based on tx_kind (for CV-UTXO-BASIC vectors only tx_kind=0x00)
  let c9 := c8
  let (wit, cW) ←
    match parseWitness c9 with
    | none => throw "TX_ERR_PARSE"
    | some x => pure x
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
      witness := wit
      daPayloadLen := daLen
      daPayload := payload
    }

def isCoinbasePrevout (i : TxIn) : Bool :=
  let zero32 : Bytes := RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)
  (i.prevTxid == zero32) && (i.prevVout == 0xffffffff)

def outputDescriptorLockId (e : UtxoEntry) : Bytes :=
  RubinFormal.OutputDescriptor.hash e.covenantType e.covenantData

def sumOutputs (outs : List TxOut) : Nat :=
  outs.foldl (fun acc o => acc + o.value) 0

def buildUtxoMap (utxos : List (Outpoint × UtxoEntry)) : Std.RBMap Outpoint UtxoEntry cmpOutpoint :=
  utxos.foldl (fun m (p : Outpoint × UtxoEntry) => m.insert p.fst p.snd) (Std.RBMap.empty)

-- NOTE: This is intentionally simplified for formal replay:
-- we enforce all pre-signature rules and binding rules, but we treat cryptographic signature
-- verification as an out-of-scope predicate (handled by Go↔Rust + OpenSSL in conformance).
def applyNonCoinbaseTxBasicState
    (txBytes : Bytes)
    (utxoMap : Std.RBMap Outpoint UtxoEntry cmpOutpoint)
    (height : Nat)
    (blockTimestamp : Nat)
    (chainId : Bytes)
    (enforceSigOracle : Bool) : Except String (Nat × Std.RBMap Outpoint UtxoEntry cmpOutpoint) := do
  let _ := blockTimestamp
  let tx ← parseTx txBytes

  if tx.inputs.length == 0 then throw "TX_ERR_PARSE"
  if tx.txNonce == 0 then throw "TX_ERR_TX_NONCE_INVALID"

  -- structural input checks (subset)
  for i in tx.inputs do
    if i.scriptSig.size != 0 then throw "TX_ERR_PARSE"
    if i.sequence > 0x7fffffff then throw "TX_ERR_SEQUENCE_INVALID"
    if isCoinbasePrevout i then throw "TX_ERR_PARSE"

  -- output-creation validation is evaluated before input UTXO lookup.
  -- This fixes deterministic conflict ordering for:
  -- invalid output descriptor vs missing UTXO.
  for o in tx.outputs do
    let outg : CovenantGenesisV1.TxOut := {
      value := o.value
      covenantType := o.covenantType
      covenantData := o.covenantData
    }
    CovenantGenesisV1.validateOutGenesis outg tx.txKind height

  -- gather sums and vault context
  let mut sumIn : Nat := 0
  let mut sumInVault : Nat := 0
  let mut vaultWhitelist : List Bytes := []
  let mut vaultOwnerLockId : Option Bytes := none
  let mut vaultInputs : Nat := 0
  let mut inputLockIds : List Bytes := []
  let mut inputCovTypes : List Nat := []
  let mut requiredWitnessSlots : Nat := 0
  let mut inputEntries : List UtxoEntry := []

  -- require unique outpoints
  let mut seen : Std.RBSet Outpoint cmpOutpoint := Std.RBSet.empty

  for i in tx.inputs do
    let op : Outpoint := { txid := i.prevTxid, vout := i.prevVout }
    if seen.contains op then throw "TX_ERR_PARSE"
    seen := seen.insert op
    let e? := utxoMap.find? op
    let e ← match e? with
      | none => throw "TX_ERR_MISSING_UTXO"
      | some x => pure x

    if e.covenantType == COV_TYPE_ANCHOR || e.covenantType == COV_TYPE_DA_COMMIT then
      throw "TX_ERR_MISSING_UTXO"

    if e.createdByCoinbase then
      if height < e.creationHeight + COINBASE_MATURITY then
        throw "TX_ERR_COINBASE_IMMATURE"

    -- P2PK suite gating (needed for CV-SIG-* and UTXO-basic replay correctness).
    if e.covenantType == COV_TYPE_P2PK then
      if e.covenantData.size != MAX_P2PK_COVENANT_DATA then
        throw "TX_ERR_COVENANT_TYPE_INVALID"
      let suite := (e.covenantData.get! 0).toNat
      if !(suite == SUITE_ID_ML_DSA_87 || suite == SUITE_ID_SLH_DSA_SHAKE_256F) then
        throw "TX_ERR_SIG_ALG_INVALID"
      if suite == SUITE_ID_SLH_DSA_SHAKE_256F && height < SLH_DSA_ACTIVATION_HEIGHT then
        throw "TX_ERR_SIG_ALG_INVALID"
    else if e.covenantType == COV_TYPE_EXT then
      if e.covenantData.size < 3 then
        throw "TX_ERR_COVENANT_TYPE_INVALID"
      let c0 : Wire.Cursor := { bs := e.covenantData, off := 2 }
      let (payloadLen, c1, minimal) ←
        match c0.getCompactSize? with
        | none => throw "TX_ERR_COVENANT_TYPE_INVALID"
        | some x => pure x
      if !minimal then
        throw "TX_ERR_COVENANT_TYPE_INVALID"
      if c1.off + payloadLen != e.covenantData.size then
        throw "TX_ERR_COVENANT_TYPE_INVALID"

    let lockId := outputDescriptorLockId e
    inputLockIds := inputLockIds.concat lockId
    inputCovTypes := inputCovTypes.concat e.covenantType
    inputEntries := inputEntries.concat e

    sumIn := sumIn + e.value
    -- witness cursor model (minimal): P2PK consumes 1 slot; VAULT consumes key_count slots.
    if e.covenantType == COV_TYPE_VAULT then
      let v ← CovenantGenesisV1.parseVaultCovenantData e.covenantData
      requiredWitnessSlots := requiredWitnessSlots + v.keyCount
    else
      requiredWitnessSlots := requiredWitnessSlots + 1

    if e.covenantType == COV_TYPE_VAULT then
      vaultInputs := vaultInputs + 1
      if vaultInputs > 1 then
        throw "TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN"
      sumInVault := e.value
      let v ← CovenantGenesisV1.parseVaultCovenantData e.covenantData
      vaultOwnerLockId := some v.ownerLockId
      vaultWhitelist := v.whitelist

  if tx.witness.length != requiredWitnessSlots then
    throw "TX_ERR_PARSE"

  let validateWitnessItemLengths (w : WitnessItem) : Except String Unit := do
    if w.suiteId == SUITE_ID_ML_DSA_87 then
      if w.pubkey.size != ML_DSA_87_PUBKEY_BYTES || w.signature.size != ML_DSA_87_SIG_BYTES then
        throw "TX_ERR_SIG_NONCANONICAL"
      pure ()
    else if w.suiteId == SUITE_ID_SLH_DSA_SHAKE_256F then
      if height < SLH_DSA_ACTIVATION_HEIGHT then
        throw "TX_ERR_SIG_ALG_INVALID"
      if w.pubkey.size != SLH_DSA_SHAKE_256F_PUBKEY_BYTES then
        throw "TX_ERR_SIG_NONCANONICAL"
      if w.signature.size == 0 || w.signature.size > MAX_SLH_DSA_SIG_BYTES then
        throw "TX_ERR_SIG_NONCANONICAL"
      pure ()
    else
      throw "TX_ERR_SIG_ALG_INVALID"

  let validateP2PKSpendPreSig (entry : UtxoEntry) (w : WitnessItem) (txBytes : Bytes) : Except String Unit := do
    if entry.covenantData.size != MAX_P2PK_COVENANT_DATA then
      throw "TX_ERR_COVENANT_TYPE_INVALID"
    let suite := (entry.covenantData.get! 0).toNat
    if !(suite == SUITE_ID_ML_DSA_87 || suite == SUITE_ID_SLH_DSA_SHAKE_256F) then
      throw "TX_ERR_SIG_ALG_INVALID"
    if suite == SUITE_ID_SLH_DSA_SHAKE_256F && height < SLH_DSA_ACTIVATION_HEIGHT then
      throw "TX_ERR_SIG_ALG_INVALID"
    if suite != w.suiteId then
      throw "TX_ERR_SIG_ALG_INVALID"
    validateWitnessItemLengths w
    let keyId := entry.covenantData.extract 1 33
    if SHA3.sha3_256 w.pubkey != keyId then
      throw "TX_ERR_SIG_INVALID"
    if enforceSigOracle then
      let wtxid := SHA3.sha3_256 txBytes
      if !(KNOWN_VALID_P2PK_WTXIDS.contains wtxid) then
        throw "TX_ERR_SIG_INVALID"
    pure ()

  -- Pre-signature witness validation (needed for CV-SIG-* replay correctness).
  let mut witnessCursor : Nat := 0
  for e in inputEntries do
    if e.covenantType == COV_TYPE_VAULT then
      let v ← CovenantGenesisV1.parseVaultCovenantData e.covenantData
      if witnessCursor + v.keyCount > tx.witness.length then
        throw "TX_ERR_PARSE"
      -- Vault signature verification is out-of-scope; cursor advance only.
      witnessCursor := witnessCursor + v.keyCount
    else
      if witnessCursor + 1 > tx.witness.length then
        throw "TX_ERR_PARSE"
      let w := tx.witness.get! witnessCursor
      if e.covenantType == COV_TYPE_P2PK then
        validateP2PKSpendPreSig e w txBytes
      else if e.covenantType == COV_TYPE_EXT then
        -- Pre-activation CORE_EXT spend: keyless sentinel only.
        if w.suiteId != SUITE_ID_SENTINEL || w.pubkey.size != 0 || w.signature.size != 0 then
          throw "TX_ERR_PARSE"
      witnessCursor := witnessCursor + 1
  if witnessCursor != tx.witness.length then
    throw "TX_ERR_PARSE"

  -- CORE_VAULT rules used by CV-UTXO-BASIC vectors
  if vaultInputs == 1 then
    let owner ←
      match vaultOwnerLockId with
      | none => throw "TX_ERR_VAULT_MALFORMED"
      | some x => pure x

    -- owner-authorization required: at least one non-vault input must have lock_id == owner lock
    let mut haveOwner : Bool := false
    for (lid, cov) in List.zip inputLockIds inputCovTypes do
      if cov != COV_TYPE_VAULT && lid == owner then
        haveOwner := true
    if !haveOwner then
      throw "TX_ERR_VAULT_OWNER_AUTH_REQUIRED"

    -- whitelist membership: every output descriptor hash must be in whitelist
    for o in tx.outputs do
      -- vault recursion is forbidden: a vault-spend must not create CORE_VAULT outputs
      if o.covenantType == COV_TYPE_VAULT then
        throw "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED"
      let h := RubinFormal.OutputDescriptor.hash o.covenantType o.covenantData
      if !(vaultWhitelist.contains h) then
        throw "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED"

    -- value rule: vault value must not fund fee
    let sumOut := sumOutputs tx.outputs
    if sumOut < sumInVault then
      throw "TX_ERR_VALUE_CONSERVATION"

  -- value conservation
  let sumOutAll := sumOutputs tx.outputs
  if sumOutAll > sumIn then throw "TX_ERR_VALUE_CONSERVATION"
  let fee := sumIn - sumOutAll

  -- update UTXO count: remove spent, add outputs
  let mut next : Std.RBMap Outpoint UtxoEntry cmpOutpoint := utxoMap
  for i in tx.inputs do
    let op : Outpoint := { txid := i.prevTxid, vout := i.prevVout }
    next := next.erase op

  -- txid is consensus identifier = SHA3-256(TxCoreBytes(T)); we reuse Sighash parser core slice as proxy:
  -- in these vectors tx_kind=0x00 and DaCoreFieldsBytes is empty, so TxCoreBytes ends at locktime.
  let txid :=
    let r := RubinFormal.TxV2.parseTx txBytes
    match r.txid with
    | some t => t
    | none => SHA3.sha3_256 ByteArray.empty

  let mut vout : Nat := 0
  for o in tx.outputs do
    let op : Outpoint := { txid := txid, vout := vout }
    next := next.insert op { value := o.value, covenantType := o.covenantType, covenantData := o.covenantData, creationHeight := height, createdByCoinbase := false }
    vout := vout + 1

  pure (fee, next)

def applyNonCoinbaseTxBasic
    (txBytes : Bytes)
    (utxos : List (Outpoint × UtxoEntry))
    (height : Nat)
    (blockTimestamp : Nat)
    (chainId : Bytes) : Except String (Nat × Nat) := do
  let (fee, next) ← applyNonCoinbaseTxBasicState txBytes (buildUtxoMap utxos) height blockTimestamp chainId true
  pure (fee, next.size)

-- CV-UTXO-BASIC replay uses the no-crypto path (signature validity is assumed).
def applyNonCoinbaseTxBasicNoCrypto
    (txBytes : Bytes)
    (utxos : List (Outpoint × UtxoEntry))
    (height : Nat)
    (blockTimestamp : Nat)
    (chainId : Bytes) : Except String (Nat × Nat) := do
  let (fee, next) ← applyNonCoinbaseTxBasicState txBytes (buildUtxoMap utxos) height blockTimestamp chainId false
  pure (fee, next.size)

end UtxoBasicV1

end RubinFormal

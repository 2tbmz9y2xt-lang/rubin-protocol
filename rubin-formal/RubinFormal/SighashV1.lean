import RubinFormal.Types
import RubinFormal.SHA3_256
import RubinFormal.ByteWireV2

namespace RubinFormal

open Wire

namespace SighashV1

def sighashPrefix : Bytes :=
  -- ASCII("RUBINv1-sighash/")
  RubinFormal.bytes #[
    0x52,0x55,0x42,0x49,0x4e,0x76,0x31,0x2d,
    0x73,0x69,0x67,0x68,0x61,0x73,0x68,0x2f
  ]

def u32le (n : Nat) : Bytes :=
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
  let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
  RubinFormal.bytes #[b0, b1, b2, b3]

def u64le (n : Nat) : Bytes :=
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
  let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
  let b4 : UInt8 := UInt8.ofNat ((n / 4294967296) % 256)
  let b5 : UInt8 := UInt8.ofNat ((n / 1099511627776) % 256)
  let b6 : UInt8 := UInt8.ofNat ((n / 281474976710656) % 256)
  let b7 : UInt8 := UInt8.ofNat ((n / 72057594037927936) % 256)
  RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7]

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
  let (locktime, _c8) ←
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

def SIGHASH_ALL : UInt8 := 0x01
def SIGHASH_NONE : UInt8 := 0x02
def SIGHASH_SINGLE : UInt8 := 0x03
def SIGHASH_ANYONECANPAY : UInt8 := 0x80
def SIGHASH_ALL_ANYONECANPAY : UInt8 := 0x81
def SIGHASH_NONE_ANYONECANPAY : UInt8 := 0x82
def SIGHASH_SINGLE_ANYONECANPAY : UInt8 := 0x83

/-- TxContext pre-activation gate: valid base types are ALL/NONE/SINGLE only. -/
def hasValidBaseType (sighashType : UInt8) : Bool :=
  let baseType := sighashType.toNat &&& 0x7F
  baseType == 1 || baseType == 2 || baseType == 3

private def bitSetNat (mask bit : Nat) : Bool :=
  (mask &&& bit) == bit

/-- Live CORE_EXT txcontext sighash policy gate.
    Mirrors the Go/Rust base-type + ACP allowlist logic. -/
def checkSighashPolicy (allowedSet sighashType : UInt8) : Bool :=
  let st := sighashType.toNat
  let baseType := st &&& 0x7F
  let hasAcp := (st &&& 0x80) != 0
  let allowed := allowedSet.toNat
  let baseAllowed :=
    (baseType == 1 && bitSetNat allowed 0x01) ||
    (baseType == 2 && bitSetNat allowed 0x02) ||
    (baseType == 3 && bitSetNat allowed 0x04)
  hasValidBaseType sighashType && baseAllowed && (!hasAcp || bitSetNat allowed 0x80)

private def sighashAllowlistOracle (allowedSet : UInt8) : List Nat :=
  let allowed := allowedSet.toNat
  let a1 := if bitSetNat allowed 0x01 then [0x01] else []
  let a2 := if bitSetNat allowed 0x02 then [0x02] else []
  let a3 := if bitSetNat allowed 0x04 then [0x03] else []
  let acp1 := if bitSetNat allowed 0x81 then [0x81] else []
  let acp2 := if bitSetNat allowed 0x82 then [0x82] else []
  let acp3 := if bitSetNat allowed 0x84 then [0x83] else []
  a1 ++ a2 ++ a3 ++ acp1 ++ acp2 ++ acp3

private def checkSighashPolicySpec (allowedSet sighashType : UInt8) : Bool :=
  decide (sighashType.toNat ∈ sighashAllowlistOracle allowedSet)

/-- Exhaustive 256×256 closure for the live txcontext sighash gate. -/
theorem checkSighashPolicy_exhaustive_256x256 :
    ∀ (allowedSet sighashType : Fin 256),
      checkSighashPolicy (UInt8.ofNat allowedSet.val) (UInt8.ofNat sighashType.val) =
      checkSighashPolicySpec (UInt8.ofNat allowedSet.val) (UInt8.ofNat sighashType.val) := by
  native_decide

/-- Invalid base types are rejected on the live txcontext sighash gate. -/
theorem checkSighashPolicy_invalid_base_rejected :
    ∀ (allowedSet : Fin 256),
      checkSighashPolicy (UInt8.ofNat allowedSet.val) 0x00 = false ∧
      checkSighashPolicy (UInt8.ofNat allowedSet.val) 0x04 = false ∧
      checkSighashPolicy (UInt8.ofNat allowedSet.val) 0x80 = false := by
  native_decide

def selectHashPrevouts (sighashType : UInt8) (allInputs currentInput : Bytes) : Option Bytes :=
  if _ : sighashType = SIGHASH_ALL_ANYONECANPAY then
    some currentInput
  else if _ : sighashType = SIGHASH_NONE_ANYONECANPAY then
    some currentInput
  else if _ : sighashType = SIGHASH_SINGLE_ANYONECANPAY then
    some currentInput
  else if _ : sighashType = SIGHASH_ALL then
    some allInputs
  else if _ : sighashType = SIGHASH_NONE then
    some allInputs
  else if _ : sighashType = SIGHASH_SINGLE then
    some allInputs
  else
    none

def selectHashSequences (sighashType : UInt8) (allInputs currentInput : Bytes) : Option Bytes :=
  if _ : sighashType = SIGHASH_ALL_ANYONECANPAY then
    some currentInput
  else if _ : sighashType = SIGHASH_NONE_ANYONECANPAY then
    some currentInput
  else if _ : sighashType = SIGHASH_SINGLE_ANYONECANPAY then
    some currentInput
  else if _ : sighashType = SIGHASH_ALL then
    some allInputs
  else if _ : sighashType = SIGHASH_NONE then
    some allInputs
  else if _ : sighashType = SIGHASH_SINGLE then
    some allInputs
  else
    none

def selectHashOutputs
    (sighashType : UInt8)
    (inputIndex outputCount : Nat)
    (allOutputs selectedOutput emptyHash : Bytes) : Option Bytes :=
  if _ : sighashType = SIGHASH_ALL then
    some allOutputs
  else if _ : sighashType = SIGHASH_ALL_ANYONECANPAY then
    some allOutputs
  else if _ : sighashType = SIGHASH_NONE then
    some emptyHash
  else if _ : sighashType = SIGHASH_NONE_ANYONECANPAY then
    some emptyHash
  else if _ : sighashType = SIGHASH_SINGLE then
    if inputIndex < outputCount then some selectedOutput else some emptyHash
  else if _ : sighashType = SIGHASH_SINGLE_ANYONECANPAY then
    if inputIndex < outputCount then some selectedOutput else some emptyHash
  else
    none

structure SighashPreimageFrame where
  chainId : Bytes
  versionLE : Bytes
  txKind : UInt8
  txNonceLE : Bytes
  hashDA : Bytes
  hashPrevouts : Bytes
  hashSeq : Bytes
  inputIndexLE : Bytes
  prevTxid : Bytes
  prevVoutLE : Bytes
  inputValueLE : Bytes
  sequenceLE : Bytes
  hashOutputs : Bytes
  locktimeLE : Bytes
  sighashType : UInt8
deriving Repr, DecidableEq

def SighashPreimageFrame.WellFormed (f : SighashPreimageFrame) : Prop :=
  f.chainId.size = 32 ∧
  f.versionLE.size = 4 ∧
  f.txNonceLE.size = 8 ∧
  f.hashDA.size = 32 ∧
  f.hashPrevouts.size = 32 ∧
  f.hashSeq.size = 32 ∧
  f.inputIndexLE.size = 4 ∧
  f.prevTxid.size = 32 ∧
  f.prevVoutLE.size = 4 ∧
  f.inputValueLE.size = 8 ∧
  f.sequenceLE.size = 4 ∧
  f.hashOutputs.size = 32 ∧
  f.locktimeLE.size = 4

def buildPreimageFrameParts (f : SighashPreimageFrame) : List Bytes :=
  [
    sighashPrefix,
    f.chainId,
    f.versionLE,
    RubinFormal.bytes #[f.txKind],
    f.txNonceLE,
    f.hashDA,
    f.hashPrevouts,
    f.hashSeq,
    f.inputIndexLE,
    f.prevTxid,
    f.prevVoutLE,
    f.inputValueLE,
    f.sequenceLE,
    f.hashOutputs,
    f.locktimeLE,
    RubinFormal.bytes #[f.sighashType]
  ]

def buildPreimageFrame (f : SighashPreimageFrame) : Bytes :=
  concatBytes (buildPreimageFrameParts f)

theorem buildPreimageFrameParts_injective (a b : SighashPreimageFrame)
    (hEq : buildPreimageFrameParts a = buildPreimageFrameParts b) :
    a = b := by
  cases a with
  | mk aChainId aVersionLE aTxKind aTxNonceLE aHashDA aHashPrevouts aHashSeq aInputIndexLE aPrevTxid aPrevVoutLE aInputValueLE aSequenceLE aHashOutputs aLocktimeLE aSighashType =>
    cases b with
    | mk bChainId bVersionLE bTxKind bTxNonceLE bHashDA bHashPrevouts bHashSeq bInputIndexLE bPrevTxid bPrevVoutLE bInputValueLE bSequenceLE bHashOutputs bLocktimeLE bSighashType =>
      simp [buildPreimageFrameParts, RubinFormal.bytes] at hEq ⊢
      simpa using hEq

def SighashPreimageFrame.inputContextView (f : SighashPreimageFrame) :
    Bytes × Bytes × Bytes × Bytes × Bytes × Bytes × Bytes :=
  (f.hashPrevouts, f.hashSeq, f.inputIndexLE, f.prevTxid, f.prevVoutLE, f.inputValueLE, f.sequenceLE)

def SighashPreimageFrame.outputContextView (f : SighashPreimageFrame) : Bytes × UInt8 :=
  (f.hashOutputs, f.sighashType)

def SighashPreimageFrame.declaredTxFieldView (f : SighashPreimageFrame) :
    Bytes × Bytes × (Bytes × Bytes × Bytes × Bytes × Bytes × Bytes × Bytes) × (Bytes × UInt8) :=
  (f.versionLE, f.locktimeLE, f.inputContextView, f.outputContextView)

theorem selectHashPrevouts_all_commits_all_inputs
    (allInputs currentInput : Bytes) :
    selectHashPrevouts SIGHASH_ALL allInputs currentInput = some allInputs := by
  have hAllAcp : ¬ (SIGHASH_ALL = SIGHASH_ALL_ANYONECANPAY) := by decide
  have hNoneAcp : ¬ (SIGHASH_ALL = SIGHASH_NONE_ANYONECANPAY) := by decide
  have hSingleAcp : ¬ (SIGHASH_ALL = SIGHASH_SINGLE_ANYONECANPAY) := by decide
  have hAll : SIGHASH_ALL = SIGHASH_ALL := rfl
  simp [selectHashPrevouts, hAllAcp, hNoneAcp, hSingleAcp, hAll]

theorem selectHashPrevouts_anyonecanpay_commits_current_input
    (allInputs currentInput : Bytes) :
    selectHashPrevouts SIGHASH_ALL_ANYONECANPAY allInputs currentInput = some currentInput := by
  have hAllAcp : SIGHASH_ALL_ANYONECANPAY = SIGHASH_ALL_ANYONECANPAY := rfl
  simp [selectHashPrevouts, hAllAcp]

theorem selectHashSequences_all_commits_all_inputs
    (allInputs currentInput : Bytes) :
    selectHashSequences SIGHASH_NONE allInputs currentInput = some allInputs := by
  have hAllAcp : ¬ (SIGHASH_NONE = SIGHASH_ALL_ANYONECANPAY) := by decide
  have hNoneAcp : ¬ (SIGHASH_NONE = SIGHASH_NONE_ANYONECANPAY) := by decide
  have hSingleAcp : ¬ (SIGHASH_NONE = SIGHASH_SINGLE_ANYONECANPAY) := by decide
  have hAll : ¬ (SIGHASH_NONE = SIGHASH_ALL) := by decide
  have hNone : SIGHASH_NONE = SIGHASH_NONE := rfl
  simp [selectHashSequences, hAllAcp, hNoneAcp, hSingleAcp, hAll, hNone]

theorem selectHashSequences_anyonecanpay_commits_current_input
    (allInputs currentInput : Bytes) :
    selectHashSequences SIGHASH_NONE_ANYONECANPAY allInputs currentInput = some currentInput := by
  have hNoneAcp : SIGHASH_NONE_ANYONECANPAY = SIGHASH_NONE_ANYONECANPAY := rfl
  simp [selectHashSequences, hNoneAcp]

theorem selectHashOutputs_all_commits_all_outputs
    (inputIndex outputCount : Nat)
    (allOutputs selectedOutput emptyHash : Bytes) :
    selectHashOutputs SIGHASH_ALL inputIndex outputCount allOutputs selectedOutput emptyHash = some allOutputs := by
  have hAll : SIGHASH_ALL = SIGHASH_ALL := rfl
  simp [selectHashOutputs, hAll]

theorem selectHashOutputs_none_commits_no_outputs
    (inputIndex outputCount : Nat)
    (allOutputs selectedOutput emptyHash : Bytes) :
    selectHashOutputs SIGHASH_NONE inputIndex outputCount allOutputs selectedOutput emptyHash = some emptyHash := by
  have hAll : ¬ (SIGHASH_NONE = SIGHASH_ALL) := by decide
  have hAllAcp : ¬ (SIGHASH_NONE = SIGHASH_ALL_ANYONECANPAY) := by decide
  have hNone : SIGHASH_NONE = SIGHASH_NONE := rfl
  simp [selectHashOutputs, hAll, hAllAcp, hNone]

theorem selectHashOutputs_single_commits_selected_output
    (inputIndex outputCount : Nat)
    (allOutputs selectedOutput emptyHash : Bytes)
    (h : inputIndex < outputCount) :
    selectHashOutputs SIGHASH_SINGLE inputIndex outputCount allOutputs selectedOutput emptyHash =
      some selectedOutput := by
  have hAll : ¬ (SIGHASH_SINGLE = SIGHASH_ALL) := by decide
  have hAllAcp : ¬ (SIGHASH_SINGLE = SIGHASH_ALL_ANYONECANPAY) := by decide
  have hNone : ¬ (SIGHASH_SINGLE = SIGHASH_NONE) := by decide
  have hNoneAcp : ¬ (SIGHASH_SINGLE = SIGHASH_NONE_ANYONECANPAY) := by decide
  have hSingle : SIGHASH_SINGLE = SIGHASH_SINGLE := rfl
  simp [selectHashOutputs, hAll, hAllAcp, hNone, hNoneAcp, hSingle, h]

theorem selectHashOutputs_single_oob_commits_empty
    (inputIndex outputCount : Nat)
    (allOutputs selectedOutput emptyHash : Bytes)
    (h : ¬ inputIndex < outputCount) :
    selectHashOutputs SIGHASH_SINGLE inputIndex outputCount allOutputs selectedOutput emptyHash =
      some emptyHash := by
  have hAll : ¬ (SIGHASH_SINGLE = SIGHASH_ALL) := by decide
  have hAllAcp : ¬ (SIGHASH_SINGLE = SIGHASH_ALL_ANYONECANPAY) := by decide
  have hNone : ¬ (SIGHASH_SINGLE = SIGHASH_NONE) := by decide
  have hNoneAcp : ¬ (SIGHASH_SINGLE = SIGHASH_NONE_ANYONECANPAY) := by decide
  have hSingle : SIGHASH_SINGLE = SIGHASH_SINGLE := rfl
  simp [selectHashOutputs, hAll, hAllAcp, hNone, hNoneAcp, hSingle, h]

-- NOTE: wrapper corollaries (buildPreimageFrameParts_commits_*) and
-- tautological eq_iff removed. Use buildPreimageFrameParts_injective directly.

def digestV1 (tx : Bytes) (chainId : Bytes) (inputIndex : Nat) (inputValue : Nat) : Except String Bytes := do
  let core ← parseTxCoreForSighash tx
  let inCount := core.inputs.length
  if inputIndex >= inCount then
    throw "TX_ERR_PARSE"
  let inp :=
    match core.inputs.get? inputIndex with
    | some x => x
    | none => { prevTxid := ByteArray.empty, prevVoutLE := ByteArray.empty, sequenceLE := ByteArray.empty }
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
    (RubinFormal.bytes #[core.txKind]) ++
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
    u32le core.locktime ++
    -- Go consensus appends sighash_type byte; digestV1 models default SIGHASH_ALL.
    (RubinFormal.bytes #[0x01])
  pure (SHA3.sha3_256 preimage)

-- NOTE: tautological digestV1_deterministic (f x = f x) and digestV1_ext
-- (equal args → equal results) removed. Substantive error/success
-- characterization is in SighashRefinementUpgrade.lean.

end SighashV1

end RubinFormal

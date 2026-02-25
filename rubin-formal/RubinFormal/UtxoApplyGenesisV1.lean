import Std
import RubinFormal.SHA3_256
import RubinFormal.OutputDescriptorV2
import RubinFormal.UtxoBasicV1
import RubinFormal.CovenantGenesisV1

namespace RubinFormal

abbrev Bytes := ByteArray

namespace UtxoApplyGenesisV1

open RubinFormal
open RubinFormal.UtxoBasicV1
open RubinFormal.CovenantGenesisV1

def SUITE_ID_SENTINEL : Nat := CovenantGenesisV1.SUITE_ID_SENTINEL
def SUITE_ID_ML_DSA_87 : Nat := CovenantGenesisV1.SUITE_ID_ML_DSA_87
def SUITE_ID_SLH_DSA_SHAKE_256F : Nat := CovenantGenesisV1.SUITE_ID_SLH_DSA_SHAKE_256F

def ML_DSA_87_PUBKEY_BYTES : Nat := 2592
def ML_DSA_87_SIG_BYTES : Nat := 4627
def SLH_DSA_SHAKE_256F_PUBKEY_BYTES : Nat := 64
def MAX_SLH_DSA_SIG_BYTES : Nat := 49_856

def WITNESS_SLOTS (covType : Nat) (covData : Bytes) : Except String Nat := do
  if covType == CovenantGenesisV1.COV_TYPE_HTLC then
    pure 2
  else if covType == CovenantGenesisV1.COV_TYPE_MULTISIG then
    if covData.size < 2 then throw "TX_ERR_PARSE"
    pure (covData.get! 1).toNat
  else if covType == CovenantGenesisV1.COV_TYPE_VAULT then
    if covData.size < 34 then throw "TX_ERR_VAULT_MALFORMED"
    pure (covData.get! 33).toNat
  else
    pure 1

def lockIdOfEntry (e : UtxoEntry) : Bytes :=
  RubinFormal.OutputDescriptor.hash e.covenantType e.covenantData

def parseU16le (b0 b1 : UInt8) : Nat :=
  Wire.u16le? b0 b1

def validateP2PKSpendPreSig (entry : UtxoEntry) (w : WitnessItem) (blockHeight : Nat) : Except String Unit := do
  let suite := w.suiteId
  if !(suite == SUITE_ID_ML_DSA_87 || suite == SUITE_ID_SLH_DSA_SHAKE_256F) then
    throw "TX_ERR_SIG_ALG_INVALID"
  if suite == SUITE_ID_SLH_DSA_SHAKE_256F && blockHeight < CovenantGenesisV1.SLH_DSA_ACTIVATION_HEIGHT then
    throw "TX_ERR_SIG_ALG_INVALID"
  if entry.covenantData.size != CovenantGenesisV1.MAX_P2PK_COVENANT_DATA then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  if (entry.covenantData.get! 0).toNat != suite then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  let keyId := entry.covenantData.extract 1 33
  if SHA3.sha3_256 w.pubkey != keyId then
    throw "TX_ERR_SIG_INVALID"
  -- crypto verify omitted (out-of-scope for formal replay)
  pure ()

def validateWitnessItemLengths (w : WitnessItem) (blockHeight : Nat) : Except String Unit := do
  match w.suiteId with
  | SUITE_ID_SENTINEL =>
      if w.pubkey.size != 0 || w.signature.size != 0 then
        throw "TX_ERR_PARSE"
      pure ()
  | SUITE_ID_ML_DSA_87 =>
      if w.pubkey.size != ML_DSA_87_PUBKEY_BYTES || w.signature.size != ML_DSA_87_SIG_BYTES then
        throw "TX_ERR_SIG_NONCANONICAL"
      pure ()
  | SUITE_ID_SLH_DSA_SHAKE_256F =>
      if blockHeight < CovenantGenesisV1.SLH_DSA_ACTIVATION_HEIGHT then
        throw "TX_ERR_SIG_ALG_INVALID"
      if w.pubkey.size != SLH_DSA_SHAKE_256F_PUBKEY_BYTES then
        throw "TX_ERR_SIG_NONCANONICAL"
      if w.signature.size == 0 || w.signature.size > MAX_SLH_DSA_SIG_BYTES then
        throw "TX_ERR_SIG_NONCANONICAL"
      pure ()
  | _ =>
      throw "TX_ERR_SIG_ALG_INVALID"

def validateThresholdSigSpendNoCrypto
    (keys : List Bytes)
    (threshold : Nat)
    (ws : List WitnessItem)
    (blockHeight : Nat)
    (context : String) : Except String Unit := do
  if ws.length != keys.length then
    throw "TX_ERR_PARSE"
  let mut valid : Nat := 0
  for i in [0:keys.length] do
    let w := ws.get! i
    let key := keys.get! i
    match w.suiteId with
    | SUITE_ID_SENTINEL => pure ()
    | SUITE_ID_ML_DSA_87 | SUITE_ID_SLH_DSA_SHAKE_256F =>
        if w.suiteId == SUITE_ID_SLH_DSA_SHAKE_256F && blockHeight < CovenantGenesisV1.SLH_DSA_ACTIVATION_HEIGHT then
          throw "TX_ERR_SIG_ALG_INVALID"
        if SHA3.sha3_256 w.pubkey != key then
          throw "TX_ERR_SIG_INVALID"
        valid := valid + 1
    | _ =>
        throw "TX_ERR_SIG_ALG_INVALID"
  if valid < threshold then
    throw "TX_ERR_SIG_INVALID"
  pure ()

def validateHTLCSpendNoCrypto
    (entry : UtxoEntry)
    (pathItem : WitnessItem)
    (sigItem : WitnessItem)
    (blockHeight : Nat)
    (blockMtp : Nat) : Except String Unit := do
  let c ← CovenantGenesisV1.parseHtlcCovenantData entry.covenantData

  if pathItem.suiteId != SUITE_ID_SENTINEL then
    throw "TX_ERR_PARSE"
  if pathItem.pubkey.size != 32 then
    throw "TX_ERR_PARSE"
  if pathItem.signature.size < 1 then
    throw "TX_ERR_PARSE"
  let pathId := (pathItem.signature.get! 0).toNat
  let mut expectedKeyId : Bytes := ByteArray.empty
  if pathId == 0x00 then
    if pathItem.signature.size < 3 then
      throw "TX_ERR_PARSE"
    let preLen := parseU16le (pathItem.signature.get! 1) (pathItem.signature.get! 2)
    if preLen == 0 then
      throw "TX_ERR_PARSE"
    if preLen > 256 then
      throw "TX_ERR_PARSE"
    if pathItem.signature.size != 3 + preLen then
      throw "TX_ERR_PARSE"
    let pathKeyId := pathItem.pubkey
    if pathKeyId != c.claimKeyId then
      throw "TX_ERR_SIG_INVALID"
    let preimage := pathItem.signature.extract 3 (3 + preLen)
    if SHA3.sha3_256 preimage != c.hash then
      throw "TX_ERR_SIG_INVALID"
    expectedKeyId := c.claimKeyId
  else if pathId == 0x01 then
    if pathItem.signature.size != 1 then
      throw "TX_ERR_PARSE"
    let pathKeyId := pathItem.pubkey
    if pathKeyId != c.refundKeyId then
      throw "TX_ERR_SIG_INVALID"
    if c.lockMode == CovenantGenesisV1.LOCK_MODE_HEIGHT then
      if blockHeight < c.lockValue then
        throw "TX_ERR_TIMELOCK_NOT_MET"
    else
      if blockMtp < c.lockValue then
        throw "TX_ERR_TIMELOCK_NOT_MET"
    expectedKeyId := c.refundKeyId
  else
    throw "TX_ERR_PARSE"

  -- sig item structural checks + activation
  validateWitnessItemLengths sigItem blockHeight
  if SHA3.sha3_256 sigItem.pubkey != expectedKeyId then
    throw "TX_ERR_SIG_INVALID"
  -- crypto verify omitted
  pure ()

def applyNonCoinbaseTxBasicNoCrypto
    (txBytes : Bytes)
    (utxos : List (Outpoint × UtxoEntry))
    (height : Nat)
    (blockTimestamp : Nat)
    (blockMtp : Nat)
    (chainId : Bytes) : Except String (Nat × Nat) := do
  let _ := chainId
  let tx ← UtxoBasicV1.parseTx txBytes

  if tx.inputs.length == 0 then throw "TX_ERR_PARSE"
  if tx.txNonce == 0 then throw "TX_ERR_TX_NONCE_INVALID"

  -- output covenant validity
  for o in tx.outputs do
    CovenantGenesisV1.validateOutGenesis
      { value := o.value, covenantType := o.covenantType, covenantData := o.covenantData }
      tx.txKind height

  -- build lookup
  let utxoMap := UtxoBasicV1.buildUtxoMap utxos
  let mut next := utxoMap

  let mut sumIn : Nat := 0
  let mut sumInVault : Nat := 0
  let mut vaultInputCount : Nat := 0
  let mut vaultWhitelist : List Bytes := []
  let mut vaultOwnerLockId : Bytes := ByteArray.empty
  let mut vaultKeys : List Bytes := []
  let mut vaultThreshold : Nat := 0
  let mut vaultWitness : List WitnessItem := []

  let mut witnessCursor : Nat := 0
  let mut inputLockIds : List Bytes := []
  let mut inputCovTypes : List Nat := []

  let mut seen : Std.RBSet Outpoint UtxoBasicV1.cmpOutpoint := Std.RBSet.empty

  for inputIndex in [0:tx.inputs.length] do
    let i := tx.inputs.get! inputIndex
    if i.scriptSig.size != 0 then throw "TX_ERR_PARSE"
    if i.sequence > 0x7fffffff then throw "TX_ERR_SEQUENCE_INVALID"
    if UtxoBasicV1.isCoinbasePrevout i then throw "TX_ERR_PARSE"
    let op : Outpoint := { txid := i.prevTxid, vout := i.prevVout }
    if seen.contains op then throw "TX_ERR_PARSE"
    seen := seen.insert op

    let e? := next.find? op
    let e ← match e? with
      | none => throw "TX_ERR_MISSING_UTXO"
      | some x => pure x
    if e.covenantType == CovenantGenesisV1.COV_TYPE_ANCHOR || e.covenantType == CovenantGenesisV1.COV_TYPE_DA_COMMIT then
      throw "TX_ERR_MISSING_UTXO"
    if e.createdByCoinbase then
      if height < e.creationHeight + UtxoBasicV1.COINBASE_MATURITY then
        throw "TX_ERR_COINBASE_IMMATURE"

    -- spend covenant structural validity (parsers)
    match e.covenantType with
    | CovenantGenesisV1.COV_TYPE_P2PK =>
        let slots ← WITNESS_SLOTS e.covenantType e.covenantData
        if slots != 1 then throw "TX_ERR_PARSE"
        if witnessCursor + slots > tx.witness.length then throw "TX_ERR_PARSE"
        let w := tx.witness.get! witnessCursor
        -- pre-signature checks only
        validateP2PKSpendPreSig e w height
        witnessCursor := witnessCursor + 1
    | CovenantGenesisV1.COV_TYPE_MULTISIG =>
        let m ← CovenantGenesisV1.parseMultisigCovenantData e.covenantData
        let slots ← WITNESS_SLOTS e.covenantType e.covenantData
        if witnessCursor + slots > tx.witness.length then throw "TX_ERR_PARSE"
        let assigned := (tx.witness.drop witnessCursor).take slots
        witnessCursor := witnessCursor + slots
        validateThresholdSigSpendNoCrypto m.keys m.threshold assigned height "CORE_MULTISIG"
    | CovenantGenesisV1.COV_TYPE_VAULT =>
        let v ← CovenantGenesisV1.parseVaultCovenantData e.covenantData
        let slots ← WITNESS_SLOTS e.covenantType e.covenantData
        if witnessCursor + slots > tx.witness.length then throw "TX_ERR_PARSE"
        let assigned := (tx.witness.drop witnessCursor).take slots
        witnessCursor := witnessCursor + slots
        vaultInputCount := vaultInputCount + 1
        if vaultInputCount > 1 then
          throw "TX_ERR_VAULT_MULTI_INPUT_FORBIDDEN"
        sumInVault := sumInVault + e.value
        vaultWhitelist := v.whitelist
        vaultOwnerLockId := v.ownerLockId
        vaultKeys := v.keys
        vaultThreshold := v.threshold
        vaultWitness := assigned
    | CovenantGenesisV1.COV_TYPE_HTLC =>
        let _ ← CovenantGenesisV1.parseHtlcCovenantData e.covenantData
        let slots ← WITNESS_SLOTS e.covenantType e.covenantData
        if slots != 2 then throw "TX_ERR_PARSE"
        if witnessCursor + slots > tx.witness.length then throw "TX_ERR_PARSE"
        let pathItem := tx.witness.get! witnessCursor
        let sigItem := tx.witness.get! (witnessCursor + 1)
        witnessCursor := witnessCursor + 2
        validateHTLCSpendNoCrypto e pathItem sigItem height blockMtp
    | _ =>
        -- unsupported covenant in basic apply path
        throw "TX_ERR_COVENANT_TYPE_INVALID"

    let lid := lockIdOfEntry e
    inputLockIds := inputLockIds.concat lid
    inputCovTypes := inputCovTypes.concat e.covenantType
    sumIn := sumIn + e.value
    next := next.erase op

  if witnessCursor != tx.witness.length then
    throw "TX_ERR_PARSE"

  -- outputs: add to UTXO (excluding non-spendable)
  let mut sumOut : Nat := 0
  let mut createsVault : Bool := false
  for o in tx.outputs do
    sumOut := sumOut + o.value
    if o.covenantType == CovenantGenesisV1.COV_TYPE_VAULT then
      createsVault := true
  let txid := SHA3.sha3_256 txBytes
  for outIndex in [0:tx.outputs.length] do
    let oo := tx.outputs.get! outIndex
    if oo.covenantType == CovenantGenesisV1.COV_TYPE_ANCHOR || oo.covenantType == CovenantGenesisV1.COV_TYPE_DA_COMMIT then
      continue
    let op2 : Outpoint := { txid := txid, vout := outIndex }
    next := next.insert op2 { value := oo.value, covenantType := oo.covenantType, covenantData := oo.covenantData, creationHeight := height, createdByCoinbase := false }

  -- CORE_VAULT creation requires owner-authorized input (lock_id match + type P2PK/MULTISIG).
  if createsVault then
    for o in tx.outputs do
      if o.covenantType != CovenantGenesisV1.COV_TYPE_VAULT then
        continue
      let v ← CovenantGenesisV1.parseVaultCovenantData o.covenantData
      let owner := v.ownerLockId
      let mut hasOwnerLockId : Bool := false
      let mut hasOwnerLockType : Bool := false
      for idx in [0:inputLockIds.length] do
        if inputLockIds.get! idx != owner then
          continue
        hasOwnerLockId := true
        let cov := inputCovTypes.get! idx
        if cov == CovenantGenesisV1.COV_TYPE_P2PK || cov == CovenantGenesisV1.COV_TYPE_MULTISIG then
          hasOwnerLockType := true
      if !hasOwnerLockId || !hasOwnerLockType then
        throw "TX_ERR_VAULT_OWNER_AUTH_REQUIRED"

  -- CORE_VAULT spend rules (safe-only model).
  if vaultInputCount == 1 then
    let mut ownerAuthPresent : Bool := false
    for lid in inputLockIds do
      if lid == vaultOwnerLockId then ownerAuthPresent := true
    if !ownerAuthPresent then
      throw "TX_ERR_VAULT_OWNER_AUTH_REQUIRED"
    for idx in [0:inputCovTypes.length] do
      let cov := inputCovTypes.get! idx
      if cov == CovenantGenesisV1.COV_TYPE_VAULT then
        continue
      if inputLockIds.get! idx != vaultOwnerLockId then
        throw "TX_ERR_VAULT_FEE_SPONSOR_FORBIDDEN"
    validateThresholdSigSpendNoCrypto vaultKeys vaultThreshold vaultWitness height "CORE_VAULT"
    for o in tx.outputs do
      let h := RubinFormal.OutputDescriptor.hash o.covenantType o.covenantData
      if !(vaultWhitelist.contains h) then
        throw "TX_ERR_VAULT_OUTPUT_NOT_WHITELISTED"

  if sumOut > sumIn then
    throw "TX_ERR_VALUE_CONSERVATION"
  if vaultInputCount == 1 && sumOut < sumInVault then
    throw "TX_ERR_VALUE_CONSERVATION"

  let fee := sumIn - sumOut
  pure (fee, next.size)

end UtxoApplyGenesisV1

end RubinFormal

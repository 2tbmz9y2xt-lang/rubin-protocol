import RubinFormal.Types
import RubinFormal.SHA3_256
import RubinFormal.ByteWireV2

namespace RubinFormal

open Wire

namespace CovenantGenesisV1

def MAX_P2PK_COVENANT_DATA : Nat := 33
def MAX_ANCHOR_PAYLOAD_SIZE : Nat := 65536
def MAX_HTLC_COVENANT_DATA : Nat := 105

def MAX_VAULT_KEYS : Nat := 12
def MAX_VAULT_WHITELIST_ENTRIES : Nat := 1024
def MAX_MULTISIG_KEYS : Nat := 12

def SUITE_ID_SENTINEL : Nat := 0x00
def SUITE_ID_ML_DSA_87 : Nat := 0x01
def SUITE_ID_SLH_DSA_SHAKE_256F : Nat := 0x02
def SLH_DSA_ACTIVATION_HEIGHT : Nat := 1000000

def COV_TYPE_P2PK : Nat := 0x0000
def COV_TYPE_ANCHOR : Nat := 0x0002
def COV_TYPE_RESERVED_FUTURE : Nat := 0x00FF
def COV_TYPE_HTLC : Nat := 0x0100
def COV_TYPE_VAULT : Nat := 0x0101
def COV_TYPE_DA_COMMIT : Nat := 0x0103
def COV_TYPE_MULTISIG : Nat := 0x0104

def LOCK_MODE_HEIGHT : Nat := 0x00
def LOCK_MODE_TIMESTAMP : Nat := 0x01

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

def strictlySortedUnique32 (xs : List Bytes) : Bool :=
  let rec go : List Bytes → Bool
    | [] => true
    | [_] => true
    | x :: y :: rest =>
        if x.size != 32 || y.size != 32 then
          false
        else
          match cmpBytes x y with
          | .lt => go (y :: rest)
          | _ => false
  go xs

structure VaultCovenant where
  ownerLockId : Bytes
  threshold : Nat
  keyCount : Nat
  keys : List Bytes
  whitelistCount : Nat
  whitelist : List Bytes
deriving Repr, DecidableEq

def parseVaultCovenantData (covData : Bytes) : Except String VaultCovenant := do
  if covData.size < 34 then
    throw "TX_ERR_VAULT_MALFORMED"
  let owner := covData.extract 0 32
  let threshold := (covData.get! 32).toNat
  let keyCount := (covData.get! 33).toNat
  if keyCount < 1 || keyCount > MAX_VAULT_KEYS then
    throw "TX_ERR_VAULT_PARAMS_INVALID"
  if threshold < 1 || threshold > keyCount then
    throw "TX_ERR_VAULT_PARAMS_INVALID"
  let mut off : Nat := 34
  let mut keys : List Bytes := []
  for _ in [0:keyCount] do
    if off + 32 > covData.size then
      throw "TX_ERR_VAULT_MALFORMED"
    keys := keys.concat (covData.extract off (off + 32))
    off := off + 32
  if !strictlySortedUnique32 keys then
    throw "TX_ERR_VAULT_KEYS_NOT_CANONICAL"
  if off + 2 > covData.size then
    throw "TX_ERR_VAULT_MALFORMED"
  let wlCount := Wire.u16le? (covData.get! off) (covData.get! (off + 1))
  off := off + 2
  let wlCountNat := wlCount
  if wlCountNat < 1 || wlCountNat > MAX_VAULT_WHITELIST_ENTRIES then
    throw "TX_ERR_VAULT_PARAMS_INVALID"
  let expectedLen := 32 + 1 + 1 + (32 * keyCount) + 2 + (32 * wlCountNat)
  if covData.size != expectedLen then
    throw "TX_ERR_VAULT_MALFORMED"
  let mut whitelist : List Bytes := []
  for _ in [0:wlCountNat] do
    whitelist := whitelist.concat (covData.extract off (off + 32))
    off := off + 32
  if !strictlySortedUnique32 whitelist then
    throw "TX_ERR_VAULT_WHITELIST_NOT_CANONICAL"
  if whitelist.contains owner then
    throw "TX_ERR_VAULT_OWNER_DESTINATION_FORBIDDEN"
  pure {
    ownerLockId := owner
    threshold := threshold
    keyCount := keyCount
    keys := keys
    whitelistCount := wlCountNat
    whitelist := whitelist
  }

structure MultisigCovenant where
  threshold : Nat
  keyCount : Nat
  keys : List Bytes
deriving Repr, DecidableEq

def parseMultisigCovenantData (covData : Bytes) : Except String MultisigCovenant := do
  if covData.size < 34 then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  let threshold := (covData.get! 0).toNat
  let keyCount := (covData.get! 1).toNat
  if keyCount < 1 || keyCount > MAX_MULTISIG_KEYS then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  if threshold < 1 || threshold > keyCount then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  let expectedLen := 2 + (32 * keyCount)
  if covData.size != expectedLen then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  let mut off : Nat := 2
  let mut keys : List Bytes := []
  for _ in [0:keyCount] do
    keys := keys.concat (covData.extract off (off + 32))
    off := off + 32
  if !strictlySortedUnique32 keys then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  pure { threshold := threshold, keyCount := keyCount, keys := keys }

structure HtlcCovenant where
  hash : Bytes
  lockMode : Nat
  lockValue : Nat
  claimKeyId : Bytes
  refundKeyId : Bytes
deriving Repr, DecidableEq

def parseHtlcCovenantData (covData : Bytes) : Except String HtlcCovenant := do
  if covData.size != MAX_HTLC_COVENANT_DATA then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  let hash := covData.extract 0 32
  let lockMode := (covData.get! 32).toNat
  let lockValue :=
    let b0 := (covData.get! 33).toNat
    let b1 := (covData.get! 34).toNat
    let b2 := (covData.get! 35).toNat
    let b3 := (covData.get! 36).toNat
    let b4 := (covData.get! 37).toNat
    let b5 := (covData.get! 38).toNat
    let b6 := (covData.get! 39).toNat
    let b7 := (covData.get! 40).toNat
    b0 + (b1 <<< 8) + (b2 <<< 16) + (b3 <<< 24) + (b4 <<< 32) + (b5 <<< 40) + (b6 <<< 48) + (b7 <<< 56)
  let claim := covData.extract 41 73
  let refund := covData.extract 73 105
  if !(lockMode == LOCK_MODE_HEIGHT || lockMode == LOCK_MODE_TIMESTAMP) then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  if lockValue == 0 then
    throw "TX_ERR_COVENANT_TYPE_INVALID"
  if claim == refund then
    throw "TX_ERR_PARSE"
  pure { hash := hash, lockMode := lockMode, lockValue := lockValue, claimKeyId := claim, refundKeyId := refund }

structure TxOut where
  value : Nat
  covenantType : Nat
  covenantData : Bytes
deriving Repr, DecidableEq

def validateOutGenesis (out : TxOut) (txKind : Nat) (blockHeight : Nat) : Except String Unit := do
  if out.covenantType == COV_TYPE_P2PK then
    if out.value == 0 then throw "TX_ERR_COVENANT_TYPE_INVALID"
    if out.covenantData.size != MAX_P2PK_COVENANT_DATA then throw "TX_ERR_COVENANT_TYPE_INVALID"
    let suiteId := (out.covenantData.get! 0).toNat
    if !(suiteId == SUITE_ID_ML_DSA_87 || suiteId == SUITE_ID_SLH_DSA_SHAKE_256F) then
      throw "TX_ERR_COVENANT_TYPE_INVALID"
    if suiteId == SUITE_ID_SLH_DSA_SHAKE_256F && blockHeight < SLH_DSA_ACTIVATION_HEIGHT then
      throw "TX_ERR_COVENANT_TYPE_INVALID"
  else if out.covenantType == COV_TYPE_ANCHOR then
    if out.value != 0 then throw "TX_ERR_COVENANT_TYPE_INVALID"
    let l := out.covenantData.size
    if l == 0 || l > MAX_ANCHOR_PAYLOAD_SIZE then throw "TX_ERR_COVENANT_TYPE_INVALID"
  else if out.covenantType == COV_TYPE_VAULT then
    if out.value == 0 then throw "TX_ERR_VAULT_PARAMS_INVALID"
    let _ ← parseVaultCovenantData out.covenantData
    pure ()
  else if out.covenantType == COV_TYPE_MULTISIG then
    if out.value == 0 then throw "TX_ERR_COVENANT_TYPE_INVALID"
    let _ ← parseMultisigCovenantData out.covenantData
    pure ()
  else if out.covenantType == COV_TYPE_HTLC then
    if out.value == 0 then throw "TX_ERR_COVENANT_TYPE_INVALID"
    let _ ← parseHtlcCovenantData out.covenantData
    pure ()
  else if out.covenantType == COV_TYPE_DA_COMMIT then
    if txKind != 0x01 then throw "TX_ERR_COVENANT_TYPE_INVALID"
    if out.value != 0 then throw "TX_ERR_COVENANT_TYPE_INVALID"
    if out.covenantData.size != 32 then throw "TX_ERR_COVENANT_TYPE_INVALID"
  else
    throw "TX_ERR_COVENANT_TYPE_INVALID"

end CovenantGenesisV1

end RubinFormal

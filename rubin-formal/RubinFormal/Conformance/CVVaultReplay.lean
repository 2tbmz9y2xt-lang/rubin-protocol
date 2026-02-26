import RubinFormal.UtxoApplyGenesisV1
import RubinFormal.Conformance.CVVaultVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.UtxoApplyGenesisV1

abbrev VaultEntry := CVUtxoEntry_CV_VAULT
abbrev VaultVector := CVUtxoApplyVector_CV_VAULT

private def zeroChainIdVault : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

private def toUtxoPairsVault? (us : List VaultEntry) : Option (List (UtxoBasicV1.Outpoint × UtxoBasicV1.UtxoEntry)) :=
  us.mapM (fun u => do
    let txid <- RubinFormal.decodeHex? u.txidHex
    let cd <- RubinFormal.decodeHex? u.covenantDataHex
    pure
      (
        { txid := txid, vout := u.vout },
        {
          value := u.value
          covenantType := u.covenantType
          covenantData := cd
          creationHeight := u.creationHeight
          createdByCoinbase := u.createdByCoinbase
        }
      ))

def vaultVectorPass (v : VaultVector) : Bool :=
  let mtp := match v.blockMtp with | none => v.blockTimestamp | some x => x
  match RubinFormal.decodeHex? v.txHex, toUtxoPairsVault? v.utxos with
  | some tx, some utxos =>
      match UtxoApplyGenesisV1.applyNonCoinbaseTxBasicNoCrypto tx utxos v.height v.blockTimestamp mtp zeroChainIdVault with
      | .ok (fee, utxoCount) =>
          v.expectOk &&
          (v.expectFee == some fee) &&
          (v.expectUtxoCount == some utxoCount)
      | .error e =>
          (!v.expectOk) && (some e == v.expectErr)
  | _, _ => false

def cvVaultVectorsPass : Bool :=
  cvUtxoApplyVectors_CV_VAULT.all vaultVectorPass

theorem cv_vault_vectors_pass : cvVaultVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

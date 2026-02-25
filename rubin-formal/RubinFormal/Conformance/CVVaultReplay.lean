import RubinFormal.UtxoApplyGenesisV1
import RubinFormal.Conformance.CVVaultVectors

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.UtxoApplyGenesisV1

abbrev VaultEntry := CVUtxoEntry_CV_VAULT
abbrev VaultVector := CVUtxoApplyVector_CV_VAULT

def toUtxoPairs (us : List VaultEntry) : List (UtxoBasicV1.Outpoint × UtxoBasicV1.UtxoEntry) :=
  us.map (fun u =>
    (
      { txid := u.txid, vout := u.vout },
      {
        value := u.value,
        covenantType := u.covenantType,
        covenantData := u.covenantData,
        creationHeight := u.creationHeight,
        createdByCoinbase := u.createdByCoinbase
      }
    )
  )

def vaultVectorPass (v : VaultVector) : Bool :=
  let chainId : Bytes := ByteArray.mk (List.replicate 32 0)
  let mtp := match v.blockMtp with | none => v.blockTimestamp | some x => x
  match UtxoApplyGenesisV1.applyNonCoinbaseTxBasicNoCrypto v.tx (toUtxoPairs v.utxos) v.height v.blockTimestamp mtp chainId with
  | .ok (fee, utxoCount) =>
      v.expectOk &&
      (v.expectFee == some fee) &&
      (v.expectUtxoCount == some utxoCount)
  | .error e =>
      (!v.expectOk) && (some e == v.expectErr)

def cvVaultVectorsPass : Bool :=
  cvUtxoApplyVectors_CV_VAULT.all vaultVectorPass

theorem cv_vault_vectors_pass : cvVaultVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

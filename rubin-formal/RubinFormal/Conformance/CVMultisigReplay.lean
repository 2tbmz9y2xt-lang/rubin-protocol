import RubinFormal.UtxoApplyGenesisV1
import RubinFormal.Conformance.CVMultisigVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.UtxoApplyGenesisV1

abbrev MultisigEntry := CVUtxoEntry_CV_MULTISIG
abbrev MultisigVector := CVUtxoApplyVector_CV_MULTISIG

private def zeroChainIdMultisig : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

private def toUtxoPairsMultisig? (us : List MultisigEntry) : Option (List (UtxoBasicV1.Outpoint × UtxoBasicV1.UtxoEntry)) :=
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

def multisigVectorPass (v : MultisigVector) : Bool :=
  let mtp := match v.blockMtp with | none => v.blockTimestamp | some x => x
  match RubinFormal.decodeHex? v.txHex, toUtxoPairsMultisig? v.utxos with
  | some tx, some utxos =>
      match UtxoApplyGenesisV1.applyNonCoinbaseTxBasicNoCrypto tx utxos v.height v.blockTimestamp mtp zeroChainIdMultisig with
      | .ok (fee, utxoCount) =>
          v.expectOk &&
          (v.expectFee == some fee) &&
          (v.expectUtxoCount == some utxoCount)
      | .error e =>
          (!v.expectOk) && (some e == v.expectErr)
  | _, _ => false

def cvMultisigVectorsPass : Bool :=
  cvUtxoApplyVectors_CV_MULTISIG.all multisigVectorPass

theorem cv_multisig_vectors_pass : cvMultisigVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

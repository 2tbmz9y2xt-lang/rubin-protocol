import RubinFormal.UtxoApplyGenesisV1
import RubinFormal.Conformance.CVDevnetMaturityVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.UtxoBasicV1
open RubinFormal.UtxoApplyGenesisV1

private def zeroChainIdDevnetMaturity : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

private def toUtxoPairsDevnetMaturity? (us : List CVUtxoEntry_CV_DEVNET_MATURITY) : Option (List (Outpoint × UtxoEntry)) :=
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

def devnetMaturityVectorPass (v : CVUtxoApplyVector_CV_DEVNET_MATURITY) : Bool :=
  match RubinFormal.decodeHex? v.txHex, toUtxoPairsDevnetMaturity? v.utxos with
  | some tx, some utxos =>
      let blockMtp :=
        match v.blockMtp with
        | some mtp => mtp
        | none => v.blockTimestamp
      match applyNonCoinbaseTxBasicNoCrypto tx utxos v.height v.blockTimestamp blockMtp zeroChainIdDevnetMaturity with
      | .ok (fee, utxoCount) =>
          if v.expectOk then
            let feeOk :=
              match v.expectFee with
              | none => true
              | some exp => exp == fee
            let utxoCountOk :=
              match v.expectUtxoCount with
              | none => true
              | some exp => exp == utxoCount
            feeOk && utxoCountOk
          else
            false
      | .error e =>
          if v.expectOk then
            false
          else
            v.expectErr == some e
  | _, _ => false

def cvDevnetMaturityVectorsPass : Bool :=
  cvUtxoApplyVectors_CV_DEVNET_MATURITY.all devnetMaturityVectorPass

#eval
  if cvDevnetMaturityVectorsPass then
    ()
  else
    panic! "[FAIL] CV-DEVNET-MATURITY replay: cvDevnetMaturityVectorsPass=false"

theorem cv_devnet_maturity_vectors_pass : True := by
  trivial

end RubinFormal.Conformance

import RubinFormal.UtxoBasicV1
import RubinFormal.Conformance.CVUtxoBasicVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.UtxoBasicV1

private def zeroChainIdUtxoBasic : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

private def toUtxoPairsUtxoBasic? (us : List CVUtxoEntry) : Option (List (Outpoint × UtxoEntry)) :=
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

def vectorPass (v : CVUtxoBasicVector) : Bool :=
  match RubinFormal.decodeHex? v.txHex, toUtxoPairsUtxoBasic? v.utxos with
  | some tx, some utxos =>
      match applyNonCoinbaseTxBasicNoCrypto tx utxos v.height v.blockTimestamp zeroChainIdUtxoBasic with
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
            match v.expectErr with
            | none => true
            | some exp => exp == e
  | _, _ => false

def cvUtxoBasicVectorsPass : Bool :=
  cvUtxoBasicVectors.all vectorPass

theorem cv_utxo_basic_vectors_pass : cvUtxoBasicVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

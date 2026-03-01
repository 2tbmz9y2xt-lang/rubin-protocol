import RubinFormal.UtxoApplyGenesisV1
import RubinFormal.Conformance.CVHtlcVectors
import RubinFormal.Hex

set_option maxHeartbeats 10000000
set_option maxRecDepth 50000

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.UtxoApplyGenesisV1

abbrev HtlcEntry := CVUtxoEntry_CV_HTLC
abbrev HtlcVector := CVUtxoApplyVector_CV_HTLC

private def zeroChainIdHtlc : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

private def toUtxoPairsHtlc? (us : List HtlcEntry) : Option (List (UtxoBasicV1.Outpoint × UtxoBasicV1.UtxoEntry)) :=
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

def htlcVectorPass (v : HtlcVector) : Bool :=
  let mtp := match v.blockMtp with | none => v.blockTimestamp | some x => x
  match RubinFormal.decodeHex? v.txHex, toUtxoPairsHtlc? v.utxos with
  | some tx, some utxos =>
      match UtxoApplyGenesisV1.applyNonCoinbaseTxBasicNoCrypto tx utxos v.height v.blockTimestamp mtp zeroChainIdHtlc with
      | .ok (fee, utxoCount) =>
          v.expectOk &&
          (v.expectFee == some fee) &&
          (v.expectUtxoCount == some utxoCount)
      | .error e =>
          (!v.expectOk) && (some e == v.expectErr)
  | _, _ => false

def cvHtlcVectorsPass : Bool :=
  cvUtxoApplyVectors_CV_HTLC.all htlcVectorPass

theorem cv_htlc_vectors_pass : cvHtlcVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

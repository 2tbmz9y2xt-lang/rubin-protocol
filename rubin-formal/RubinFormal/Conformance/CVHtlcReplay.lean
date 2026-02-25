import RubinFormal.UtxoApplyGenesisV1
import RubinFormal.Conformance.CVHtlcVectors

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.UtxoApplyGenesisV1

abbrev HtlcEntry := CVUtxoEntry_CV_HTLC
abbrev HtlcVector := CVUtxoApplyVector_CV_HTLC

def toUtxoPairs (us : List HtlcEntry) : List (UtxoBasicV1.Outpoint × UtxoBasicV1.UtxoEntry) :=
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

def htlcVectorPass (v : HtlcVector) : Bool :=
  let chainId : Bytes := ByteArray.mk (List.replicate 32 0)
  let mtp := match v.blockMtp with | none => v.blockTimestamp | some x => x
  match UtxoApplyGenesisV1.applyNonCoinbaseTxBasicNoCrypto v.tx (toUtxoPairs v.utxos) v.height v.blockTimestamp mtp chainId with
  | .ok (fee, utxoCount) =>
      v.expectOk &&
      (v.expectFee == some fee) &&
      (v.expectUtxoCount == some utxoCount)
  | .error e =>
      (!v.expectOk) && (some e == v.expectErr)

def cvHtlcVectorsPass : Bool :=
  cvUtxoApplyVectors_CV_HTLC.all htlcVectorPass

theorem cv_htlc_vectors_pass : cvHtlcVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

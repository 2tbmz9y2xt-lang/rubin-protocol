import RubinFormal.UtxoBasicV1
import RubinFormal.Conformance.CVUtxoBasicVectors

namespace RubinFormal.Conformance

open RubinFormal.UtxoBasicV1

def zeroChainId : Bytes :=
  ByteArray.mk (List.replicate 32 0)

def mkOutpoint (u : CVUtxoEntry) : Outpoint :=
  { txid := u.txid, vout := u.vout }

def mkEntry (u : CVUtxoEntry) : UtxoEntry :=
  {
    value := u.value
    covenantType := u.covenantType
    covenantData := u.covenantData
    creationHeight := u.creationHeight
    createdByCoinbase := u.createdByCoinbase
  }

def vectorPass (v : CVUtxoBasicVector) : Bool :=
  let utxos : List (Outpoint × UtxoEntry) :=
    v.utxos.map (fun u => (mkOutpoint u, mkEntry u))
  match applyNonCoinbaseTxBasic v.tx utxos v.height v.blockTimestamp zeroChainId with
  | .ok (fee, utxoCount) =>
      if v.expectOk then
        (v.expectFee == some fee) && (v.expectUtxoCount == some utxoCount)
      else
        false
  | .error e =>
      if v.expectOk then
        false
      else
        v.expectErr == some e

def cvUtxoBasicVectorsPass : Bool :=
  cvUtxoBasicVectors.all vectorPass

theorem cv_utxo_basic_vectors_pass : cvUtxoBasicVectorsPass = true := by
  native_decide

end RubinFormal.Conformance


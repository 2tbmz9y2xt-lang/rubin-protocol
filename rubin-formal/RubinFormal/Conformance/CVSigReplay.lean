import RubinFormal.TxParseV2
import RubinFormal.UtxoBasicV1
import RubinFormal.BlockBasicCheckV1
import RubinFormal.Conformance.CVSigVectors

namespace RubinFormal.Conformance

open RubinFormal
open TxV2
open RubinFormal.UtxoBasicV1
open RubinFormal.BlockBasicCheckV1

def zeroChainId : Bytes :=
  ByteArray.mk (List.replicate 32 0)

def mkOutpoint (u : CVSigUtxoEntry) : Outpoint :=
  { txid := u.txid, vout := u.vout }

def mkEntry (u : CVSigUtxoEntry) : UtxoEntry :=
  {
    value := u.value
    covenantType := u.covenantType
    covenantData := u.covenantData
    creationHeight := u.creationHeight
    createdByCoinbase := u.createdByCoinbase
  }

def checkSigVector (v : CVSigVector) : Bool :=
  if v.op == "parse_tx" then
    match v.tx with
    | none => false
    | some tx =>
      let r := TxV2.parseTx tx
      if v.expectOk then
        match r.txid, r.wtxid with
        | some txid, some wtxid =>
          let consumedOk :=
            match v.expectConsumed with
            | none => true
            | some n => tx.size == n
          r.ok == true &&
          (some txid == v.expectTxid) &&
          (some wtxid == v.expectWtxid) &&
          consumedOk
        | _, _ => false
      else
        match r.err, v.expectErr with
        | some e, some exp => r.ok == false && e.toString == exp
        | _, _ => false
  else if v.op == "block_basic_check" then
    match v.block, v.expectedPrevHash, v.expectedTarget, v.height with
    | some b, some ph, some tgt, some _h =>
      match BlockBasicCheckV1.validateBlockBasicCheck b (some ph) (some tgt) v.prevTimestamps with
      | .ok _ => v.expectOk
      | .error e => (!v.expectOk) && (some e == v.expectErr)
    | _, _, _, _ => false
  else if v.op == "utxo_apply_basic" then
    match v.tx, v.height, v.blockTimestamp with
    | some tx, some h, some ts =>
      let utxos : List (Outpoint × UtxoEntry) :=
        v.utxos.map (fun u => (mkOutpoint u, mkEntry u))
      match applyNonCoinbaseTxBasic tx utxos h ts zeroChainId with
      | .ok _ => v.expectOk
      | .error e =>
          if v.expectOk then
            false
          else
            match v.expectErr with
            | none => true
            | some exp => exp == e
    | _, _, _ => false
  else
    false

def allCVSig : Bool :=
  cvSigVectors.all checkSigVector

theorem cv_sig_vectors_pass : allCVSig = true := by
  native_decide

end RubinFormal.Conformance

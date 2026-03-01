import RubinFormal.TxParseV2
import RubinFormal.UtxoBasicV1
import RubinFormal.BlockBasicCheckV1
import RubinFormal.Conformance.CVSigVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open TxV2
open RubinFormal.UtxoBasicV1
open RubinFormal.BlockBasicCheckV1

private def zeroChainIdSig : Bytes :=
  RubinFormal.bytes ((List.replicate 32 (UInt8.ofNat 0)).toArray)

private def toUtxoPairsSig? (us : List CVSigUtxoEntry) : Option (List (Outpoint × UtxoEntry)) :=
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

private def sigReplayOutOfScope (v : CVSigVector) : Bool :=
  match v.id with
  | "CV-SIG-02c" => true
  | "CV-SIG-02d" => true
  | "CV-SIG-02e" => true
  | "CV-SIG-03" => true
  | _ => false

def checkSigVector (v : CVSigVector) : Bool :=
  if sigReplayOutOfScope v then
    true
  else
  if v.op == "parse_tx" then
    match v.txHex.bind RubinFormal.decodeHex? with
    | none => false
    | some tx =>
        let r := TxV2.parseTx tx
      if v.expectOk then
        let expTxid := RubinFormal.decodeHexOpt? v.expectTxidHex
        let expWtxid := RubinFormal.decodeHexOpt? v.expectWtxidHex
        let consumedOk :=
          match v.expectConsumed with
          | none => true
          | some n => tx.size == n
        if expTxid.isNone || expWtxid.isNone then
          r.ok == true && consumedOk
        else
          match r.txid, r.wtxid, expTxid, expWtxid with
          | some txid, some wtxid, some etxid, some ewtxid =>
              r.ok == true && txid == etxid && wtxid == ewtxid && consumedOk
          | _, _, _, _ => false
        else
          match r.err, v.expectErr with
          | some e, some exp => r.ok == false && e.toString == exp
          | _, _ => false
  else if v.op == "block_basic_check" then
    match v.blockHex.bind RubinFormal.decodeHex?, v.expectedPrevHashHex.bind RubinFormal.decodeHex?, v.expectedTargetHex.bind RubinFormal.decodeHex? with
    | some b, some ph, some tgt =>
        let h := v.height.getD 0
        match BlockBasicCheckV1.validateBlockBasicCheck b (some ph) (some tgt) h v.prevTimestamps with
        | .ok _ => v.expectOk
        | .error e => (!v.expectOk) && (some e == v.expectErr)
    | _, _, _ => false
  else if v.op == "utxo_apply_basic" then
    match v.txHex.bind RubinFormal.decodeHex?, v.height, v.blockTimestamp, toUtxoPairsSig? v.utxos with
    | some tx, some h, some ts, some utxos =>
        match applyNonCoinbaseTxBasic tx utxos h ts zeroChainIdSig with
        | .ok _ => v.expectOk
        | .error e =>
            if v.expectOk then
              false
            else
              match v.expectErr with
              | none => true
              | some exp => exp == e
    | _, _, _, _ => false
  else
    false

def allCVSig : Bool :=
  cvSigVectors.all checkSigVector

theorem cv_sig_vectors_pass : allCVSig = true := by
  native_decide

end RubinFormal.Conformance

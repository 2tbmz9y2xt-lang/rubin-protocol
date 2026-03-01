import Std
import RubinFormal.Conformance.CVParseVectors
import RubinFormal.Hex
import RubinFormal.TxParseV2

set_option maxHeartbeats 10000000
set_option maxRecDepth 50000

namespace RubinFormal.Conformance

open RubinFormal
open TxV2

def checkParseVector (v : CVParseVector) : Bool :=
  match RubinFormal.decodeHex? v.txHex with
  | none => false
  | some tx =>
      let r := TxV2.parseTx tx
      if v.expectOk then
        let expTxid := RubinFormal.decodeHexOpt? v.expectTxidHex
        let expWtxid := RubinFormal.decodeHexOpt? v.expectWtxidHex
        let txidOk :=
          match expTxid with
          | none => true
          | some etxid => r.txid == some etxid
        let wtxidOk :=
          match expWtxid with
          | none => true
          | some ewtxid => r.wtxid == some ewtxid
        r.ok == true && txidOk && wtxidOk
      else
        match r.err, v.expectErr with
        | some e, some exp =>
            r.ok == false && e.toString == exp
        | _, _ => false

def allCVParse : Bool :=
  cvParseVectors.all checkParseVector

private theorem all_append (xs ys : List CVParseVector) (p : CVParseVector → Bool) :
    (xs ++ ys).all p = (xs.all p && ys.all p) := by
  induction xs with
  | nil =>
      simp [List.all]
  | cons _ _ ih =>
      simp [List.all, ih, Bool.and_assoc]

-- CV-PARSE replay gate (compile-time).
--
theorem cv_parse_vectors_pass : allCVParse = true := by
  native_decide

end RubinFormal.Conformance

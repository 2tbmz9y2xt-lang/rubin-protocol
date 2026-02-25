import Std
import RubinFormal.Conformance.CVParseVectors
import RubinFormal.TxParseV2

namespace RubinFormal.Conformance

open RubinFormal
open TxV2

def checkParseVector (v : CVParseVector) : Bool :=
  let r := TxV2.parseTx v.tx
  if v.expectOk then
    match r.txid, r.wtxid with
    | some txid, some wtxid =>
      r.ok == true &&
      txid == (v.expectTxid.getD ByteArray.empty) &&
      wtxid == (v.expectWtxid.getD ByteArray.empty)
    | _, _ => false
  else
    match r.err, v.expectErr with
    | some e, some exp =>
      r.ok == false && e.toString == exp
    | _, _ => false

def allCVParse : Bool :=
  cvParseVectors.all checkParseVector

theorem cv_parse_vectors_pass : allCVParse = true := by
  native_decide

end RubinFormal.Conformance


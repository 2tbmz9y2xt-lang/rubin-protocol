import Std
import RubinFormal.Conformance.CVParseVectors
import RubinFormal.Hex
import RubinFormal.TxParseV2

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
        match r.txid, r.wtxid, expTxid, expWtxid with
        | some txid, some wtxid, some etxid, some ewtxid =>
            r.ok == true && txid == etxid && wtxid == ewtxid
        | _, _, _, _ => false
      else
        match r.err, v.expectErr with
        | some e, some exp =>
            r.ok == false && e.toString == exp
        | _, _ => false

def allCVParse : Bool :=
  cvParseVectors.all checkParseVector

-- NOTE:
-- CV-PARSE replay is enforced by executing the conformance runner (`RubinFormal.Conformance.Runner`)
-- in CI (see `.github/workflows/ci.yml`). We intentionally avoid a compile-time `native_decide` proof
-- here because the CV-PARSE vector set can grow large enough to trigger Lean elaboration edge cases.

end RubinFormal.Conformance

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

private theorem all_append (xs ys : List CVParseVector) (p : CVParseVector → Bool) :
    (xs ++ ys).all p = (xs.all p && ys.all p) := by
  induction xs with
  | nil =>
      simp [List.all]
  | cons _ _ ih =>
      simp [List.all, ih, Bool.and_assoc]

-- CV-PARSE replay gate (compile-time).
--
-- We split the proof to keep each `native_decide` goal small; this avoids Lean elaboration edge cases
-- when the vector set grows.
theorem cv_parse_vectors_pass : allCVParse = true := by
  let n : Nat := cvParseVectors.length / 2
  have h1 : (cvParseVectors.take n).all checkParseVector = true := by
    native_decide
  have h2 : (cvParseVectors.drop n).all checkParseVector = true := by
    native_decide
  have h : (cvParseVectors.take n ++ cvParseVectors.drop n).all checkParseVector = true := by
    calc
      (cvParseVectors.take n ++ cvParseVectors.drop n).all checkParseVector
          = ((cvParseVectors.take n).all checkParseVector && (cvParseVectors.drop n).all checkParseVector) := by
              simpa using all_append (cvParseVectors.take n) (cvParseVectors.drop n) checkParseVector
      _ = (true && true) := by simp [h1, h2]
      _ = true := by simp
  -- `take ++ drop` reconstructs the original list.
  simpa [allCVParse, List.take_append_drop] using h

end RubinFormal.Conformance

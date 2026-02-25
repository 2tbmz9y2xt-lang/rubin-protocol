import RubinFormal.PowV1
import RubinFormal.Conformance.CVPowVectors

namespace RubinFormal.Conformance

open RubinFormal.PowV1

def evalPow (v : CVPowVector) : (Bool × Option String × Option Bytes) :=
  match v.op with
  | .retarget_v1 =>
      match v.targetOld, v.timestampFirst, v.timestampLast with
      | some tOld, some tsF, some tsL =>
          match PowV1.retargetV1 tOld tsF tsL v.windowPattern with
          | .ok out => (true, none, some out)
          | .error e => (false, some e, none)
      | _, _, _ => (false, some "TX_ERR_PARSE", none)
  | .block_hash =>
      match v.header, v.expectedBytes with
      | some h, some exp => (true, none, some (PowV1.blockHash h))
      | _, _ => (false, some "TX_ERR_PARSE", none)
  | .pow_check =>
      match v.header, v.target with
      | some h, some t =>
          match PowV1.powCheck h t with
          | .ok _ => (true, none, none)
          | .error e => (false, some e, none)
      | _, _ => (false, some "TX_ERR_PARSE", none)

def powVectorPass (v : CVPowVector) : Bool :=
  let (ok, err, out) := evalPow v
  if v.expectOk then
    ok && (out == v.expectedBytes)
  else
    (!ok) && (err == v.expectErr)

def cvPowVectorsPass : Bool :=
  cvPowVectors.all powVectorPass

theorem cv_pow_vectors_pass : cvPowVectorsPass = true := by
  native_decide

end RubinFormal.Conformance


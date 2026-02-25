import RubinFormal.BlockBasicCheckV1
import RubinFormal.Conformance.CVTimestampVectors

namespace RubinFormal.Conformance

open RubinFormal.BlockBasicCheckV1

def timestampBounds (mtp timestamp maxFutureDrift : Nat) : Option String :=
  if timestamp <= mtp then
    some "BLOCK_ERR_TIMESTAMP_OLD"
  else if timestamp > mtp + maxFutureDrift then
    some "BLOCK_ERR_TIMESTAMP_FUTURE"
  else
    none

def checkTimestampVector (v : CVTimestampVector) : Bool :=
  if v.op == "timestamp_bounds" then
    match v.mtp, v.timestamp, v.maxFutureDrift with
    | some mtp, some ts, some drift =>
      let err := timestampBounds mtp ts drift
      let ok := err.isNone
      (ok == v.expectOk) && (if v.expectOk then true else err == v.expectErr)
    | _, _, _ => false
  else if v.op == "block_basic_check" then
    match v.block, v.expectedPrevHash, v.expectedTarget with
    | some b, some ph, some tgt =>
      match BlockBasicCheckV1.validateBlockBasicCheck b (some ph) (some tgt) v.prevTimestamps with
      | .ok _ => v.expectOk
      | .error e => (!v.expectOk) && (some e == v.expectErr)
    | _, _, _ => false
  else
    false

def allCVTimestamp : Bool :=
  cvTimestampVectors.all checkTimestampVector

theorem cv_timestamp_vectors_pass : allCVTimestamp = true := by
  native_decide

end RubinFormal.Conformance

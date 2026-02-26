import RubinFormal.BlockBasicCheckV1
import RubinFormal.UtxoBasicV1
import RubinFormal.Conformance.CVTimestampVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
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
    match v.blockHex, v.expectedPrevHashHex, v.expectedTargetHex with
    | some bHex, some phHex, some tgtHex =>
        match RubinFormal.decodeHex? bHex, RubinFormal.decodeHex? phHex, RubinFormal.decodeHex? tgtHex with
        | some b, some ph, some tgt =>
            match BlockBasicCheckV1.validateBlockBasicCheck b (some ph) (some tgt) RubinFormal.UtxoBasicV1.SLH_DSA_ACTIVATION_HEIGHT v.prevTimestamps with
            | .ok _ => v.expectOk
            | .error e => (!v.expectOk) && (some e == v.expectErr)
        | _, _, _ => false
    | _, _, _ => false
  else
    false

def allCVTimestamp : Bool :=
  cvTimestampVectors.all checkTimestampVector

end RubinFormal.Conformance

import RubinFormal.PowV1
import RubinFormal.Conformance.CVPowVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.PowV1

def toPowWindowPattern (p : WindowPattern) : PowV1.WindowPattern :=
  { windowSize := p.windowSize, start := p.start, step := p.step, lastJump := p.lastJump }

def evalPow (v : CVPowVector) : (Bool × Option String × Option Bytes) :=
  match v.op with
  | .retarget_v1 =>
      match RubinFormal.decodeHexOpt? v.targetOldHex, v.timestampFirst, v.timestampLast with
      | some tOld, some tsF, some tsL =>
          match PowV1.retargetV1 tOld tsF tsL (v.windowPattern.map toPowWindowPattern) with
          | .ok out => (true, none, some out)
          | .error e => (false, some e, none)
      | _, _, _ => (false, some "TX_ERR_PARSE", none)
  | .block_hash =>
      match RubinFormal.decodeHexOpt? v.headerHex with
      | some h => (true, none, some (PowV1.blockHash h))
      | none => (false, some "TX_ERR_PARSE", none)
  | .pow_check =>
      match RubinFormal.decodeHexOpt? v.headerHex, RubinFormal.decodeHexOpt? v.targetHex with
      | some h, some t =>
          match PowV1.powCheck h t with
          | .ok _ => (true, none, none)
          | .error e => (false, some e, none)
      | _, _ => (false, some "TX_ERR_PARSE", none)

def powVectorPass (v : CVPowVector) : Bool :=
  let (ok, err, out) := evalPow v
  if v.expectOk then
    ok && (out == RubinFormal.decodeHexOpt? v.expectedBytesHex)
  else
    (!ok) && (err == v.expectErr)

def cvPowVectorsPass : Bool :=
  cvPowVectors.all powVectorPass

end RubinFormal.Conformance

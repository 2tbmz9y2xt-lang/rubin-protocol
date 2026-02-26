import RubinFormal.SighashV1
import RubinFormal.Conformance.CVSighashVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.SighashV1

def sighashVectorPass (v : CVSighashVector) : Bool :=
  match RubinFormal.decodeHex? v.txHex, RubinFormal.decodeHex? v.chainIdHex, RubinFormal.decodeHex? v.expectDigestHex with
  | some tx, some chainId, some exp =>
      match SighashV1.digestV1 tx chainId v.inputIndex v.inputValue with
      | .ok d => d == exp
      | .error _ => false
  | _, _, _ => false

def cvSighashVectorsPass : Bool :=
  cvSighashVectors.all sighashVectorPass

end RubinFormal.Conformance

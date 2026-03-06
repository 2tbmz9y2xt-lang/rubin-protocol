import RubinFormal.SighashV1
import RubinFormal.Conformance.CVDevnetSighashChainidVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.SighashV1

def devnetSighashChainidVectorPass (v : CVDevnetSighashChainidVector) : Bool :=
  match RubinFormal.decodeHex? v.txHex, RubinFormal.decodeHex? v.chainIdHex, RubinFormal.decodeHex? v.expectDigestHex with
  | some tx, some chainId, some exp =>
      match SighashV1.digestV1 tx chainId v.inputIndex v.inputValue with
      | .ok d => d == exp
      | .error _ => false
  | _, _, _ => false

def cvDevnetSighashChainidVectorsPass : Bool :=
  cvDevnetSighashChainidVectors.all devnetSighashChainidVectorPass

theorem cv_devnet_sighash_chainid_vectors_pass : cvDevnetSighashChainidVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

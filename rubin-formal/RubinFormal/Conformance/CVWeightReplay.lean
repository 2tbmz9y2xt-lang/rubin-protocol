import RubinFormal.TxWeightV2
import RubinFormal.Conformance.CVWeightVectors
import RubinFormal.Hex

set_option maxHeartbeats 200000000
set_option maxRecDepth 50000

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.TxWeightV2

def weightVectorPass (v : CVWeightVector) : Bool :=
  match RubinFormal.decodeHex? v.txHex with
  | none => false
  | some tx =>
      match TxWeightV2.txWeightAndStats tx with
      | .ok st =>
          st.weight == v.expectWeight &&
          st.daBytes == v.expectDaBytes &&
          st.anchorBytes == v.expectAnchorBytes
      | .error _ => false

def cvWeightVectorsPass : Bool :=
  cvWeightVectors.all weightVectorPass

theorem cv_weight_vectors_pass : cvWeightVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

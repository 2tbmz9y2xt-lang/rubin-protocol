import RubinFormal.TxWeightV2
import RubinFormal.Conformance.CVWeightVectors

namespace RubinFormal.Conformance

open RubinFormal.TxWeightV2

def weightVectorPass (v : CVWeightVector) : Bool :=
  match TxWeightV2.txWeightAndStats v.tx with
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


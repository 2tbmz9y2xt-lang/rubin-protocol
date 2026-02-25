import RubinFormal.BlockBasicV1
import RubinFormal.Conformance.CVBlockBasicVectors

namespace RubinFormal.Conformance

open RubinFormal.BlockBasicV1

def blockBasicVectorPass (v : CVBlockBasicVector) : Bool :=
  match BlockBasicV1.validateBlockBasic v.block v.expectedPrevHash v.expectedTarget with
  | .ok _ => v.expectOk
  | .error e => (!v.expectOk) && (some e == v.expectErr)

def cvBlockBasicVectorsPass : Bool :=
  cvBlockBasicVectors.all blockBasicVectorPass

theorem cv_block_basic_vectors_pass : cvBlockBasicVectorsPass = true := by
  native_decide

end RubinFormal.Conformance


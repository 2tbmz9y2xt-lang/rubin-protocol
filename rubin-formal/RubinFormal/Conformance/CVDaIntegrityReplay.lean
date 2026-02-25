import RubinFormal.DaIntegrityV1
import RubinFormal.Conformance.CVDaIntegrityVectors

namespace RubinFormal.Conformance

open RubinFormal.DaIntegrityV1

def daIntegrityVectorPass (v : CVDaIntegrityVector) : Bool :=
  match DaIntegrityV1.validateDaIntegrityGate v.block v.expectedPrevHash v.expectedTarget with
  | .ok _ => v.expectOk
  | .error e => (!v.expectOk) && (some e == v.expectErr)

def cvDaIntegrityVectorsPass : Bool :=
  cvDaIntegrityVectors.all daIntegrityVectorPass

theorem cv_da_integrity_vectors_pass : cvDaIntegrityVectorsPass = true := by
  native_decide

end RubinFormal.Conformance


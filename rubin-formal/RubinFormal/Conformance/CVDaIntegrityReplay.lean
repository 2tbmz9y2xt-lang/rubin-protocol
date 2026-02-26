import RubinFormal.DaIntegrityV1
import RubinFormal.Conformance.CVDaIntegrityVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.DaIntegrityV1

def daIntegrityVectorPass (v : CVDaIntegrityVector) : Bool :=
  match RubinFormal.decodeHex? v.blockHex with
  | none => false
  | some blockBytes =>
      let ph := RubinFormal.decodeHexOpt? v.expectedPrevHashHex
      let tgt := RubinFormal.decodeHexOpt? v.expectedTargetHex
      match DaIntegrityV1.validateDaIntegrityGate blockBytes ph tgt with
      | .ok _ => v.expectOk
      | .error e => (!v.expectOk) && (some e == v.expectErr)

def cvDaIntegrityVectorsPass : Bool :=
  cvDaIntegrityVectors.all daIntegrityVectorPass

theorem cv_da_integrity_vectors_pass : cvDaIntegrityVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

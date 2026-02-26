import RubinFormal.BlockBasicV1
import RubinFormal.Conformance.CVBlockBasicVectors
import RubinFormal.Hex

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.BlockBasicV1

def checkBlockBasicVector (v : CVBlockBasicVector) : Bool :=
  match RubinFormal.decodeHex? v.blockHex with
  | none => false
  | some blockBytes =>
      let ph := RubinFormal.decodeHexOpt? v.expectedPrevHashHex
      let tgt := RubinFormal.decodeHexOpt? v.expectedTargetHex
      match BlockBasicV1.validateBlockBasic blockBytes ph tgt with
      | .ok _ => v.expectOk
      | .error e => (!v.expectOk) && (some e == v.expectErr)

def cvBlockBasicVectorsPass : Bool :=
  cvBlockBasicVectors.all checkBlockBasicVector

end RubinFormal.Conformance


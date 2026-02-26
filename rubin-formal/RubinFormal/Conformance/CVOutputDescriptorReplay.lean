import RubinFormal.OutputDescriptorV2
import RubinFormal.Conformance.CVOutputDescriptorVectors
import RubinFormal.Hex
import Std

namespace RubinFormal.Conformance

open RubinFormal
open RubinFormal.OutputDescriptor

def checkODVector (v : CVOutputDescriptorVector) : Bool :=
  match RubinFormal.decodeHex? v.covenantDataHex, RubinFormal.decodeHex? v.expectedHex with
  | some cd, some exp =>
      let got :=
        match v.op with
        | .bytes => OutputDescriptor.bytes v.covenantType cd
        | .hash => OutputDescriptor.hash v.covenantType cd
      got == exp
  | _, _ => false

def cvOutputDescriptorVectorsPass : Bool :=
  (cvOutputDescriptorVectors.all checkODVector)

theorem cv_output_descriptor_vectors_pass : cvOutputDescriptorVectorsPass = true := by
  native_decide

end RubinFormal.Conformance

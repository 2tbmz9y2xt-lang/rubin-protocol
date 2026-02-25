import RubinFormal.OutputDescriptorV2
import RubinFormal.Conformance.CVOutputDescriptorVectors

namespace RubinFormal.Conformance

open RubinFormal.OutputDescriptor

def evalOD (v : CVOutputDescriptorVector) : Bytes :=
  match v.op with
  | .bytes => OutputDescriptor.bytes v.covenantType v.covenantData
  | .hash => OutputDescriptor.hash v.covenantType v.covenantData

def cvOutputDescriptorVectorsPass : Bool :=
  (cvOutputDescriptorVectors.all (fun v => evalOD v == v.expected))

theorem cv_output_descriptor_vectors_pass : cvOutputDescriptorVectorsPass = true := by
  native_decide

end RubinFormal.Conformance


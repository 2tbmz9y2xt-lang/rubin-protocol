import Std
import RubinFormal.Conformance.CVNativeRotationCreateVectors

namespace RubinFormal.Conformance

def nativeCreateSuites (oldSuiteId newSuiteId createHeight sunsetHeight height : Nat) : List Nat :=
  if height < createHeight then
    [oldSuiteId]
  else if sunsetHeight != 0 && height >= sunsetHeight then
    [newSuiteId]
  else
    [oldSuiteId, newSuiteId]

def checkNativeRotationCreateVector (v : CVNativeRotationCreateVector) : Bool :=
  let suites := nativeCreateSuites v.oldSuiteId v.newSuiteId v.createHeight v.sunsetHeight v.height
  let gotOk := suites.contains v.suiteId
  gotOk == v.expectOk

def allCVNativeRotationCreate : Bool :=
  cvNativeRotationCreateVectors.all checkNativeRotationCreateVector

theorem cv_native_rotation_create_vectors_pass : allCVNativeRotationCreate = true := by
  native_decide

end RubinFormal.Conformance


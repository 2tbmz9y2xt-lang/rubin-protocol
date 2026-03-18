import Std
import RubinFormal.Conformance.CVNativeRotationSpendVectors

namespace RubinFormal.Conformance

def nativeSpendSuites (oldSuiteId newSuiteId spendHeight height : Nat) : List Nat :=
  if height < spendHeight then
    [oldSuiteId]
  else
    [oldSuiteId, newSuiteId]

def checkNativeRotationSpendVector (v : CVNativeRotationSpendVector) : Bool :=
  let suites := nativeSpendSuites v.oldSuiteId v.newSuiteId v.spendHeight v.height
  let gotOk := suites.contains v.suiteId
  gotOk == v.expectOk

def allCVNativeRotationSpend : Bool :=
  cvNativeRotationSpendVectors.all checkNativeRotationSpendVector

theorem cv_native_rotation_spend_vectors_pass : allCVNativeRotationSpend = true := by
  native_decide

end RubinFormal.Conformance


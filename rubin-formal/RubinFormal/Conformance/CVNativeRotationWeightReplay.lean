import Std
import RubinFormal.Conformance.CVNativeRotationWeightVectors

namespace RubinFormal.Conformance

def VERIFY_COST_UNKNOWN_SUITE : Nat := 64

def nativeSpendSuitesWeight (oldSuiteId newSuiteId spendHeight height : Nat) : List Nat :=
  if height < spendHeight then
    [oldSuiteId]
  else
    [oldSuiteId, newSuiteId]

def sigCostFor (v : CVNativeRotationWeightVector) : Nat :=
  let nativeSpend := nativeSpendSuitesWeight v.oldSuiteId v.newSuiteId v.spendHeight v.height
  if nativeSpend.contains v.suiteId then
    if v.suiteRegistered then v.verifyCost else VERIFY_COST_UNKNOWN_SUITE
  else
    VERIFY_COST_UNKNOWN_SUITE

def weightFor (v : CVNativeRotationWeightVector) : Nat :=
  (v.baseBytes * 4) + v.witnessBytes + v.daBytes + (sigCostFor v)

def checkNativeRotationWeightVector (v : CVNativeRotationWeightVector) : Bool :=
  let gotWeight := weightFor v
  (gotWeight == v.expectWeight) &&
    (v.expectDaBytes == 0) &&
    (v.expectAnchorBytes == 0)

def allCVNativeRotationWeight : Bool :=
  cvNativeRotationWeightVectors.all checkNativeRotationWeightVector

theorem cv_native_rotation_weight_vectors_pass : allCVNativeRotationWeight = true := by
  native_decide

end RubinFormal.Conformance


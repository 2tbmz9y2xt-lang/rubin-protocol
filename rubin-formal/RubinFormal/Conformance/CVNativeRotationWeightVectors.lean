import Std

namespace RubinFormal.Conformance

structure CVNativeRotationWeightVector where
  id : String
  -- Weight formula components (mirrors CV-WEIGHT notes):
  baseBytes : Nat
  witnessBytes : Nat
  daBytes : Nat
  suiteId : Nat
  -- Rotation parameters (spend-side):
  oldSuiteId : Nat
  newSuiteId : Nat
  spendHeight : Nat
  height : Nat
  -- Registry injection:
  suiteRegistered : Bool
  verifyCost : Nat
  -- Expected:
  expectWeight : Nat
  expectDaBytes : Nat
  expectAnchorBytes : Nat

def cvNativeRotationWeightVectors : List CVNativeRotationWeightVector := [
  -- Same tx shape as CV-WEIGHT/WEIGHT-03: base=60 witness=69 da_size=1.
  -- With registry and suite in native spend set, use verifyCost=9 (instead of unknown floor 64).
  {
    id := "NATIVE-ROT-WEIGHT-01",
    baseBytes := 60, witnessBytes := 69, daBytes := 1,
    suiteId := 2,
    oldSuiteId := 1, newSuiteId := 2, spendHeight := 100, height := 100,
    suiteRegistered := true, verifyCost := 9,
    expectWeight := 319, expectDaBytes := 0, expectAnchorBytes := 0
  },
  -- Unknown suite (not in native spend set) => unknown floor 64, so weight matches legacy.
  {
    id := "NATIVE-ROT-WEIGHT-02",
    baseBytes := 60, witnessBytes := 69, daBytes := 1,
    suiteId := 2,
    oldSuiteId := 1, newSuiteId := 3, spendHeight := 100, height := 100,
    suiteRegistered := false, verifyCost := 0,
    expectWeight := 374, expectDaBytes := 0, expectAnchorBytes := 0
  }
]

end RubinFormal.Conformance


-- Generated from conformance/fixtures/CV-NATIVE-ROTATION-CUTOFF.json
-- CUTOFF: H1/H2 boundary vectors for NATIVE_CREATE_SUITES/NATIVE_SPEND_SUITES transitions.

namespace RubinFormal.Conformance

structure CVNativeRotationCutoffVector where
  id : String
  op : String
  height : Nat
  suiteId : Nat
  expectOk : Bool
  expectErr : Option String

def cvNativeRotationCutoffVectors : List CVNativeRotationCutoffVector := [
  { id := "NATIVE-ROT-CUTOFF-01", op := "rotation_create_suite_check", height := 199, suiteId := 1, expectOk := true, expectErr := none },
  { id := "NATIVE-ROT-CUTOFF-02", op := "rotation_create_suite_check", height := 200, suiteId := 1, expectOk := true, expectErr := none },
  { id := "NATIVE-ROT-CUTOFF-03", op := "rotation_create_suite_check", height := 200, suiteId := 2, expectOk := true, expectErr := none },
  { id := "NATIVE-ROT-CUTOFF-04", op := "rotation_create_suite_check", height := 99, suiteId := 2, expectOk := false, expectErr := some "TX_ERR_SIG_ALG_INVALID" },
  { id := "NATIVE-ROT-CUTOFF-05", op := "rotation_create_suite_check", height := 100, suiteId := 2, expectOk := true, expectErr := none },
  { id := "NATIVE-ROT-CUTOFF-06", op := "rotation_spend_suite_check", height := 200, suiteId := 1, expectOk := true, expectErr := none }
]

end RubinFormal.Conformance

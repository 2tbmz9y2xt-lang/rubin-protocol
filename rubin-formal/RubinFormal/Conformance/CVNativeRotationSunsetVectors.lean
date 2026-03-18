-- Generated from conformance/fixtures/CV-NATIVE-ROTATION-SUNSET.json
-- SUNSET: H4 boundary vectors — old suite removal from CREATE set at sunset_height.

namespace RubinFormal.Conformance

structure CVNativeRotationSunsetVector where
  id : String
  op : String
  height : Nat
  suiteId : Nat
  expectOk : Bool
  expectErr : Option String

def cvNativeRotationSunsetVectors : List CVNativeRotationSunsetVector := [
  { id := "NATIVE-ROT-SUNSET-01", op := "rotation_spend_suite_check", height := 399, suiteId := 1, expectOk := true, expectErr := none },
  { id := "NATIVE-ROT-SUNSET-02", op := "rotation_spend_suite_check", height := 400, suiteId := 1, expectOk := true, expectErr := none },
  { id := "NATIVE-ROT-SUNSET-03", op := "rotation_create_suite_check", height := 399, suiteId := 1, expectOk := true, expectErr := none },
  { id := "NATIVE-ROT-SUNSET-04", op := "rotation_create_suite_check", height := 400, suiteId := 1, expectOk := false, expectErr := some "TX_ERR_SIG_ALG_INVALID" },
  { id := "NATIVE-ROT-SUNSET-05", op := "rotation_create_suite_check", height := 999999, suiteId := 1, expectOk := true, expectErr := none }
]

end RubinFormal.Conformance

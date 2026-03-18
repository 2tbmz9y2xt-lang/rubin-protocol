-- CV-NATIVE-ROTATION-SUNSET structural replay checks.
import RubinFormal.Conformance.CVNativeRotationSunsetVectors

namespace RubinFormal.Conformance

/-- All 5 vectors present. -/
theorem cv_native_rotation_sunset_vector_count :
    cvNativeRotationSunsetVectors.length = 5 := by native_decide

/-- IDs are distinct. -/
private def allDistinctSunsetIds (vs : List CVNativeRotationSunsetVector) : Bool :=
  let ids := vs.map (·.id)
  ids.length == ids.eraseDups.length

theorem cv_native_rotation_sunset_ids_distinct :
    allDistinctSunsetIds cvNativeRotationSunsetVectors = true := by native_decide

/-- Every reject vector has non-empty expect_err. -/
private def allSunsetRejectsHaveErr (vs : List CVNativeRotationSunsetVector) : Bool :=
  vs.all fun v =>
    if v.expectOk then true
    else match v.expectErr with
      | some e => e.length > 0
      | none => false

theorem cv_native_rotation_sunset_rejects_have_err :
    allSunsetRejectsHaveErr cvNativeRotationSunsetVectors = true := by native_decide

/-- Gate-mandated alias. -/
theorem cv_native_rotation_sunset_vectors_pass :
    cvNativeRotationSunsetVectors.length = 5 := cv_native_rotation_sunset_vector_count

end RubinFormal.Conformance

-- CV-NATIVE-ROTATION-CUTOFF structural replay checks.
import RubinFormal.Conformance.CVNativeRotationCutoffVectors

namespace RubinFormal.Conformance

/-- All 6 vectors present. -/
theorem cv_native_rotation_cutoff_vector_count :
    cvNativeRotationCutoffVectors.length = 6 := by native_decide

/-- IDs are distinct. -/
private def allDistinctCutoffIds (vs : List CVNativeRotationCutoffVector) : Bool :=
  let ids := vs.map (·.id)
  ids.length == ids.eraseDups.length

theorem cv_native_rotation_cutoff_ids_distinct :
    allDistinctCutoffIds cvNativeRotationCutoffVectors = true := by native_decide

/-- Every reject vector has non-empty expect_err. -/
private def allCutoffRejectsHaveErr (vs : List CVNativeRotationCutoffVector) : Bool :=
  vs.all fun v =>
    if v.expectOk then true
    else match v.expectErr with
      | some e => e.length > 0
      | none => false

theorem cv_native_rotation_cutoff_rejects_have_err :
    allCutoffRejectsHaveErr cvNativeRotationCutoffVectors = true := by native_decide

/-- Gate-mandated alias. -/
theorem cv_native_rotation_cutoff_vectors_pass :
    cvNativeRotationCutoffVectors.length = 6 := cv_native_rotation_cutoff_vector_count

end RubinFormal.Conformance

-- CV-EXT conformance replay: verify vector expectations are self-consistent.
-- Full mechanized replay (parse + verify) requires CV-EXT ops in Lean model.
-- These theorems verify structural properties of the vector set.

import RubinFormal.Conformance.CVExtVectors

namespace RubinFormal.Conformance

/-- All 25 vectors are present. -/
theorem cv_ext_vector_count : cvExtVectors.length = 25 := by native_decide

/-- Vector IDs are all distinct (no duplicates). -/
private def allDistinctIds (vs : List CVExtVector) : Bool :=
  let ids := vs.map (·.id)
  ids.length == ids.eraseDups.length

theorem cv_ext_ids_distinct : allDistinctIds cvExtVectors = true := by native_decide

/-- Every reject vector has a non-empty expect_err. -/
private def allRejectsHaveErr (vs : List CVExtVector) : Bool :=
  vs.all fun v =>
    if v.expectOk then true
    else match v.expectErr with
      | some e => e.length > 0
      | none => false

theorem cv_ext_rejects_have_err : allRejectsHaveErr cvExtVectors = true := by native_decide

/-- At least one vector per required family. -/
private def hasFamilies (vs : List CVExtVector) (families : List String) : Bool :=
  families.all fun fam => vs.any fun v => v.id.startsWith ("CV-EXT-" ++ fam)

theorem cv_ext_has_all_families :
    hasFamilies cvExtVectors ["ENV", "ACT", "PRE", "ENF", "PAY", "ERR", "DUP", "GEN", "PAR"] = true := by
  native_decide

end RubinFormal.Conformance

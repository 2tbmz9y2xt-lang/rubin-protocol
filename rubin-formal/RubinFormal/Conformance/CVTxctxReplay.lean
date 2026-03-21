import RubinFormal.Conformance.CVTxctxVectors

namespace RubinFormal.Conformance

theorem cv_txctx_vector_count : cvTxctxVectors.length = 92 := by native_decide

private def allDistinctIds (vs : List CVTxctxVector) : Bool :=
  let ids := vs.map (·.id)
  ids.length == ids.eraseDups.length

theorem cv_txctx_ids_distinct : allDistinctIds cvTxctxVectors = true := by native_decide

private def allRejectsHaveErr (vs : List CVTxctxVector) : Bool :=
  vs.all fun v =>
    if v.governanceScope then true
    else if v.expectOk then true
    else match v.expectErr with
      | some e => e.length > 0
      | none => false

theorem cv_txctx_rejects_have_err : allRejectsHaveErr cvTxctxVectors = true := by native_decide

private def governanceScopedCount (vs : List CVTxctxVector) : Nat :=
  vs.foldl (fun acc v => if v.governanceScope then acc + 1 else acc) 0

theorem cv_txctx_governance_scope_count : governanceScopedCount cvTxctxVectors = 2 := by native_decide

theorem cv_txctx_vectors_pass : cvTxctxVectors.length = 92 := cv_txctx_vector_count

end RubinFormal.Conformance

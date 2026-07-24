import RubinFormal.TxWireListContract

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem daCoreStructurallyWellFormed_withBytes_exists
    (txKind : Nat)
    (daCoreBytes : Bytes)
    (h : daCoreStructurallyWellFormed txKind daCoreBytes) :
    ∃ a,
      DaCoreV1.parseDaCoreFieldsWithBytes txKind { bs := daCoreBytes, off := 0 } = some a ∧
        a.fst.off = daCoreBytes.size := by
  rcases h with ⟨_, c', hParse, hOff⟩
  simp [DaCoreV1.parseDaCoreFields] at hParse
  rcases hParse with ⟨a, hWithBytes, hCurEq⟩
  cases hCurEq
  exact ⟨a, hWithBytes, hOff⟩

theorem daCoreStructurallyWellFormed_kind0_empty
    (daCoreBytes : Bytes)
    (h : daCoreStructurallyWellFormed 0x00 daCoreBytes) :
    daCoreBytes = ByteArray.empty := by
  rcases h with ⟨_, c', hParse, hOff⟩
  simp [DaCoreV1.parseDaCoreFields, DaCoreV1.parseDaCoreFieldsWithBytes] at hParse
  cases hParse
  cases daCoreBytes with
  | mk arr =>
      simp at hOff
      have hSize : arr.size = 0 := by
        simpa using Eq.symm hOff
      have hArr : arr = #[] := by
        apply Array.ext
        · simpa [hSize]
        · intro i hiLeft hiRight
          have hImpossible : i < 0 := by
            simpa [hSize] using hiLeft
          exact False.elim (Nat.not_lt_zero i hImpossible)
      subst hArr
      rfl

theorem parseDaCoreFieldsWithBytes_kind0_between
    (pre : Bytes)
    (daCoreBytes : Bytes)
    (post : Bytes)
    (h : daCoreStructurallyWellFormed 0x00 daCoreBytes) :
    DaCoreV1.parseDaCoreFieldsWithBytes 0x00
      { bs := pre ++ daCoreBytes ++ post, off := pre.size } =
      some ({ bs := pre ++ daCoreBytes ++ post, off := pre.size + daCoreBytes.size }, daCoreBytes.size) := by
  have hEmpty := daCoreStructurallyWellFormed_kind0_empty daCoreBytes h
  subst hEmpty
  simp [DaCoreV1.parseDaCoreFieldsWithBytes]

end UtxoBasicV1

end RubinFormal

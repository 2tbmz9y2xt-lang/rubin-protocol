import RubinFormal.TxWireDaCoreKind2Info

set_option maxHeartbeats 4000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem parseDaCoreFieldsWithBytes_kind2_between
    (pre : Bytes)
    (daCoreBytes : Bytes)
    (post : Bytes)
    (h : daCoreStructurallyWellFormed 0x02 daCoreBytes) :
    DaCoreV1.parseDaCoreFieldsWithBytes 0x02
      { bs := pre ++ daCoreBytes ++ post, off := pre.size } =
      some ({ bs := pre ++ daCoreBytes ++ post, off := pre.size + daCoreBytes.size }, daCoreBytes.size) := by
  rcases daCoreStructurallyWellFormed_withBytes_exists 0x02 daCoreBytes h with ⟨a, hWith, hOff⟩
  cases pre
  rename_i preData
  cases daCoreBytes
  rename_i daData
  cases post
  rename_i postData
  have hSize66 : Array.size daData = 66 := by
    simpa using kind2_size66 { data := daData } h
  simp [DaCoreV1.parseDaCoreFieldsWithBytes, Cursor.getBytes?, ByteArray.extract, ByteArray.copySlice, ByteArray.size] at hWith ⊢
  rcases hWith with ⟨a1, h1, a2, h2, hTail⟩
  rcases h1 with ⟨hLen1, hEq1⟩
  cases hEq1
  rcases h2 with ⟨hLen2, hEq2⟩
  cases hEq2
  let first : Bytes × Cursor :=
    ({ data := Array.extract (preData ++ daData ++ postData) (Array.size preData)
        (Array.size preData + (Array.size preData + 32 - Array.size preData)) },
      { bs := { data := preData } ++ { data := daData } ++ { data := postData }, off := Array.size preData + 32 })
  refine ⟨first, ?_, ?_⟩
  · constructor
    · have hLeft : Array.size preData + 32 ≤ Array.size preData + Array.size daData := by
        exact Nat.add_le_add_left hLen1 _
      have hRight : Array.size preData + Array.size daData ≤ Array.size preData + Array.size daData + Array.size postData := by
        exact Nat.le_add_right _ _
      exact Nat.le_trans hLeft (by simpa [Array.size_append, Nat.add_assoc] using hRight)
    · rfl
  · let second : Bytes × Cursor :=
      ({ data := Array.extract (preData ++ daData ++ postData) (Array.size preData + 32)
          (Array.size preData + 32 + (Array.size preData + 32 + 2 - (Array.size preData + 32))) },
        { bs := { data := preData } ++ { data := daData } ++ { data := postData }, off := Array.size preData + 32 + 2 })
    refine ⟨second, ?_, ?_⟩
    · constructor
      · have hLen2' : 34 ≤ Array.size daData := by
          simpa [Nat.add_assoc] using hLen2
        have hLeft : Array.size preData + 34 ≤ Array.size preData + Array.size daData := by
          exact Nat.add_le_add_left hLen2' _
        have hRight : Array.size preData + Array.size daData ≤ Array.size preData + Array.size daData + Array.size postData := by
          exact Nat.le_add_right _ _
        exact Nat.le_trans hLeft (by simpa [Array.size_append, Nat.add_assoc] using hRight)
      · simpa [first, second, Nat.add_assoc]
    · split at hTail
      · simp at hTail
      · simp [Nat.add_assoc] at hTail ⊢
        rename_i hNoGuard
        rcases hTail with ⟨a3, h3, hEqA⟩
        rcases h3 with ⟨hLen3, hEq3⟩
        cases hEq3
        cases hEqA
        have hNoGuard' :
            ¬DaCoreV1.MAX_DA_CHUNK_COUNT ≤
              u16le?
                (ByteArray.get! ({ data := Array.extract daData 32 34 } : Bytes) 0)
                (ByteArray.get! ({ data := Array.extract daData 32 34 } : Bytes) 1) := by
          simpa [Cursor.getBytes?, ByteArray.extract, ByteArray.copySlice, ByteArray.size, Nat.add_assoc] using hNoGuard
        have hLocalIndexLt :
            u16le?
              (ByteArray.get! ({ data := Array.extract daData 32 34 } : Bytes) 0)
              (ByteArray.get! ({ data := Array.extract daData 32 34 } : Bytes) 1) <
            DaCoreV1.MAX_DA_CHUNK_COUNT := by
          exact
            DaCoreV1.daChunkIndex_valid_range
              (ByteArray.get! ({ data := Array.extract daData 32 34 } : Bytes) 0)
              (ByteArray.get! ({ data := Array.extract daData 32 34 } : Bytes) 1)
              hNoGuard'
        have hIndexLt :
            u16le?
              (ByteArray.get!
                {
                  data := Array.extract (preData ++ daData ++ postData) (Array.size preData + 32)
                    (Array.size preData + (32 + (Array.size preData + 2 - Array.size preData)))
                } 0)
              (ByteArray.get!
                {
                  data := Array.extract (preData ++ daData ++ postData) (Array.size preData + 32)
                    (Array.size preData + (32 + (Array.size preData + 2 - Array.size preData)))
                } 1) <
            DaCoreV1.MAX_DA_CHUNK_COUNT := by
          exact kind2_shifted_index_lt preData daData postData hSize66 hLocalIndexLt
        have hGuardFalse :
            ¬DaCoreV1.MAX_DA_CHUNK_COUNT ≤
              u16le?
                (ByteArray.get!
                  {
                    data := Array.extract (preData ++ daData ++ postData) (Array.size preData + 32)
                      (Array.size preData + (32 + (Array.size preData + 2 - Array.size preData)))
                  } 0)
                (ByteArray.get!
                  {
                    data := Array.extract (preData ++ daData ++ postData) (Array.size preData + 32)
                      (Array.size preData + (32 + (Array.size preData + 2 - Array.size preData)))
                  } 1) := by
          exact Nat.not_le_of_lt hIndexLt
        have hBig66 : Array.size preData + 66 ≤ Array.size (preData ++ daData ++ postData) := by
          rw [Array.size_append, Array.size_append, hSize66, Nat.add_assoc]
          simpa [Nat.add_assoc] using Nat.le_add_right (Array.size preData + 66) (Array.size postData)
        exact kind2_tail_shift preData daData postData hSize66 hGuardFalse hBig66

end UtxoBasicV1

end RubinFormal

import RubinFormal.TxWireDaCoreBase

set_option maxHeartbeats 12000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private def kind2TailChunk (preData daData postData : Array UInt8) : Bytes :=
  {
    data := Array.extract (preData ++ daData ++ postData) (Array.size preData + 34)
      (Array.size preData + (34 + (Array.size preData + 32 - Array.size preData)))
  }

private def kind2TailCursor (preData daData postData : Array UInt8) : Cursor :=
  { bs := ({ data := preData } : Bytes) ++ ({ data := daData } : Bytes) ++ ({ data := postData } : Bytes),
    off := Array.size preData + 66 }

theorem kind2_size66
    (daCoreBytes : Bytes)
    (h : daCoreStructurallyWellFormed 0x02 daCoreBytes) :
    daCoreBytes.size = 66 := by
  rcases daCoreStructurallyWellFormed_withBytes_exists 0x02 daCoreBytes h with ⟨a, hWith, hOff⟩
  simp [DaCoreV1.parseDaCoreFieldsWithBytes] at hWith
  rcases hWith with ⟨a1, h1, a2, h2, hTail⟩
  simp [Cursor.getBytes?, ByteArray.extract, ByteArray.copySlice, ByteArray.size] at h1
  rcases h1 with ⟨_, hEq1⟩
  cases hEq1
  simp [Cursor.getBytes?, ByteArray.extract, ByteArray.copySlice, ByteArray.size] at h2
  rcases h2 with ⟨_, hEq2⟩
  cases hEq2
  simp [Cursor.getBytes?, ByteArray.extract, ByteArray.copySlice, ByteArray.size, Nat.add_assoc] at hTail
  split at hTail
  · simp at hTail
  · simp [Nat.add_assoc] at hTail
    rename_i _hLenTail _hGuard
    rcases hTail with ⟨a3, h3, hEqA⟩
    rcases h3 with ⟨_, hEq3⟩
    cases hEq3
    cases hEqA
    simpa using Eq.symm hOff

theorem kind2_tail_shift
    (preData daData postData : Array UInt8)
    (hSize66 : Array.size daData = 66)
    (hGuardFalse :
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
            } 1))
    (hBig66 : Array.size preData + 66 ≤ Array.size (preData ++ daData ++ postData)) :
    (if
        DaCoreV1.MAX_DA_CHUNK_COUNT ≤
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
              } 1) then
      none
    else
      Option.bind
        (if Array.size preData + 66 ≤ Array.size (preData ++ daData ++ postData) then
          some (kind2TailChunk preData daData postData, kind2TailCursor preData daData postData)
        else none)
        fun __discr => some (__discr.snd, __discr.snd.off - Array.size preData)) =
      some
        (({ bs := ({ data := preData } : Bytes) ++ ({ data := daData } : Bytes) ++ ({ data := postData } : Bytes),
            off := Array.size preData + Array.size daData } : Cursor),
          Array.size daData) := by
  rw [if_neg hGuardFalse, if_pos hBig66]
  have hSub : Array.size preData + 66 - Array.size preData = 66 := by
    exact Nat.add_sub_cancel_left (Array.size preData) 66
  simp [kind2TailChunk, kind2TailCursor, hSize66, hSub, Nat.add_assoc]

private theorem kind2_shifted_idxRaw_eq
    (preData daData postData : Array UInt8)
    (hSize66 : Array.size daData = 66) :
    ({ data := Array.extract (preData ++ daData ++ postData) (Array.size preData + 32) (Array.size preData + 34) } : Bytes) =
      ({ data := Array.extract daData 32 34 } : Bytes) := by
  apply ByteArray.ext
  apply Array.ext
  · simp [ByteArray.size, Array.size_extract, Array.size_append, hSize66, Nat.add_assoc]
    omega
  · intro i hiLeft hiRight
    have hi : i < 2 := by
      simp [ByteArray.size, Array.size_extract, Array.size_append, hSize66, Nat.add_assoc] at hiLeft
      omega
    rw [Array.get_extract, Array.get_extract]
    · have hDa : 32 + i < Array.size daData := by
        have h34 : 32 + i < 34 := by
          simpa [Nat.add_assoc] using Nat.add_lt_add_left hi 32
        exact Nat.lt_of_lt_of_le h34 (by simpa [hSize66] using hConst)
      have hDaPost : 32 + i < Array.size (daData ++ postData) := by
        exact Nat.lt_of_lt_of_le hDa (by simpa [Array.size_append] using Nat.le_add_right (Array.size daData) (Array.size postData))
      have hAll :
          Array.size preData + (32 + i) < Array.size (preData ++ daData ++ postData) := by
        simpa [Array.size_append, Nat.add_assoc] using Nat.add_lt_add_left hDaPost (Array.size preData)
      have hShift :
          (preData ++ daData ++ postData)[Array.size preData + (32 + i)] =
            (daData ++ postData)[32 + i] := by
        simpa [Array.append_assoc, Nat.add_assoc, Nat.add_sub_cancel_left] using
          (Array.get_append_right
            (as := preData)
            (bs := daData ++ postData)
            (i := Array.size preData + (32 + i))
            (h := by simpa [Array.append_assoc, Array.size_append, Nat.add_assoc] using hAll)
            (by exact Nat.le_add_right (Array.size preData) (32 + i)))
      have hLeft :
          (daData ++ postData)[32 + i] = daData[32 + i] := by
        exact
          Array.get_append_left
            (as := daData)
            (bs := postData)
            (i := 32 + i)
            (h := hDaPost)
            (by simpa [hSize66] using hDa)
      simpa [Nat.add_assoc] using Eq.trans hShift hLeft

theorem kind2_shifted_index_lt
    (preData daData postData : Array UInt8)
    (hSize66 : Array.size daData = 66)
    (hIndexLt :
      u16le?
        (ByteArray.get! ({ data := Array.extract daData 32 34 } : Bytes) 0)
        (ByteArray.get! ({ data := Array.extract daData 32 34 } : Bytes) 1) <
      DaCoreV1.MAX_DA_CHUNK_COUNT) :
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
  have hTwo : Array.size preData + 2 - Array.size preData = 2 := by
    exact Nat.add_sub_cancel_left (Array.size preData) 2
  have hEq :
      ({ data := Array.extract (preData ++ daData ++ postData) (Array.size preData + 32)
          (Array.size preData + (32 + (Array.size preData + 2 - Array.size preData))) } : Bytes) =
        ({ data := Array.extract daData 32 34 } : Bytes) := by
    rw [show Array.size preData + (32 + (Array.size preData + 2 - Array.size preData)) = Array.size preData + 34 by
      simp [hTwo, Nat.add_assoc]]
    exact kind2_shifted_idxRaw_eq preData daData postData hSize66
  simpa [hEq] using hIndexLt

end UtxoBasicV1

end RubinFormal

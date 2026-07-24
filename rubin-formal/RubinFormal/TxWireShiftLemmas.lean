import RubinFormal.DaCoreV1
import Std.Tactic.Omega

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private theorem requireMinimal_true
    {minimal : Bool}
    (h : ∃ x, DaCoreV1.requireMinimal minimal = some x) :
    minimal = true := by
  cases minimal with
  | false =>
      rcases h with ⟨x, hx⟩
      simp [DaCoreV1.requireMinimal] at hx
  | true =>
      rfl

theorem cursor_getU8_preserves_bs_local
    (c : Cursor)
    (b : UInt8)
    (c' : Cursor) :
    c.getU8? = some (b, c') → c'.bs = c.bs := by
  simp only [Cursor.getU8?]
  split
  · simp only [Option.some.injEq, Prod.mk.injEq, and_imp]
    intro _ h
    subst h
    rfl
  · simp

theorem cursor_getBytes_preserves_bs_local
    (c : Cursor)
    (n : Nat)
    (bs : Bytes)
    (c' : Cursor) :
    c.getBytes? n = some (bs, c') → c'.bs = c.bs := by
  simp only [Cursor.getBytes?]
  split
  · simp only [Option.some.injEq, Prod.mk.injEq, and_imp]
    intro _ h
    subst h
    rfl
  · simp

theorem cursor_getBytes_between_of_success
    (pre mid post : Bytes)
    (off n : Nat)
    (out : Bytes)
    (c' : Cursor)
    (h : ({ bs := mid, off := off } : Cursor).getBytes? n = some (out, c')) :
    ({ bs := pre ++ mid ++ post, off := pre.size + off } : Cursor).getBytes? n =
      some (out, { bs := pre ++ mid ++ post, off := pre.size + c'.off }) := by
  have hAdv : c'.off = off + n := Cursor.getBytes_advances { bs := mid, off := off } n out c' h
  rw [hAdv]
  cases pre
  rename_i preData
  cases mid
  rename_i midData
  cases post
  rename_i postData
  simp [Cursor.getBytes?, ByteArray.extract, ByteArray.copySlice, ByteArray.size] at h ⊢
  rcases h with ⟨hLen, hEqOut, hEqCur⟩
  constructor
  · have hLeft : Array.size preData + (off + n) ≤ Array.size preData + Array.size midData := by
      exact Nat.add_le_add_left hLen _
    have hRight : Array.size preData + Array.size midData ≤ Array.size preData + Array.size midData + Array.size postData := by
      exact Nat.le_add_right _ _
    exact Nat.le_trans (by simpa [Nat.add_assoc] using hLeft) (by simpa [Array.size_append, Nat.add_assoc] using hRight)
  · constructor
    · have hExtractEq :
          ({
            data :=
              Array.extract (preData ++ midData ++ postData) (Array.size preData + off)
                (Array.size preData + off + (Array.size preData + off + n - (Array.size preData + off)))
          } : Bytes) =
            ({ data := Array.extract midData off (off + (off + n - off)) } : Bytes) := by
        apply ByteArray.ext
        apply Array.ext
        · have hSub : Array.size preData + off + n - (Array.size preData + off) = off + n - off := by
            omega
          have hBound :
              Array.size preData + off + n ≤ Array.size preData + (Array.size midData + Array.size postData) := by
            omega
          have hMin :
              min (Array.size preData + off + n) (Array.size preData + (Array.size midData + Array.size postData)) =
                Array.size preData + off + n := Nat.min_eq_left hBound
          have hBoundRight : off + (off + n - off) ≤ Array.size midData := by
            omega
          have hMinRight :
              min (off + (off + n - off)) (Array.size midData) = off + (off + n - off) :=
            Nat.min_eq_left hBoundRight
          simp [Array.size_extract, Array.size_append, Nat.add_assoc, hSub]
          have hMinLeftWeird :
              min (Array.size preData + (off + (Array.size preData + (off + n) - (Array.size preData + off))))
                  (Array.size preData + (Array.size midData + Array.size postData)) =
                Array.size preData + off + n := by
            have hNorm :
                Array.size preData + (off + (Array.size preData + (off + n) - (Array.size preData + off))) =
                  Array.size preData + off + n := by
              omega
            rw [hNorm]
            exact hMin
          rw [hMinLeftWeird, hMinRight]
          omega
        · intro i hiLeft hiRight
          have hBoundRight : off + (off + n - off) ≤ Array.size midData := by
            omega
          have hMinRight :
              min (off + (off + n - off)) (Array.size midData) = off + (off + n - off) :=
            Nat.min_eq_left hBoundRight
          have hiRight' : i < off + (off + n - off) - off := by
            simpa [Array.size_extract, hMinRight] using hiRight
          have hMidLt : off + i < Array.size midData := by
            omega
          have hMidPost : off + i < Array.size (midData ++ postData) := by
            exact Nat.lt_of_lt_of_le hMidLt (by simpa [Array.size_append] using Nat.le_add_right (Array.size midData) (Array.size postData))
          have hAll : Array.size preData + (off + i) < Array.size (preData ++ midData ++ postData) := by
            simpa [Array.size_append, Nat.add_assoc] using Nat.add_lt_add_left hMidPost (Array.size preData)
          have hShift :
              (preData ++ midData ++ postData)[Array.size preData + (off + i)] =
                (midData ++ postData)[off + i] := by
            simpa [Array.append_assoc, Nat.add_assoc, Nat.add_sub_cancel_left] using
              (Array.get_append_right
                (as := preData)
                (bs := midData ++ postData)
                (i := Array.size preData + (off + i))
                (h := by simpa [Array.append_assoc] using hAll)
                (by exact Nat.le_add_right _ _))
          have hLeft :
              (midData ++ postData)[off + i] = midData[off + i] := by
            exact
              Array.get_append_left
                (as := midData)
                (bs := postData)
                (i := off + i)
                (h := hMidPost)
                hMidLt
          have hBigGet :
              ({ data := Array.extract (preData ++ midData ++ postData) (Array.size preData + off)
                  (Array.size preData + off + (Array.size preData + off + n - (Array.size preData + off))) } : Bytes).data[i] =
                (preData ++ midData ++ postData)[Array.size preData + (off + i)] := by
            simpa [Nat.add_assoc] using
              (Array.get_extract
                (arr := preData ++ midData ++ postData)
                (start := Array.size preData + off)
                (stop := Array.size preData + off + (Array.size preData + off + n - (Array.size preData + off)))
                (i := i)
                (h := by exact hAll)
                (h' := hiLeft))
          have hMidGet :
              ({ data := Array.extract midData off (off + (off + n - off)) } : Bytes).data[i] =
                midData[off + i] := by
            simpa using
              (Array.get_extract
                (arr := midData)
                (start := off)
                (stop := off + (off + n - off))
                (i := i)
                (h := hMidLt)
                (h' := hiLeft))
          calc
            ({ data := Array.extract (preData ++ midData ++ postData) (Array.size preData + off)
                (Array.size preData + off + (Array.size preData + off + n - (Array.size preData + off))) } : Bytes).data[i]
                = (preData ++ midData ++ postData)[Array.size preData + (off + i)] := hBigGet
            _ = (midData ++ postData)[off + i] := hShift
            _ = midData[off + i] := hLeft
            _ = ({ data := Array.extract midData off (off + (off + n - off)) } : Bytes).data[i] := hMidGet.symm
      exact hExtractEq.trans hEqOut
    · simpa [Nat.add_assoc] using hEqCur

theorem cursor_getU8_between_of_success
    (pre mid post : Bytes)
    (off : Nat)
    (b : UInt8)
    (c' : Cursor)
    (h : ({ bs := mid, off := off } : Cursor).getU8? = some (b, c')) :
    ({ bs := pre ++ mid ++ post, off := pre.size + off } : Cursor).getU8? =
      some (b, { bs := pre ++ mid ++ post, off := pre.size + c'.off }) := by
  have hAdv : c'.off = off + 1 := Cursor.getU8_advances { bs := mid, off := off } b c' h
  rw [hAdv]
  cases pre
  rename_i preData
  cases mid
  rename_i midData
  cases post
  rename_i postData
  simp [Cursor.getU8?, ByteArray.size] at h ⊢
  rcases h with ⟨hLt, hEqB, hEqCur⟩
  constructor
  · have hMidPost : off < Array.size (midData ++ postData) := by
      exact Nat.lt_of_lt_of_le hLt (by simpa [Array.size_append] using Nat.le_add_right (Array.size midData) (Array.size postData))
    simpa [Array.size_append, Nat.add_assoc] using Nat.add_lt_add_left hMidPost (Array.size preData)
  · constructor
    · have hMidPost : off < Array.size (midData ++ postData) := by
        exact Nat.lt_of_lt_of_le hLt (by simpa [Array.size_append] using Nat.le_add_right (Array.size midData) (Array.size postData))
      have hAll : Array.size preData + off < Array.size (preData ++ midData ++ postData) := by
        simpa [Array.size_append, Nat.add_assoc] using Nat.add_lt_add_left hMidPost (Array.size preData)
      have hShift :
          (preData ++ midData ++ postData)[Array.size preData + off] =
            (midData ++ postData)[off] := by
        simpa [Array.append_assoc, Nat.add_assoc, Nat.add_sub_cancel_left] using
          (Array.get_append_right
            (as := preData)
            (bs := midData ++ postData)
            (i := Array.size preData + off)
            (h := by simpa [Array.append_assoc] using hAll)
            (by exact Nat.le_add_right _ _))
      have hLeft :
          (midData ++ postData)[off] = midData[off] := by
        exact
          Array.get_append_left
            (as := midData)
            (bs := postData)
            (i := off)
            (h := hMidPost)
            hLt
      calc
        ByteArray.get! ({ data := preData } ++ { data := midData } ++ { data := postData }) (Array.size preData + off)
            = Option.getD ((preData ++ midData ++ postData)[Array.size preData + off]?) default := by
                simp [ByteArray.get!, getElem!, hAll]
        _ = (preData ++ midData ++ postData)[Array.size preData + off] := by
                simp [getElem?, hAll]
        _ = (midData ++ postData)[off] := hShift
        _ = midData[off] := hLeft
        _ = b := by
            calc
              midData[off] = ByteArray.get! ({ data := midData } : Bytes) off := by
                simp [ByteArray.get!, getElem!, hLt, getElem?]
              _ = b := hEqB
    · simp [Nat.add_assoc]

theorem cursor_getBytes_between_of_success_cur
    (pre mid post : Bytes)
    (cur : Cursor)
    (n : Nat)
    (out : Bytes)
    (c' : Cursor)
    (hBs : cur.bs = mid)
    (h : cur.getBytes? n = some (out, c')) :
    ({ bs := pre ++ mid ++ post, off := pre.size + cur.off } : Cursor).getBytes? n =
      some (out, { bs := pre ++ mid ++ post, off := pre.size + c'.off }) := by
  cases cur with
  | mk bs off =>
      simp at hBs
      subst hBs
      simpa using cursor_getBytes_between_of_success pre bs post off n out c' h

theorem cursor_getU8_between_of_success_cur
    (pre mid post : Bytes)
    (cur : Cursor)
    (b : UInt8)
    (c' : Cursor)
    (hBs : cur.bs = mid)
    (h : cur.getU8? = some (b, c')) :
    ({ bs := pre ++ mid ++ post, off := pre.size + cur.off } : Cursor).getU8? =
      some (b, { bs := pre ++ mid ++ post, off := pre.size + c'.off }) := by
  cases cur with
  | mk bs off =>
      simp at hBs
      subst hBs
      simpa using cursor_getU8_between_of_success pre bs post off b c' h

theorem cursor_getCompactSize_preserves_bs_local
    (c : Cursor)
    (n : Nat)
    (c' : Cursor)
    (minimal : Bool) :
    c.getCompactSize? = some (n, c', minimal) → c'.bs = c.bs := by
  unfold Cursor.getCompactSize?
  cases hU8 : c.getU8? with
  | none =>
      simp [hU8]
  | some p =>
      rcases p with ⟨b, c1⟩
      have hC1Bs : c1.bs = c.bs := cursor_getU8_preserves_bs_local c b c1 hU8
      by_cases hSmall : b.toNat < 0xfd
      · intro h
        have hEq : c' = c1 := by
          have hEq' : b.toNat = n ∧ c1 = c' ∧ true = minimal := by
            simpa [hU8, hSmall] using h
          exact hEq'.2.1.symm
        simpa [hEq] using hC1Bs
      · by_cases hTag253 : b.toNat = 253
        · cases hBytes : Cursor.getBytes? c1 2 with
          | none =>
              simp [hU8, hSmall, hTag253, hBytes]
          | some p2 =>
              rcases p2 with ⟨raw2, c2⟩
              have hC2Bs : c2.bs = c.bs := by
                calc
                  c2.bs = c1.bs := cursor_getBytes_preserves_bs_local c1 2 raw2 c2 hBytes
                  _ = c.bs := hC1Bs
              intro h
              have hEq : c' = c2 := by
                have hEq' :
                    u16le? (ByteArray.get! raw2 0) (ByteArray.get! raw2 1) = n ∧
                      c2 = c' ∧
                      decide (253 ≤ u16le? (ByteArray.get! raw2 0) (ByteArray.get! raw2 1)) = minimal := by
                  simpa [hU8, hSmall, hTag253, hBytes] using h
                exact hEq'.2.1.symm
              simpa [hEq] using hC2Bs
        · by_cases hTag254 : b.toNat = 254
          · cases hBytes : Cursor.getBytes? c1 4 with
            | none =>
                simp [hU8, hSmall, hTag253, hTag254, hBytes]
            | some p4 =>
                rcases p4 with ⟨raw4, c2⟩
                have hC2Bs : c2.bs = c.bs := by
                  calc
                    c2.bs = c1.bs := cursor_getBytes_preserves_bs_local c1 4 raw4 c2 hBytes
                    _ = c.bs := hC1Bs
                intro h
                have hEq : c' = c2 := by
                  have hEq' :
                      u32le? (ByteArray.get! raw4 0) (ByteArray.get! raw4 1) (ByteArray.get! raw4 2)
                          (ByteArray.get! raw4 3) = n ∧
                        c2 = c' ∧
                        decide
                            (65535 <
                              u32le? (ByteArray.get! raw4 0) (ByteArray.get! raw4 1)
                                (ByteArray.get! raw4 2) (ByteArray.get! raw4 3)) = minimal := by
                    simpa [hU8, hSmall, hTag253, hTag254, hBytes] using h
                  exact hEq'.2.1.symm
                simpa [hEq] using hC2Bs
          · cases hBytes : Cursor.getBytes? c1 8 with
            | none =>
                simp [hU8, hSmall, hTag253, hTag254, hBytes]
            | some p8 =>
                rcases p8 with ⟨raw8, c2⟩
                have hC2Bs : c2.bs = c.bs := by
                  calc
                    c2.bs = c1.bs := cursor_getBytes_preserves_bs_local c1 8 raw8 c2 hBytes
                    _ = c.bs := hC1Bs
                intro h
                have hEq : c' = c2 := by
                  have hEq' :
                      (Wire.u64le? (ByteArray.get! raw8 0) (ByteArray.get! raw8 1)
                          (ByteArray.get! raw8 2) (ByteArray.get! raw8 3)
                          (ByteArray.get! raw8 4) (ByteArray.get! raw8 5)
                          (ByteArray.get! raw8 6) (ByteArray.get! raw8 7)).toNat = n ∧
                        c2 = c' ∧
                        decide
                            (4294967295 <
                              (Wire.u64le? (ByteArray.get! raw8 0) (ByteArray.get! raw8 1)
                                (ByteArray.get! raw8 2) (ByteArray.get! raw8 3)
                                (ByteArray.get! raw8 4) (ByteArray.get! raw8 5)
                                (ByteArray.get! raw8 6) (ByteArray.get! raw8 7)).toNat) = minimal := by
                    simpa [hU8, hSmall, hTag253, hTag254, hBytes] using h
                  exact hEq'.2.1.symm
                simpa [hEq] using hC2Bs

end UtxoBasicV1

end RubinFormal

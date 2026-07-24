import RubinFormal.TxWireDaCoreBase
import RubinFormal.TxWireShiftLemmas

set_option maxHeartbeats 12000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private theorem requireMinimal_true_local
    {minimal : Bool}
    (h : ∃ x, DaCoreV1.requireMinimal minimal = some x) :
    minimal = true := by
  cases minimal with
  | false =>
      rcases h with ⟨x, hx⟩
      simp [DaCoreV1.requireMinimal] at hx
  | true =>
      rfl

theorem parseDaCoreFieldsWithBytes_kind1_between
    (pre : Bytes)
    (daCoreBytes : Bytes)
    (post : Bytes)
    (h : daCoreStructurallyWellFormed 0x01 daCoreBytes) :
    DaCoreV1.parseDaCoreFieldsWithBytes 0x01
      { bs := pre ++ daCoreBytes ++ post, off := pre.size } =
      some ({ bs := pre ++ daCoreBytes ++ post, off := pre.size + daCoreBytes.size }, daCoreBytes.size) := by
  rcases daCoreStructurallyWellFormed_withBytes_exists 0x01 daCoreBytes h with ⟨a, hWith, hOff⟩
  simp [DaCoreV1.parseDaCoreFieldsWithBytes] at hWith ⊢
  rcases hWith with ⟨a1, h1, a2, h2, hTail⟩
  have h1s :=
    cursor_getBytes_between_of_success pre daCoreBytes post 0 32 a1.fst a1.snd h1
  have h1Bs : a1.snd.bs = daCoreBytes := by
    exact cursor_getBytes_preserves_bs_local { bs := daCoreBytes, off := 0 } 32 a1.fst a1.snd h1
  refine ⟨(a1.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a1.snd.off }), ?_, ?_⟩
  · simpa [Nat.add_assoc] using h1s
  · have h2s :=
        cursor_getBytes_between_of_success_cur pre daCoreBytes post a1.snd 2 a2.fst a2.snd h1Bs h2
    have h2Bs : a2.snd.bs = daCoreBytes := by
      calc
        a2.snd.bs = a1.snd.bs := cursor_getBytes_preserves_bs_local a1.snd 2 a2.fst a2.snd h2
        _ = daCoreBytes := h1Bs
    refine ⟨(a2.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a2.snd.off }), ?_, ?_⟩
    · simpa [Nat.add_assoc] using h2s
    · split at hTail
      · simp at hTail
      · rename_i hChunkGuardFalse
        simp [hChunkGuardFalse] at hTail ⊢
        rcases hTail with ⟨a3, h3, hTail⟩
        have h3s :=
          cursor_getBytes_between_of_success_cur pre daCoreBytes post a2.snd 32 a3.fst a3.snd h2Bs h3
        have h3Bs : a3.snd.bs = daCoreBytes := by
          calc
            a3.snd.bs = a2.snd.bs := cursor_getBytes_preserves_bs_local a2.snd 32 a3.fst a3.snd h3
            _ = daCoreBytes := h2Bs
        refine ⟨(a3.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a3.snd.off }), ?_, ?_⟩
        · simpa [Nat.add_assoc] using h3s
        · rcases hTail with ⟨a4, h4, hTail⟩
          have h4s :=
            cursor_getBytes_between_of_success_cur pre daCoreBytes post a3.snd 8 a4.fst a4.snd h3Bs h4
          have h4Bs : a4.snd.bs = daCoreBytes := by
            calc
              a4.snd.bs = a3.snd.bs := cursor_getBytes_preserves_bs_local a3.snd 8 a4.fst a4.snd h4
              _ = daCoreBytes := h3Bs
          refine ⟨(a4.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a4.snd.off }), ?_, ?_⟩
          · simpa [Nat.add_assoc] using h4s
          · rcases hTail with ⟨a5, h5, hTail⟩
            have h5s :=
              cursor_getBytes_between_of_success_cur pre daCoreBytes post a4.snd 32 a5.fst a5.snd h4Bs h5
            have h5Bs : a5.snd.bs = daCoreBytes := by
              calc
                a5.snd.bs = a4.snd.bs := cursor_getBytes_preserves_bs_local a4.snd 32 a5.fst a5.snd h5
                _ = daCoreBytes := h4Bs
            refine ⟨(a5.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a5.snd.off }), ?_, ?_⟩
            · simpa [Nat.add_assoc] using h5s
            · rcases hTail with ⟨a6, h6, hTail⟩
              have h6s :=
                cursor_getBytes_between_of_success_cur pre daCoreBytes post a5.snd 32 a6.fst a6.snd h5Bs h6
              have h6Bs : a6.snd.bs = daCoreBytes := by
                calc
                  a6.snd.bs = a5.snd.bs := cursor_getBytes_preserves_bs_local a5.snd 32 a6.fst a6.snd h6
                  _ = daCoreBytes := h5Bs
              refine ⟨(a6.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a6.snd.off }), ?_, ?_⟩
              · simpa [Nat.add_assoc] using h6s
              · rcases hTail with ⟨a7, h7, hTail⟩
                have h7s :=
                  cursor_getBytes_between_of_success_cur pre daCoreBytes post a6.snd 32 a7.fst a7.snd h6Bs h7
                have h7Bs : a7.snd.bs = daCoreBytes := by
                  calc
                    a7.snd.bs = a6.snd.bs := cursor_getBytes_preserves_bs_local a6.snd 32 a7.fst a7.snd h7
                    _ = daCoreBytes := h6Bs
                refine ⟨(a7.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a7.snd.off }), ?_, ?_⟩
                · simpa [Nat.add_assoc] using h7s
                · rcases hTail with ⟨a8, h8, hTail⟩
                  have h8s :=
                    cursor_getBytes_between_of_success_cur pre daCoreBytes post a7.snd 1 a8.fst a8.snd h7Bs h8
                  have h8Bs : a8.snd.bs = daCoreBytes := by
                    calc
                      a8.snd.bs = a7.snd.bs := cursor_getBytes_preserves_bs_local a7.snd 1 a8.fst a8.snd h8
                      _ = daCoreBytes := h7Bs
                  refine ⟨(a8.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a8.snd.off }), ?_, ?_⟩
                  · simpa [Nat.add_assoc] using h8s
                  · rcases hTail with ⟨a9, h9, hMin, hTail⟩
                    cases hU8Base : Cursor.getU8? a8.snd with
                    | none =>
                        unfold Cursor.getCompactSize? at h9
                        simp [hU8Base] at h9
                    | some p =>
                        rcases p with ⟨bTag, cTag⟩
                        have hU8Shift :=
                          cursor_getU8_between_of_success_cur pre daCoreBytes post a8.snd bTag cTag h8Bs hU8Base
                        have hU8Bs : cTag.bs = daCoreBytes := by
                          calc
                            cTag.bs = a8.snd.bs := cursor_getU8_preserves_bs_local a8.snd bTag cTag hU8Base
                            _ = daCoreBytes := h8Bs
                        have hMinTrue : a9.2.snd = true := requireMinimal_true_local hMin
                        have hCompactShift :
                            Cursor.getCompactSize?
                              { bs := pre ++ daCoreBytes ++ post, off := pre.size + a8.snd.off } =
                            some (a9.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a9.2.fst.off }, a9.2.snd) := by
                          by_cases hTagSmall : bTag.toNat < 0xfd
                          · have h9' := h9
                            unfold Cursor.getCompactSize? at h9'
                            simp [hU8Base, hTagSmall] at h9'
                            have hA9 : a9 = (bTag.toNat, cTag, true) := by
                              exact h9'.symm
                            subst a9
                            unfold Cursor.getCompactSize?
                            rw [hU8Shift]
                            simp [hTagSmall]
                          · by_cases hTag253 : bTag.toNat = 253
                            · cases hBytesBase : Cursor.getBytes? cTag 2 with
                              | none =>
                                  have h9' := h9
                                  unfold Cursor.getCompactSize? at h9'
                                  simp [hU8Base, hTagSmall, hTag253, hBytesBase] at h9'
                              | some p2 =>
                                  rcases p2 with ⟨raw2, c2⟩
                                  have h9' := h9
                                  unfold Cursor.getCompactSize? at h9'
                                  simp [hU8Base, hTagSmall, hTag253, hBytesBase] at h9'
                                  have hA9 :
                                      a9 =
                                        (Wire.u16le? (ByteArray.get! raw2 0) (ByteArray.get! raw2 1),
                                          c2,
                                          decide
                                            (253 ≤
                                              Wire.u16le? (ByteArray.get! raw2 0) (ByteArray.get! raw2 1))) := by
                                    exact h9'.symm
                                  have hBytesShift :=
                                    cursor_getBytes_between_of_success_cur pre daCoreBytes post cTag 2 raw2 c2 hU8Bs hBytesBase
                                  subst a9
                                  unfold Cursor.getCompactSize?
                                  rw [hU8Shift]
                                  simp [hTagSmall, hTag253, hBytesShift, Nat.add_assoc]
                            · by_cases hTag254 : bTag.toNat = 254
                              · cases hBytesBase : Cursor.getBytes? cTag 4 with
                                | none =>
                                    have h9' := h9
                                    unfold Cursor.getCompactSize? at h9'
                                    simp [hU8Base, hTagSmall, hTag253, hTag254, hBytesBase] at h9'
                                | some p4 =>
                                    rcases p4 with ⟨raw4, c4⟩
                                    have h9' := h9
                                    unfold Cursor.getCompactSize? at h9'
                                    simp [hU8Base, hTagSmall, hTag253, hTag254, hBytesBase] at h9'
                                    have hA9 :
                                        a9 =
                                          (Wire.u32le? (ByteArray.get! raw4 0) (ByteArray.get! raw4 1)
                                              (ByteArray.get! raw4 2) (ByteArray.get! raw4 3),
                                            c4,
                                            decide
                                              (65535 <
                                                Wire.u32le? (ByteArray.get! raw4 0) (ByteArray.get! raw4 1)
                                                  (ByteArray.get! raw4 2) (ByteArray.get! raw4 3))) := by
                                      exact h9'.symm
                                    have hBytesShift :=
                                      cursor_getBytes_between_of_success_cur pre daCoreBytes post cTag 4 raw4 c4 hU8Bs hBytesBase
                                    subst a9
                                    unfold Cursor.getCompactSize?
                                    rw [hU8Shift]
                                    simp [hTagSmall, hTag253, hTag254, hBytesShift, Nat.add_assoc]
                              · cases hBytesBase : Cursor.getBytes? cTag 8 with
                                | none =>
                                    have h9' := h9
                                    unfold Cursor.getCompactSize? at h9'
                                    simp [hU8Base, hTagSmall, hTag253, hTag254, hBytesBase] at h9'
                                | some p8 =>
                                    rcases p8 with ⟨raw8, c8⟩
                                    have h9' := h9
                                    unfold Cursor.getCompactSize? at h9'
                                    simp [hU8Base, hTagSmall, hTag253, hTag254, hBytesBase] at h9'
                                    have hA9 :
                                        a9 =
                                          ((Wire.u64le? (ByteArray.get! raw8 0) (ByteArray.get! raw8 1)
                                              (ByteArray.get! raw8 2) (ByteArray.get! raw8 3)
                                              (ByteArray.get! raw8 4) (ByteArray.get! raw8 5)
                                              (ByteArray.get! raw8 6) (ByteArray.get! raw8 7)).toNat,
                                            c8,
                                            decide
                                              (4294967295 <
                                                (Wire.u64le? (ByteArray.get! raw8 0) (ByteArray.get! raw8 1)
                                                  (ByteArray.get! raw8 2) (ByteArray.get! raw8 3)
                                                  (ByteArray.get! raw8 4) (ByteArray.get! raw8 5)
                                                  (ByteArray.get! raw8 6) (ByteArray.get! raw8 7)).toNat)) := by
                                      exact h9'.symm
                                    have hBytesShift :=
                                      cursor_getBytes_between_of_success_cur pre daCoreBytes post cTag 8 raw8 c8 hU8Bs hBytesBase
                                    subst a9
                                    unfold Cursor.getCompactSize?
                                    rw [hU8Shift]
                                    simp [hTagSmall, hTag253, hTag254, hBytesShift, Nat.add_assoc]
                        refine ⟨(a9.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a9.2.fst.off }, a9.2.snd), ?_, ?_⟩
                        · simpa [Nat.add_assoc] using hCompactShift
                        · rw [hMinTrue]
                          simp [DaCoreV1.requireMinimal]
                          split at hTail
                          · simp at hTail
                          · rename_i hSigGuardFalse
                            simp [hSigGuardFalse, Nat.add_assoc] at hTail ⊢
                            have hCompactBs : a9.2.fst.bs = daCoreBytes := by
                              calc
                                a9.2.fst.bs = a8.snd.bs := by
                                  exact cursor_getCompactSize_preserves_bs_local a8.snd a9.fst a9.2.fst a9.2.snd h9
                                _ = daCoreBytes := h8Bs
                            rcases hTail with ⟨a10, h10, hEqA⟩
                            have h10s :=
                              cursor_getBytes_between_of_success_cur
                                pre daCoreBytes post a9.2.fst a9.fst a10.fst a10.snd hCompactBs h10
                            have hAcur : a10.snd = a.fst := by
                              simpa using congrArg Prod.fst hEqA
                            have hAend : a10.snd.off = daCoreBytes.size := by
                              calc
                                a10.snd.off = a.fst.off := by simpa [hAcur]
                                _ = daCoreBytes.size := hOff
                            refine ⟨(a10.fst, { bs := pre ++ daCoreBytes ++ post, off := pre.size + a10.snd.off }), ?_, ?_⟩
                            · simpa [Nat.add_assoc] using h10s
                            · constructor
                              · simp [Nat.add_assoc, hAend]
                              · simpa [Nat.add_assoc, hAend] using Nat.add_sub_cancel_left pre.size a10.snd.off

end UtxoBasicV1

end RubinFormal

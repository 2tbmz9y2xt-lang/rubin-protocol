import RubinFormal.UtxoBasicV1
import RubinFormal.TxWirePrefixLemmas

set_option maxHeartbeats 8000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private theorem cursor_getCompactSize_after_pre_three_bytes
    (pre rest : Bytes)
    (b0 b1 : UInt8)
    (hMin : 0xfd ≤ Wire.u16le? b0 b1) :
    ({ bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest), off := pre.size } : Cursor).getCompactSize? =
      some
        (Wire.u16le? b0 b1,
          { bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest),
            off := pre.size + 3 },
          true) := by
  have hU8 :
      ({ bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest), off := pre.size } : Cursor).getU8? =
        some
          (0xfd,
            { bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest),
              off := pre.size + 1 }) := by
    exact
      (cursor_getU8_after_pre_exact
        (pre := pre)
        (post := RubinFormal.bytes #[b0, b1] ++ rest)
        (b := (0xfd : UInt8)))
  have hBytes :
      ({ bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest), off := pre.size + 1 } : Cursor).getBytes? 2 =
        some
          (RubinFormal.bytes #[b0, b1],
            { bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest),
              off := pre.size + 3 }) := by
    have hPrefixSize : (pre ++ RubinFormal.bytes #[0xfd]).size = pre.size + 1 := by
      simp [RubinFormal.bytes, ByteArray.size, Array.size_append, Nat.add_assoc]
    have hRaw :=
      (cursor_getBytes_after_pre_nested_exact
        (pre := pre ++ RubinFormal.bytes #[0xfd])
        (mid := RubinFormal.bytes #[b0, b1])
        (post := rest)
        (n := 2)
        (by rfl))
    have hRaw' := hRaw
    rw [hPrefixSize] at hRaw'
    simpa [Nat.add_assoc] using hRaw'
  exact compactSize_from_three_byte_prefix
    (c := { bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest), off := pre.size })
    (c1 := { bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest), off := pre.size + 1 })
    (c2 := { bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest), off := pre.size + 3 })
    (b0 := b0) (b1 := b1) hU8 hBytes hMin

set_option maxHeartbeats 20000000 in
theorem cursor_getCompactSize_after_pre_three
    (pre rest : Bytes)
    (n : Nat)
    (hOne : ¬ n < 0xfd)
    (hThree : n ≤ 0xffff) :
    ({ bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size } : Cursor).getCompactSize? =
      some
        (n,
          { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest,
            off := pre.size + 3 },
          true) := by
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  have hVal : Wire.u16le? b0 b1 = n := by
    simpa [b0, b1] using u16le_ofNat_roundtrip n hThree
  have hMin : 0xfd ≤ Wire.u16le? b0 b1 := by
    simpa [hVal] using Nat.not_lt.mp hOne
  have hCompactDef :
      RubinFormal.WireEnc.compactSize n =
        RubinFormal.bytes #[0xfd] ++ RubinFormal.bytes #[b0, b1] := by
    have hTag : ByteArray.push ByteArray.empty (0xfd : UInt8) = RubinFormal.bytes #[0xfd] := by
      rfl
    rw [RubinFormal.WireEnc.compactSize]
    simp [hOne, hThree]
    rw [hTag]
    rfl
  have hAssoc :
      pre ++ (RubinFormal.bytes #[0xfd] ++ RubinFormal.bytes #[b0, b1]) ++ rest =
        pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest) := by
    cases pre
    rename_i preData
    cases rest
    rename_i restData
    ext
    simp [RubinFormal.bytes, ByteArray.append, ByteArray.copySlice, ByteArray.extract, Array.append_assoc]
  have hThreeBytes :
      ({ bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest), off := pre.size } : Cursor).getCompactSize? =
        some
          (Wire.u16le? b0 b1,
            { bs := pre ++ RubinFormal.bytes #[0xfd] ++ (RubinFormal.bytes #[b0, b1] ++ rest),
              off := pre.size + 3 },
            true) := cursor_getCompactSize_after_pre_three_bytes pre rest b0 b1 hMin
  rw [hCompactDef]
  rw [hAssoc]
  simpa [hVal] using hThreeBytes

end UtxoBasicV1

end RubinFormal

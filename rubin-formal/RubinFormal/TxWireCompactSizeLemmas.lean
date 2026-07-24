import RubinFormal.UtxoBasicV1
import RubinFormal.TxWirePrefixLemmas
import RubinFormal.TxWireCompactSizeThreeLemmas
import RubinFormal.TxWireCompactSizeNineLemmas
import Std.Tactic.Omega

set_option maxHeartbeats 8000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private theorem cursor_getCompactSize_after_pre_one
    (pre rest : Bytes)
    (n : Nat)
    (hOne : n < 0xfd) :
    ({ bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size } : Cursor).getCompactSize? =
      some
        (n,
          { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest,
            off := pre.size + 1 },
          true) := by
  have hU8 :
      ({ bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size } : Cursor).getU8? =
        some
          (UInt8.ofNat n,
            { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size + 1 }) := by
      simpa [RubinFormal.WireEnc.compactSize, hOne] using
        cursor_getU8_after_pre_exact pre rest (UInt8.ofNat n)
  have hTagEq : (UInt8.ofNat n).toNat = n := by
    exact uint8_ofNat_toNat_eq n (Nat.lt_of_lt_of_le hOne (by decide))
  have hTag : (UInt8.ofNat n).toNat < 0xfd := by
    simpa [hTagEq] using hOne
  have hMain :=
    compactSize_from_single_byte
      (c := { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size })
      (c' := { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size + 1 })
      (b := UInt8.ofNat n)
      hU8 hTag
  simpa [hTagEq] using hMain

private theorem cursor_getCompactSize_after_pre_five
    (pre rest : Bytes)
    (n : Nat)
    (hOne : ¬ n < 0xfd)
    (hThree : ¬ n ≤ 0xffff)
    (hFive : n ≤ 0xffffffff) :
    ({ bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size } : Cursor).getCompactSize? =
      some
        (n,
          { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest,
            off := pre.size + 5 },
          true) := by
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
  let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
  have hCompactDef :
      RubinFormal.WireEnc.compactSize n =
        RubinFormal.bytes #[0xfe] ++ RubinFormal.bytes #[b0, b1, b2, b3] := by
    have hTag : ByteArray.push ByteArray.empty (0xfe : UInt8) = RubinFormal.bytes #[0xfe] := by
      rfl
    rw [RubinFormal.WireEnc.compactSize]
    simp [hOne, hThree, hFive, b0, b1, b2, b3, RubinFormal.WireEnc.u32le, RubinFormal.bytes]
    rw [hTag]
    rfl
  have hU8 :
      ({ bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size } : Cursor).getU8? =
        some
          (0xfe,
            { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size + 1 }) := by
      rw [hCompactDef]
      rw [cursor_bytes_append_assoc pre (RubinFormal.bytes #[0xfe]) (RubinFormal.bytes #[b0, b1, b2, b3]) rest]
      exact cursor_getU8_after_pre_exact pre (RubinFormal.bytes #[b0, b1, b2, b3] ++ rest) (0xfe : UInt8)
  have hBytes :
      ({ bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size + 1 } : Cursor).getBytes? 4 =
        some
          (RubinFormal.bytes #[b0, b1, b2, b3],
            { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size + 5 }) := by
    have hPrefixSize : (pre ++ RubinFormal.bytes #[0xfe]).size = pre.size + 1 := by
      simp [RubinFormal.bytes, ByteArray.size, Array.size_append, Nat.add_assoc]
    have hRaw :=
      (cursor_getBytes_after_pre_nested_exact
        (pre := pre ++ RubinFormal.bytes #[0xfe])
        (mid := RubinFormal.bytes #[b0, b1, b2, b3])
        (post := rest)
        (n := 4)
        (by rfl))
    have hRaw' := hRaw
    rw [hPrefixSize] at hRaw'
    rw [hCompactDef]
    rw [cursor_bytes_append_assoc pre (RubinFormal.bytes #[0xfe]) (RubinFormal.bytes #[b0, b1, b2, b3]) rest]
    simpa [Nat.add_assoc] using hRaw'
  have hMin :
      0xffff <
        Wire.u32le? b0 b1 b2 b3 := by
    simpa [b0, b1, b2, b3, u32le_ofNat_roundtrip n hFive] using Nat.lt_of_not_ge hThree
  have hMain :=
    compactSize_from_five_byte_prefix
      (c := { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size })
      (c1 := { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size + 1 })
      (c2 := { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size + 5 })
      b0 b1 b2 b3 hU8 hBytes hMin
  simpa [b0, b1, b2, b3, u32le_ofNat_roundtrip n hFive] using hMain

theorem cursor_getCompactSize_after_pre
    (pre rest : Bytes)
    (n : Nat)
    (hBound : n ≤ UInt64.size - 1) :
    ({ bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size } : Cursor).getCompactSize? =
      some
        (n,
          { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest,
            off := pre.size + (RubinFormal.WireEnc.compactSize n).size },
          true) := by
  by_cases hOne : n < 0xfd
  · simpa [RubinFormal.WireEnc.compactSize, hOne] using
      cursor_getCompactSize_after_pre_one pre rest n hOne
  · by_cases hThree : n ≤ 0xffff
    · simpa [RubinFormal.WireEnc.compactSize, hOne, hThree] using
        cursor_getCompactSize_after_pre_three pre rest n hOne hThree
    · by_cases hFive : n ≤ 0xffffffff
      · simpa [RubinFormal.WireEnc.compactSize, hOne, hThree, hFive] using
          cursor_getCompactSize_after_pre_five pre rest n hOne hThree hFive
      · simpa [RubinFormal.WireEnc.compactSize, hOne, hThree, hFive] using
          cursor_getCompactSize_after_pre_nine pre rest n hOne hThree hFive hBound

end UtxoBasicV1

end RubinFormal

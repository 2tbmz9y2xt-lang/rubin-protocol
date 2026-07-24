import RubinFormal.UtxoBasicV1
import RubinFormal.TxWirePrefixLemmas
import RubinFormal.TxWireCompactSizeNineByteLemmas
import Std.Tactic.Omega

set_option maxHeartbeats 8000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem cursor_getCompactSize_after_pre_nine
    (pre rest : Bytes)
    (n : Nat)
    (hOne : ¬ n < 0xfd)
    (hThree : ¬ n ≤ 0xffff)
    (hFive : ¬ n ≤ 0xffffffff)
    (hBound : n ≤ UInt64.size - 1) :
    ({ bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest, off := pre.size } : Cursor).getCompactSize? =
      some
        (n,
          { bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest,
            off := pre.size + 9 },
          true) := by
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
  let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
  let b4 : UInt8 := UInt8.ofNat ((n / 4294967296) % 256)
  let b5 : UInt8 := UInt8.ofNat ((n / 1099511627776) % 256)
  let b6 : UInt8 := UInt8.ofNat ((n / 281474976710656) % 256)
  let b7 : UInt8 := UInt8.ofNat ((n / 72057594037927936) % 256)
  have hCompact :
      RubinFormal.WireEnc.compactSize n =
        RubinFormal.bytes #[0xff] ++ RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7] := by
    have hTag : ByteArray.push ByteArray.empty (0xff : UInt8) = RubinFormal.bytes #[0xff] := by
      rfl
    simp [RubinFormal.WireEnc.compactSize, RubinFormal.WireEnc.u64le,
      b0, b1, b2, b3, b4, b5, b6, b7, hOne, hThree, hFive]
    rw [hTag]
  have hRoundU64 :
      Wire.u64le? b0 b1 b2 b3 b4 b5 b6 b7 = UInt64.ofNat n := by
    simpa [b0, b1, b2, b3, b4, b5, b6, b7] using u64le_ofNat_roundtrip n hBound
  have hNatLt : n < UInt64.size := by
    omega
  have hRound : (Wire.u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat = n := by
    rw [hRoundU64]
    simp [UInt64.ofNat, UInt64.toNat, Fin.ofNat, Nat.mod_eq_of_lt hNatLt]
  have hMin :
      0xffffffff < (Wire.u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat := by
    simpa [hRound] using Nat.lt_of_not_ge hFive
  have hMain :
      ({ bs := pre ++ RubinFormal.bytes #[0xff] ++ RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7] ++ rest,
         off := pre.size } : Cursor).getCompactSize? =
        some
          ((Wire.u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat,
            { bs := pre ++ RubinFormal.bytes #[0xff] ++ RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7] ++ rest,
              off := pre.size + 9 },
            true) :=
    cursor_getCompactSize_after_pre_nine_bytes pre rest b0 b1 b2 b3 b4 b5 b6 b7 hMin
  have hAssoc :
      pre ++ (RubinFormal.bytes #[0xff] ++ RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7]) ++ rest =
        pre ++ RubinFormal.bytes #[0xff] ++ RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7] ++ rest := by
    cases pre
    cases rest
    ext
    simp [ByteArray.append, Array.append_assoc]
  rw [← hAssoc] at hMain
  rw [hRound] at hMain
  rw [hCompact]
  exact hMain

end UtxoBasicV1

end RubinFormal

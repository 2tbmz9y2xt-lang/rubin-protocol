import RubinFormal.UtxoBasicV1
import RubinFormal.TxWireCompactSizeNineMidLemmas
import Std.Tactic.Omega

set_option maxHeartbeats 8000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem cursor_getCompactSize_after_pre_nine_bytes
    (pre rest : Bytes)
    (b0 b1 b2 b3 b4 b5 b6 b7 : UInt8)
    (hMin : 0xffffffff < (Wire.u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat) :
    ({ bs := pre ++ RubinFormal.bytes #[0xff] ++ RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7] ++ rest,
       off := pre.size } : Cursor).getCompactSize? =
      some
        ((Wire.u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat,
          { bs := pre ++ RubinFormal.bytes #[0xff] ++ RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7] ++ rest,
            off := pre.size + 9 },
          true) := by
  let mid : Bytes := RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7]
  have hU8 :
      ({ bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest, off := pre.size } : Cursor).getU8? =
        some (0xff, { bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest, off := pre.size + 1 }) :=
    cursor_getCompactSize_after_pre_nine_tag_mid pre mid rest
  have hBytes :
      ({ bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest, off := pre.size + 1 } : Cursor).getBytes? 8 =
        some (mid, { bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest, off := pre.size + 9 }) :=
    cursor_getCompactSize_after_pre_nine_payload_mid pre mid rest (by
      simp [mid, RubinFormal.bytes, ByteArray.size])
  have hMain :=
    compactSize_from_nine_byte_prefix
      (c := { bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest, off := pre.size })
      (c1 := { bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest, off := pre.size + 1 })
      (c2 := { bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest, off := pre.size + 9 })
      b0 b1 b2 b3 b4 b5 b6 b7
      (by simpa [mid] using hU8)
      (by simpa [mid] using hBytes)
      hMin
  simpa [mid] using hMain

end UtxoBasicV1

end RubinFormal

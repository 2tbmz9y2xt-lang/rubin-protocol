import RubinFormal.UtxoBasicV1
import RubinFormal.TxWirePrefixLemmas
import Std.Tactic.Omega

set_option maxHeartbeats 8000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem cursor_getCompactSize_after_pre_nine_tag_mid
    (pre mid rest : Bytes) :
    ({ bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest, off := pre.size } : Cursor).getU8? =
      some
        (0xff,
          { bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest,
            off := pre.size + 1 }) := by
  simp [Cursor.getU8?]
  constructor
  · have hPos : 0 < 1 + (Array.size mid.data + Array.size rest.data) := by
      omega
    have hLt : Array.size pre.data < Array.size pre.data + (1 + (Array.size mid.data + Array.size rest.data)) := by
      exact Nat.lt_add_of_pos_right hPos
    simpa [RubinFormal.bytes, ByteArray.size, Array.size_append, Nat.add_assoc] using hLt
  · have hPos : 0 < 1 + (Array.size mid.data + Array.size rest.data) := by
      omega
    have hAll : Array.size pre.data < Array.size (pre.data ++ (#[255] ++ (mid.data ++ rest.data))) := by
      have hLt : Array.size pre.data < Array.size pre.data + (1 + (Array.size mid.data + Array.size rest.data)) := by
        exact Nat.lt_add_of_pos_right hPos
      simpa [Array.size_append, Nat.add_assoc] using hLt
    have hMid : 0 < Array.size (#[255] ++ (mid.data ++ rest.data)) := by
      simpa [Array.size_append, Nat.add_assoc] using hPos
    have hAppendRight :
        (pre.data ++ (#[255] ++ (mid.data ++ rest.data)))[Array.size pre.data] =
          (#[255] ++ (mid.data ++ rest.data))[0] := by
      simpa [Array.append_assoc] using
        (Array.get_append_right (as := pre.data) (bs := #[255] ++ (mid.data ++ rest.data)) (i := Array.size pre.data)
          (h := by simpa [Array.append_assoc] using hAll)
          (by exact Nat.le_refl _))
    have hHead : (#[255] ++ (mid.data ++ rest.data))[0] = 255 := by
      simpa using
        (Array.get_append_left (as := #[(0xff : UInt8)]) (bs := mid.data ++ rest.data) (i := 0)
          (h := hMid)
          (by simp))
    calc
      ByteArray.get! ({ data := pre.data } ++ { data := #[255] } ++ { data := mid.data } ++ { data := rest.data }) (Array.size pre.data)
        = Option.getD ((pre.data ++ (#[255] ++ (mid.data ++ rest.data)))[Array.size pre.data]?) default := by
            simp [ByteArray.get!, getElem!, hAll, Array.append_assoc]
      _ = (pre.data ++ (#[255] ++ (mid.data ++ rest.data)))[Array.size pre.data] := by
            simp [getElem?, hAll]
      _ = (#[255] ++ (mid.data ++ rest.data))[0] := hAppendRight
      _ = 255 := hHead

theorem cursor_getCompactSize_after_pre_nine_payload_mid
    (pre mid rest : Bytes)
    (hMid : mid.size = 8) :
    ({ bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest, off := pre.size + 1 } : Cursor).getBytes? 8 =
      some
        (mid,
          { bs := pre ++ RubinFormal.bytes #[0xff] ++ mid ++ rest,
            off := pre.size + 9 }) := by
  have hPrefixSize : (pre ++ RubinFormal.bytes #[0xff]).size = pre.size + 1 := by
    simp [RubinFormal.bytes, ByteArray.size, Array.size_append, Nat.add_assoc]
  have hRaw :=
    (cursor_getBytes_after_pre_nested_exact
      (pre := pre ++ RubinFormal.bytes #[0xff])
      (mid := mid)
      (post := rest)
      (n := 8)
      hMid)
  have hRaw' := hRaw
  rw [hPrefixSize] at hRaw'
  have hAssoc :
      (pre ++ RubinFormal.bytes #[0xff]) ++ mid ++ rest =
        pre ++ RubinFormal.bytes #[0xff] ++ (mid ++ rest) := by
    cases pre
    cases mid
    cases rest
    ext
    simp [ByteArray.append, Array.append_assoc]
  simpa [Nat.add_assoc, hAssoc] using hRaw'

end UtxoBasicV1

end RubinFormal

import RubinFormal.TxWirePrefixLemmas

set_option maxHeartbeats 50000000
set_option maxRecDepth 8192

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem extract_after_pre_exact
    (pre mid post : Bytes) :
    (pre ++ mid ++ post).extract pre.size (pre.size + mid.size) = mid := by
  have h :
      Cursor.getBytes? { bs := pre ++ mid ++ post, off := pre.size } mid.size =
        some
          (mid,
            { bs := pre ++ mid ++ post, off := pre.size + mid.size }) := by
    exact
      cursor_getBytes_after_pre_exact
        (pre := pre)
        (mid := mid)
        (post := post)
        (n := mid.size)
        (by rfl)
  simp [Cursor.getBytes?, ByteArray.extract, ByteArray.copySlice, ByteArray.size] at h
  rcases h with ⟨_, hEq⟩
  simpa [ByteArray.extract, ByteArray.copySlice, ByteArray.size] using hEq

end UtxoBasicV1

end RubinFormal

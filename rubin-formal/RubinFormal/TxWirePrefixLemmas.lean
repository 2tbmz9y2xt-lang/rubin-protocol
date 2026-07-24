import RubinFormal.UtxoBasicV1
import Std.Tactic.Omega

set_option maxHeartbeats 8000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem cursor_bytes_append_assoc
    (pre a b rest : Bytes) :
    pre ++ (a ++ b) ++ rest = pre ++ a ++ (b ++ rest) := by
  cases pre
  rename_i preData
  cases a
  rename_i aData
  cases b
  rename_i bData
  cases rest
  rename_i restData
  ext
  simp [ByteArray.append, ByteArray.copySlice, ByteArray.extract, Array.append_assoc]

theorem cursor_bytes_left_assoc
    (a b c : Bytes) :
    a ++ b ++ c = a ++ (b ++ c) := by
  cases a
  rename_i aData
  cases b
  rename_i bData
  cases c
  rename_i cData
  ext
  simp [ByteArray.append, ByteArray.copySlice, ByteArray.extract, Array.append_assoc]

theorem cursor_getBytes_prefix_exact
    (pre rest : Bytes)
    (n : Nat)
    (hSize : pre.size = n) :
    ({ bs := pre ++ rest, off := 0 } : Cursor).getBytes? n =
      some (pre, { bs := pre ++ rest, off := n }) := by
  cases pre
  rename_i preData
  cases rest
  rename_i restData
  simp [Cursor.getBytes?, ByteArray.extract, ByteArray.copySlice, ByteArray.size] at hSize ⊢
  constructor
  · simpa [Array.size_append, hSize] using (Nat.le_add_right n (Array.size restData))
  · apply Array.ext
    · have hLe : n ≤ n + Array.size restData := Nat.le_add_right n (Array.size restData)
      simp [Array.size_extract, Array.size_append, hSize, Nat.min_eq_left hLe]
    · intro i hLeft hRight
      rw [Array.get_extract]
      · simpa using
          (Array.get_append_left (as := preData) (bs := restData) (i := i)
            (h := by
              exact Nat.lt_of_lt_of_le hLeft (by
                have hLe : n ≤ n + Array.size restData := Nat.le_add_right n (Array.size restData)
                simpa [Array.size_extract, Array.size_append, hSize, Nat.min_eq_left hLe]))
            (by simpa [hSize] using hRight))

theorem cursor_getBytes_after_pre_exact
    (pre mid post : Bytes)
    (n : Nat)
    (hMid : mid.size = n) :
    ({ bs := pre ++ mid ++ post, off := pre.size } : Cursor).getBytes? n =
      some (mid, { bs := pre ++ mid ++ post, off := pre.size + n }) := by
  cases pre
  rename_i preData
  cases mid
  rename_i midData
  cases post
  rename_i postData
  simp [Cursor.getBytes?, ByteArray.extract, ByteArray.copySlice, ByteArray.size] at hMid ⊢
  constructor
  · simpa [Array.size_append, hMid, Nat.add_assoc] using
      (Nat.le_add_right (Array.size preData + n) (Array.size postData))
  · apply Array.ext
    · have hSub : Array.size preData + n - Array.size preData = n := by omega
      have hLe' : Array.size preData + n ≤ Array.size preData + n + Array.size postData := by
        exact Nat.le_add_right (Array.size preData + n) (Array.size postData)
      have hMin :
          min (Array.size preData + n) (Array.size preData + (n + Array.size postData)) =
            Array.size preData + n := by
        apply Nat.min_eq_left
        simpa [Nat.add_assoc] using hLe'
      simpa [Array.size_extract, Array.size_append, hMid, hSub, Nat.add_assoc, hMin]
    · intro i hLeft hRight
      rw [Array.get_extract]
      · have hAll : Array.size preData + i < Array.size (preData ++ midData ++ postData) := by
          exact Nat.lt_of_lt_of_le
            (Nat.add_lt_add_left hRight (Array.size preData))
            (by simpa [Array.size_append, hMid, Nat.add_assoc] using
              (Nat.le_add_right (Array.size preData + n) (Array.size postData)))
        have hMidPost : i < Array.size (midData ++ postData) := by
          exact Nat.lt_of_lt_of_le hRight (by simpa [Array.size_append, hMid] using Nat.le_add_right n (Array.size postData))
        have hAppendRight :
            (preData ++ midData ++ postData)[Array.size preData + i]'hAll =
              (midData ++ postData)[i]'hMidPost := by
          simpa [Array.append_assoc, Nat.add_assoc, Nat.add_sub_cancel_left] using
            (Array.get_append_right (as := preData) (bs := midData ++ postData) (i := Array.size preData + i)
              (h := by simpa [Array.append_assoc] using hAll)
              (by exact Nat.le_add_right _ _))
        rw [show (preData ++ midData ++ postData)[Array.size preData + i]'hAll =
            (midData ++ postData)[i]'hMidPost by exact hAppendRight]
        simpa [hMid, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm] using
          (Array.get_append_left (as := midData) (bs := postData) (i := i)
            (h := hMidPost)
            (by simpa [hMid] using hRight))

theorem cursor_getBytes_after_pre_nested_exact
    (pre mid post : Bytes)
    (n : Nat)
    (hMid : mid.size = n) :
    ({ bs := pre ++ (mid ++ post), off := pre.size } : Cursor).getBytes? n =
      some (mid, { bs := pre ++ (mid ++ post), off := pre.size + n }) := by
  cases pre
  rename_i preData
  cases mid
  rename_i midData
  cases post
  rename_i postData
  simp [Cursor.getBytes?, ByteArray.extract, ByteArray.copySlice, ByteArray.size] at hMid ⊢
  constructor
  · simpa [Array.size_append, hMid, Nat.add_assoc] using
      (Nat.le_add_right (Array.size preData + n) (Array.size postData))
  · apply Array.ext
    · have hSub : Array.size preData + n - Array.size preData = n := by omega
      have hLe' : Array.size preData + n ≤ Array.size preData + n + Array.size postData := by
        exact Nat.le_add_right (Array.size preData + n) (Array.size postData)
      have hMin :
          min (Array.size preData + n) (Array.size preData + (n + Array.size postData)) =
            Array.size preData + n := by
        apply Nat.min_eq_left
        simpa [Nat.add_assoc] using hLe'
      simpa [Array.size_extract, Array.size_append, hMid, hSub, Nat.add_assoc, hMin]
    · intro i hLeft hRight
      rw [Array.get_extract]
      · have hAll : Array.size preData + i < Array.size (preData ++ (midData ++ postData)) := by
          exact Nat.lt_of_lt_of_le
            (Nat.add_lt_add_left hRight (Array.size preData))
            (by simpa [Array.size_append, hMid, Nat.add_assoc] using
              (Nat.le_add_right (Array.size preData + n) (Array.size postData)))
        have hMidPost : i < Array.size (midData ++ postData) := by
          exact Nat.lt_of_lt_of_le hRight (by simpa [Array.size_append, hMid] using Nat.le_add_right n (Array.size postData))
        have hAppendRight :
            (preData ++ (midData ++ postData))[Array.size preData + i]'hAll =
              (midData ++ postData)[i]'hMidPost := by
          simpa [Nat.add_assoc, Nat.add_sub_cancel_left] using
            (Array.get_append_right (as := preData) (bs := midData ++ postData) (i := Array.size preData + i)
              (h := hAll)
              (by exact Nat.le_add_right _ _))
        rw [show (preData ++ (midData ++ postData))[Array.size preData + i]'hAll =
            (midData ++ postData)[i]'hMidPost by exact hAppendRight]
        simpa [hMid, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm] using
          (Array.get_append_left (as := midData) (bs := postData) (i := i)
            (h := hMidPost)
            (by simpa [hMid] using hRight))


theorem cursor_getU8_after_pre_exact
    (pre post : Bytes)
    (b : UInt8) :
    ({ bs := pre ++ RubinFormal.bytes #[b] ++ post, off := pre.size } : Cursor).getU8? =
      some (b, { bs := pre ++ RubinFormal.bytes #[b] ++ post, off := pre.size + 1 }) := by
  cases pre
  rename_i preData
  cases post
  rename_i postData
  simp [Cursor.getU8?, RubinFormal.bytes, ByteArray.size]
  constructor
  · have hPos : 0 < 1 + Array.size postData := by
        omega
    have hLt : Array.size preData < Array.size preData + (1 + Array.size postData) := by
        exact Nat.lt_add_of_pos_right hPos
    simpa [Array.size_append, Nat.add_assoc] using hLt
  · have hAll : Array.size preData < Array.size (preData ++ #[b] ++ postData) := by
        have hPos : 0 < 1 + Array.size postData := by
          omega
        have hLt : Array.size preData < Array.size preData + (1 + Array.size postData) := by
          exact Nat.lt_add_of_pos_right hPos
        simpa [Array.size_append, Nat.add_assoc] using hLt
    have hMid : 0 < Array.size (#[b] ++ postData) := by
      have hPos : 0 < 1 + Array.size postData := by omega
      simpa [Array.size_append, Nat.add_comm] using hPos
    have hAppendRight :
        (preData ++ #[b] ++ postData)[Array.size preData] =
          (#[b] ++ postData)[0] := by
      simpa [Array.append_assoc] using
        (Array.get_append_right (as := preData) (bs := #[b] ++ postData) (i := Array.size preData)
          (h := by simpa [Array.append_assoc] using hAll)
          (by exact Nat.le_refl _))
    have hSome :
        (preData ++ #[b] ++ postData)[Array.size preData]? =
          some ((preData ++ #[b] ++ postData)[Array.size preData]) := by
      simp [getElem?, hAll]
    have hHead : (#[b] ++ postData)[0] = b := by
      simpa using
        (Array.get_append_left (as := #[b]) (bs := postData) (i := 0)
          (h := hMid)
          (by simp))
    calc
      ByteArray.get! ({ data := preData } ++ { data := #[b] } ++ { data := postData }) (Array.size preData)
        = Option.getD ((preData ++ #[b] ++ postData)[Array.size preData]?) default := by
            simp [ByteArray.get!, getElem!, hAll]
      _ = (preData ++ #[b] ++ postData)[Array.size preData] := by
            simp [hSome]
      _ = (#[b] ++ postData)[0] := hAppendRight
      _ = b := hHead

theorem uint8_ofNat_toNat_eq (n : Nat) (h : n < 256) :
    (UInt8.ofNat n).toNat = n := by
  simp [UInt8.ofNat, UInt8.toNat, Fin.ofNat, Nat.mod_eq_of_lt h]

theorem u16le_ofNat_roundtrip (n : Nat) (h : n ≤ 0xffff) :
    Wire.u16le? (UInt8.ofNat (n % 256)) (UInt8.ofNat ((n / 256) % 256)) = n := by
  have h0 : n % 256 < 256 := Nat.mod_lt _ (by decide)
  have h1div : n / 256 < 256 := by omega
  have h1 : (UInt8.ofNat ((n / 256) % 256)).toNat = n / 256 := by
    simpa [Nat.mod_eq_of_lt h1div] using
      uint8_ofNat_toNat_eq ((n / 256) % 256) (Nat.mod_lt _ (by decide))
  calc
    Wire.u16le? (UInt8.ofNat (n % 256)) (UInt8.ofNat ((n / 256) % 256))
      = (UInt8.ofNat (n % 256)).toNat + ((UInt8.ofNat ((n / 256) % 256)).toNat <<< 8) := by
          rfl
    _ = n % 256 + ((n / 256) <<< 8) := by
          rw [uint8_ofNat_toNat_eq (n % 256) h0, h1]
    _ = n % 256 + (n / 256) * 256 := by
          rw [Nat.shiftLeft_eq, show 2 ^ 8 = 256 by decide]
    _ = n := by
          simpa [Nat.mul_comm] using Nat.mod_add_div n 256

theorem u32le_ofNat_roundtrip (n : Nat) (h : n ≤ 0xffffffff) :
    Wire.u32le?
      (UInt8.ofNat (n % 256))
      (UInt8.ofNat ((n / 256) % 256))
      (UInt8.ofNat ((n / 65536) % 256))
      (UInt8.ofNat ((n / 16777216) % 256)) = n := by
  have h0 : n % 256 < 256 := Nat.mod_lt _ (by decide)
  have h1 : (n / 256) % 256 < 256 := Nat.mod_lt _ (by decide)
  have h2 : (n / 65536) % 256 < 256 := Nat.mod_lt _ (by decide)
  have h3div : n / 16777216 < 256 := by omega
  have h3 : (UInt8.ofNat ((n / 16777216) % 256)).toNat = n / 16777216 := by
    simpa [Nat.mod_eq_of_lt h3div] using
      uint8_ofNat_toNat_eq ((n / 16777216) % 256) (Nat.mod_lt _ (by decide))
  have hq1 : (n / 256) % 256 + 256 * (n / 65536) = n / 256 := by
    simpa [Nat.div_div_eq_div_mul, Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc] using
      Nat.mod_add_div (n / 256) 256
  have hq2 : (n / 65536) % 256 + 256 * (n / 16777216) = n / 65536 := by
    simpa [Nat.div_div_eq_div_mul, Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc] using
      Nat.mod_add_div (n / 65536) 256
  have hFlatToNested :
      n % 256 +
      ((n / 256) % 256 * 256) +
      ((n / 65536) % 256 * 65536) +
      ((n / 16777216) * 16777216) =
      n % 256 + 256 * ((n / 256) % 256 + 256 * ((n / 65536) % 256 + 256 * (n / 16777216))) := by
    omega
  have hNestedEq :
      n % 256 + 256 * ((n / 256) % 256 + 256 * ((n / 65536) % 256 + 256 * (n / 16777216))) = n := by
    rw [hq2, hq1, Nat.mod_add_div]
  calc
    Wire.u32le?
      (UInt8.ofNat (n % 256))
      (UInt8.ofNat ((n / 256) % 256))
      (UInt8.ofNat ((n / 65536) % 256))
      (UInt8.ofNat ((n / 16777216) % 256))
      =
      n % 256 +
      ((n / 256) % 256 * 256) +
      ((n / 65536) % 256 * 65536) +
      ((n / 16777216) * 16777216) := by
          unfold Wire.u32le?
          rw [uint8_ofNat_toNat_eq (n % 256) h0]
          rw [uint8_ofNat_toNat_eq ((n / 256) % 256) h1]
          rw [uint8_ofNat_toNat_eq ((n / 65536) % 256) h2]
          rw [h3]
          rw [Nat.shiftLeft_eq, Nat.shiftLeft_eq, Nat.shiftLeft_eq]
          rw [show 2 ^ 8 = 256 by decide,
              show 2 ^ 16 = 65536 by decide,
              show 2 ^ 24 = 16777216 by decide]
    _ = n % 256 + 256 * ((n / 256) % 256 + 256 * ((n / 65536) % 256 + 256 * (n / 16777216))) := by
          exact hFlatToNested
    _ = n := hNestedEq

theorem u64_digits_nested_eq (n : Nat) (h : n ≤ UInt64.size - 1) :
    n % 256 +
      256 * ((n / 256) % 256 +
      256 * ((n / 65536) % 256 +
      256 * ((n / 16777216) % 256 +
      256 * ((n / 4294967296) % 256 +
      256 * ((n / 1099511627776) % 256 +
      256 * ((n / 281474976710656) % 256 +
      256 * ((n / 72057594037927936) % 256))))))) = n := by
  have hlt : n < UInt64.size := Nat.lt_of_le_of_lt h (by decide)
  have h7div : n / 72057594037927936 < 256 := by
    exact
      (Nat.div_lt_iff_lt_mul (x := n) (y := 256) (k := 72057594037927936) (by decide)).2
        (by simpa [UInt64.size, Nat.mul_comm] using hlt)
  have hq0 : n % 256 + 256 * (n / 256) = n := Nat.mod_add_div n 256
  have hq1 : (n / 256) % 256 + 256 * (n / 65536) = n / 256 := by
    simpa [Nat.div_div_eq_div_mul, Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc] using
      Nat.mod_add_div (n / 256) 256
  have hq2 : (n / 65536) % 256 + 256 * (n / 16777216) = n / 65536 := by
    simpa [Nat.div_div_eq_div_mul, Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc] using
      Nat.mod_add_div (n / 65536) 256
  have hq3 : (n / 16777216) % 256 + 256 * (n / 4294967296) = n / 16777216 := by
    simpa [Nat.div_div_eq_div_mul, Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc] using
      Nat.mod_add_div (n / 16777216) 256
  have hq4 : (n / 4294967296) % 256 + 256 * (n / 1099511627776) = n / 4294967296 := by
    simpa [Nat.div_div_eq_div_mul, Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc] using
      Nat.mod_add_div (n / 4294967296) 256
  have hq5 : (n / 1099511627776) % 256 + 256 * (n / 281474976710656) = n / 1099511627776 := by
    simpa [Nat.div_div_eq_div_mul, Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc] using
      Nat.mod_add_div (n / 1099511627776) 256
  have hq6 : (n / 281474976710656) % 256 + 256 * ((n / 72057594037927936) % 256) =
      n / 281474976710656 := by
    rw [Nat.mod_eq_of_lt h7div]
    simpa [Nat.div_div_eq_div_mul, Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc] using
      Nat.mod_add_div (n / 281474976710656) 256
  rw [hq6, hq5, hq4, hq3, hq2, hq1, hq0]

theorem u64_digits_flat_eq (n : Nat) (h : n ≤ UInt64.size - 1) :
    n % 256 +
    ((n / 256) % 256 * 256) +
    ((n / 65536) % 256 * 65536) +
    ((n / 16777216) % 256 * 16777216) +
    ((n / 4294967296) % 256 * 4294967296) +
    ((n / 1099511627776) % 256 * 1099511627776) +
    ((n / 281474976710656) % 256 * 281474976710656) +
    ((n / 72057594037927936) % 256 * 72057594037927936) = n := by
  have hNested := u64_digits_nested_eq n h
  have hFlatToNested :
      n % 256 +
      (n / 256 % 256) * 256 +
      (n / 65536 % 256) * 65536 +
      (n / 16777216 % 256) * 16777216 +
      (n / 4294967296 % 256) * 4294967296 +
      (n / 1099511627776 % 256) * 1099511627776 +
      (n / 281474976710656 % 256) * 281474976710656 +
      (n / 72057594037927936 % 256) * 72057594037927936 =
      n % 256 +
        256 * ((n / 256) % 256 +
        256 * ((n / 65536) % 256 +
        256 * ((n / 16777216) % 256 +
        256 * ((n / 4294967296) % 256 +
        256 * ((n / 1099511627776) % 256 +
        256 * ((n / 281474976710656) % 256 +
        256 * ((n / 72057594037927936) % 256))))))) := by
    omega
  exact hFlatToNested.trans hNested

theorem u64le_ofNat_roundtrip (n : Nat) (h : n ≤ UInt64.size - 1) :
    Wire.u64le?
      (UInt8.ofNat (n % 256))
      (UInt8.ofNat ((n / 256) % 256))
      (UInt8.ofNat ((n / 65536) % 256))
      (UInt8.ofNat ((n / 16777216) % 256))
      (UInt8.ofNat ((n / 4294967296) % 256))
      (UInt8.ofNat ((n / 1099511627776) % 256))
      (UInt8.ofNat ((n / 281474976710656) % 256))
      (UInt8.ofNat ((n / 72057594037927936) % 256)) = UInt64.ofNat n := by
  have hb0 : (UInt8.ofNat (n % 256)).toNat = n % 256 := by
    exact uint8_ofNat_toNat_eq _ (Nat.mod_lt _ (by decide))
  have hb1 : (UInt8.ofNat ((n / 256) % 256)).toNat = (n / 256) % 256 := by
    exact uint8_ofNat_toNat_eq _ (Nat.mod_lt _ (by decide))
  have hb2 : (UInt8.ofNat ((n / 65536) % 256)).toNat = (n / 65536) % 256 := by
    exact uint8_ofNat_toNat_eq _ (Nat.mod_lt _ (by decide))
  have hb3 : (UInt8.ofNat ((n / 16777216) % 256)).toNat = (n / 16777216) % 256 := by
    exact uint8_ofNat_toNat_eq _ (Nat.mod_lt _ (by decide))
  have hb4 : (UInt8.ofNat ((n / 4294967296) % 256)).toNat = (n / 4294967296) % 256 := by
    exact uint8_ofNat_toNat_eq _ (Nat.mod_lt _ (by decide))
  have hb5 : (UInt8.ofNat ((n / 1099511627776) % 256)).toNat = (n / 1099511627776) % 256 := by
    exact uint8_ofNat_toNat_eq _ (Nat.mod_lt _ (by decide))
  have hb6 : (UInt8.ofNat ((n / 281474976710656) % 256)).toNat = (n / 281474976710656) % 256 := by
    exact uint8_ofNat_toNat_eq _ (Nat.mod_lt _ (by decide))
  have hb7 : (UInt8.ofNat ((n / 72057594037927936) % 256)).toNat = (n / 72057594037927936) % 256 := by
    exact uint8_ofNat_toNat_eq _ (Nat.mod_lt _ (by decide))
  have hFlat := u64_digits_flat_eq n h
  calc
    Wire.u64le?
      (UInt8.ofNat (n % 256))
      (UInt8.ofNat ((n / 256) % 256))
      (UInt8.ofNat ((n / 65536) % 256))
      (UInt8.ofNat ((n / 16777216) % 256))
      (UInt8.ofNat ((n / 4294967296) % 256))
      (UInt8.ofNat ((n / 1099511627776) % 256))
      (UInt8.ofNat ((n / 281474976710656) % 256))
      (UInt8.ofNat ((n / 72057594037927936) % 256))
      =
      UInt64.ofNat (
        n % 256 +
        ((n / 256) % 256 * 256) +
        ((n / 65536) % 256 * 65536) +
        ((n / 16777216) % 256 * 16777216) +
        ((n / 4294967296) % 256 * 4294967296) +
        ((n / 1099511627776) % 256 * 1099511627776) +
        ((n / 281474976710656) % 256 * 281474976710656) +
        ((n / 72057594037927936) % 256 * 72057594037927936)) := by
          unfold Wire.u64le?
          rw [hb0, hb1, hb2, hb3, hb4, hb5, hb6, hb7]
          rw [Nat.shiftLeft_eq, Nat.shiftLeft_eq, Nat.shiftLeft_eq, Nat.shiftLeft_eq,
              Nat.shiftLeft_eq, Nat.shiftLeft_eq, Nat.shiftLeft_eq]
          rw [show 2 ^ 8 = 256 by decide,
              show 2 ^ 16 = 65536 by decide,
              show 2 ^ 24 = 16777216 by decide,
              show 2 ^ 32 = 4294967296 by decide,
              show 2 ^ 40 = 1099511627776 by decide,
              show 2 ^ 48 = 281474976710656 by decide,
              show 2 ^ 56 = 72057594037927936 by decide]
  _ = UInt64.ofNat n := by
        rw [hFlat]

theorem cursor_getU32le_prefix
    (n : Nat)
    (rest : Bytes)
    (h : n ≤ 0xffffffff) :
    ({ bs := RubinFormal.WireEnc.u32le n ++ rest, off := 0 } : Cursor).getU32le? =
      some (n, { bs := RubinFormal.WireEnc.u32le n ++ rest, off := 4 }) := by
  unfold Cursor.getU32le?
  rw [cursor_getBytes_prefix_exact (pre := RubinFormal.WireEnc.u32le n) (rest := rest) (n := 4) (by rfl)]
  simpa [RubinFormal.WireEnc.u32le] using u32le_ofNat_roundtrip n h

theorem cursor_getU32le_after_pre
    (pre rest : Bytes)
    (n : Nat)
    (h : n ≤ 0xffffffff) :
    ({ bs := pre ++ RubinFormal.WireEnc.u32le n ++ rest, off := pre.size } : Cursor).getU32le? =
      some (n, { bs := pre ++ RubinFormal.WireEnc.u32le n ++ rest, off := pre.size + 4 }) := by
  unfold Cursor.getU32le?
  rw [cursor_getBytes_after_pre_exact
    (pre := pre) (mid := RubinFormal.WireEnc.u32le n) (post := rest) (n := 4) (by rfl)]
  simpa [RubinFormal.WireEnc.u32le] using u32le_ofNat_roundtrip n h

theorem cursor_getU64le_prefix
    (n : Nat)
    (rest : Bytes)
    (h : n ≤ UInt64.size - 1) :
    ({ bs := RubinFormal.WireEnc.u64le n ++ rest, off := 0 } : Cursor).getU64le? =
      some (UInt64.ofNat n, { bs := RubinFormal.WireEnc.u64le n ++ rest, off := 8 }) := by
  unfold Cursor.getU64le?
  rw [cursor_getBytes_prefix_exact (pre := RubinFormal.WireEnc.u64le n) (rest := rest) (n := 8) (by rfl)]
  simpa [RubinFormal.WireEnc.u64le] using u64le_ofNat_roundtrip n h

theorem cursor_getU64le_after_pre
    (pre rest : Bytes)
    (n : Nat)
    (h : n ≤ UInt64.size - 1) :
    ({ bs := pre ++ RubinFormal.WireEnc.u64le n ++ rest, off := pre.size } : Cursor).getU64le? =
      some (UInt64.ofNat n, { bs := pre ++ RubinFormal.WireEnc.u64le n ++ rest, off := pre.size + 8 }) := by
  unfold Cursor.getU64le?
  rw [cursor_getBytes_after_pre_exact
    (pre := pre) (mid := RubinFormal.WireEnc.u64le n) (post := rest) (n := 8) (by rfl)]
  simpa [RubinFormal.WireEnc.u64le] using u64le_ofNat_roundtrip n h

theorem parseU16le_u16le
    (n : Nat)
    (h : n ≤ 0xffff) :
    parseU16le (RubinFormal.WireEnc.u16le n) = .ok n := by
  unfold parseU16le
  simp [RubinFormal.WireEnc.u16le]
  change Except.ok (Wire.u16le? (UInt8.ofNat (n % 256)) (UInt8.ofNat ((n / 256) % 256))) = Except.ok n
  exact congrArg (fun x : Nat => (Except.ok x : Except String Nat)) (u16le_ofNat_roundtrip n h)

end UtxoBasicV1

end RubinFormal

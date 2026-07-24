import RubinFormal.Types
import RubinFormal.OutputDescriptorV2
import Std.Tactic.Omega

namespace RubinFormal

namespace Wire

structure Cursor where
  bs : Bytes
  off : Nat

def Cursor.remaining (c : Cursor) : Nat :=
  c.bs.size - c.off

def Cursor.getU8? (c : Cursor) : Option (UInt8 × Cursor) :=
  if h : c.off < c.bs.size then
    let b := c.bs.get! c.off
    some (b, { c with off := c.off + 1 })
  else
    none

def Cursor.getBytes? (c : Cursor) (n : Nat) : Option (Bytes × Cursor) :=
  if c.off + n <= c.bs.size then
    let out := c.bs.extract c.off (c.off + n)
    some (out, { c with off := c.off + n })
  else
    none

def u16le? (b0 b1 : UInt8) : Nat :=
  (b0.toNat) + (b1.toNat <<< 8)

def u32le? (b0 b1 b2 b3 : UInt8) : Nat :=
  (b0.toNat) + (b1.toNat <<< 8) + (b2.toNat <<< 16) + (b3.toNat <<< 24)

def u64le? (b0 b1 b2 b3 b4 b5 b6 b7 : UInt8) : UInt64 :=
  UInt64.ofNat (
    b0.toNat +
    (b1.toNat <<< 8) +
    (b2.toNat <<< 16) +
    (b3.toNat <<< 24) +
    (b4.toNat <<< 32) +
    (b5.toNat <<< 40) +
    (b6.toNat <<< 48) +
    (b7.toNat <<< 56))

def Cursor.getU32le? (c : Cursor) : Option (Nat × Cursor) := do
  let (bs, c') ← c.getBytes? 4
  let b0 := bs.get! 0
  let b1 := bs.get! 1
  let b2 := bs.get! 2
  let b3 := bs.get! 3
  pure (u32le? b0 b1 b2 b3, c')

def Cursor.getU64le? (c : Cursor) : Option (UInt64 × Cursor) := do
  let (bs, c') ← c.getBytes? 8
  let b0 := bs.get! 0
  let b1 := bs.get! 1
  let b2 := bs.get! 2
  let b3 := bs.get! 3
  let b4 := bs.get! 4
  let b5 := bs.get! 5
  let b6 := bs.get! 6
  let b7 := bs.get! 7
  pure (u64le? b0 b1 b2 b3 b4 b5 b6 b7, c')

inductive TxErr where
  | parse
  | witnessOverflow
  | sigAlgInvalid
  | sigNoncanonical
deriving DecidableEq

def TxErr.toString : TxErr -> String
  | .parse => "TX_ERR_PARSE"
  | .witnessOverflow => "TX_ERR_WITNESS_OVERFLOW"
  | .sigAlgInvalid => "TX_ERR_SIG_ALG_INVALID"
  | .sigNoncanonical => "TX_ERR_SIG_NONCANONICAL"

structure ParseResult where
  ok : Bool
  err : Option TxErr
  txid : Option Bytes
  wtxid : Option Bytes

-- CompactSize (Varint) with minimality constraints (FIPS 202 spec section 3).
def Cursor.getCompactSize? (c : Cursor) : Option (Nat × Cursor × Bool) := do
  let (b, c1) ← c.getU8?
  let tag := b.toNat
  if tag < 0xfd then
    pure (tag, c1, true)
  else if tag == 0xfd then
    let (raw, c2) ← c1.getBytes? 2
    let n := u16le? (raw.get! 0) (raw.get! 1)
    let minimal := n >= 0xfd
    pure (n, c2, minimal)
  else if tag == 0xfe then
    let (raw, c2) ← c1.getBytes? 4
    let n := u32le? (raw.get! 0) (raw.get! 1) (raw.get! 2) (raw.get! 3)
    let minimal := n > 0xffff
    pure (n, c2, minimal)
  else
    let (raw, c2) ← c1.getBytes? 8
    let n64 := u64le? (raw.get! 0) (raw.get! 1) (raw.get! 2) (raw.get! 3) (raw.get! 4) (raw.get! 5) (raw.get! 6) (raw.get! 7)
    let n := n64.toNat
    let minimal := n > 0xffffffff
    pure (n, c2, minimal)

/-- Canonical CompactSize prefixes accepted by the v2 cursor decoder. -/
inductive CompactSizeCanonical : Bytes -> Nat -> Prop where
  | oneByte (b : UInt8) (h : b.toNat < 0xfd) (hBound : b.toNat ≤ UInt64.size - 1) :
      CompactSizeCanonical (RubinFormal.bytes #[b]) b.toNat
  | threeByte (b0 b1 : UInt8) (h : 0xfd ≤ u16le? b0 b1) (hBound : u16le? b0 b1 ≤ UInt64.size - 1) :
      CompactSizeCanonical (RubinFormal.bytes #[0xfd, b0, b1]) (u16le? b0 b1)
  | fiveByte (b0 b1 b2 b3 : UInt8)
      (h : 0xffff < u32le? b0 b1 b2 b3)
      (hBound : u32le? b0 b1 b2 b3 ≤ UInt64.size - 1) :
      CompactSizeCanonical (RubinFormal.bytes #[0xfe, b0, b1, b2, b3]) (u32le? b0 b1 b2 b3)
  | nineByte (b0 b1 b2 b3 b4 b5 b6 b7 : UInt8)
      (h : 0xffffffff < (u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat)
      (hBound : (u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat ≤ UInt64.size - 1) :
      CompactSizeCanonical
        (RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7])
        (u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat

theorem compactSize_from_single_byte
    {c c' : Cursor}
    (b : UInt8)
    (hU8 : c.getU8? = some (b, c'))
    (hTag : b.toNat < 0xfd) :
    c.getCompactSize? = some (b.toNat, c', true) := by
  unfold Cursor.getCompactSize?
  rw [hU8]
  simp [hTag]

theorem compactSize_from_three_byte_prefix
    {c c1 c2 : Cursor}
    (b0 b1 : UInt8)
    (hU8 : c.getU8? = some (0xfd, c1))
    (hBytes : c1.getBytes? 2 = some (RubinFormal.bytes #[b0, b1], c2))
    (hMin : 0xfd ≤ u16le? b0 b1) :
    c.getCompactSize? = some (u16le? b0 b1, c2, true) := by
  unfold Cursor.getCompactSize?
  rw [hU8]
  simp [hBytes, u16le?, hMin, show UInt8.toNat (0xfd : UInt8) = 253 by decide]
  constructor
  · rfl
  · simpa [u16le?] using hMin

theorem compactSize_from_five_byte_prefix
    {c c1 c2 : Cursor}
    (b0 b1 b2 b3 : UInt8)
    (hU8 : c.getU8? = some (0xfe, c1))
    (hBytes : c1.getBytes? 4 = some (RubinFormal.bytes #[b0, b1, b2, b3], c2))
    (hMin : 0xffff < u32le? b0 b1 b2 b3) :
    c.getCompactSize? = some (u32le? b0 b1 b2 b3, c2, true) := by
  unfold Cursor.getCompactSize?
  rw [hU8]
  simp [hBytes, u32le?, hMin, show UInt8.toNat (0xfe : UInt8) = 254 by decide]
  constructor
  · rfl
  · simpa [u32le?] using hMin

theorem compactSize_from_nine_byte_prefix
    {c c1 c2 : Cursor}
    (b0 b1 b2 b3 b4 b5 b6 b7 : UInt8)
    (hU8 : c.getU8? = some (0xff, c1))
    (hBytes : c1.getBytes? 8 = some (RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7], c2))
    (hMin : 0xffffffff < (u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat) :
    c.getCompactSize? = some ((u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat, c2, true) := by
  unfold Cursor.getCompactSize?
  rw [hU8]
  simp [hBytes, hMin, show UInt8.toNat (0xff : UInt8) = 255 by decide]
  constructor
  · rfl
  · simpa using hMin

theorem compactSize_nine_byte_getBytes
    (b0 b1 b2 b3 b4 b5 b6 b7 : UInt8) :
    ({ bs := RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7], off := 1 } : Cursor).getBytes? 8 =
      some
        (RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7],
          { bs := RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7],
            off := (RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7]).size }) := by
  simp [Cursor.getBytes?, RubinFormal.bytes, ByteArray.extract, ByteArray.copySlice, ByteArray.size]
  rfl

theorem compactSize_one_byte_roundtrip
    (b : UInt8)
    (hTag : b.toNat < 0xfd) :
    let bs := RubinFormal.bytes #[b]
    ({ bs := bs, off := 0 } : Cursor).getCompactSize? =
      some (b.toNat, { bs := bs, off := bs.size }, true) := by
  let bs := RubinFormal.bytes #[b]
  have hSize : bs.size = 1 := rfl
  simpa [hSize] using
    compactSize_from_single_byte b
      (c := { bs := bs, off := 0 })
      (c' := { bs := bs, off := 1 })
      rfl hTag

theorem compactSize_three_byte_roundtrip
    (b0 b1 : UInt8)
    (hMin : 0xfd ≤ u16le? b0 b1) :
    let bs := RubinFormal.bytes #[0xfd, b0, b1]
    ({ bs := bs, off := 0 } : Cursor).getCompactSize? =
      some (u16le? b0 b1, { bs := bs, off := bs.size }, true) := by
  let bs := RubinFormal.bytes #[0xfd, b0, b1]
  have hSize : bs.size = 3 := rfl
  simpa [hSize] using
    compactSize_from_three_byte_prefix b0 b1
      (c := { bs := bs, off := 0 })
      (c1 := { bs := bs, off := 1 })
      (c2 := { bs := bs, off := 3 })
      rfl rfl hMin

theorem compactSize_five_byte_roundtrip
    (b0 b1 b2 b3 : UInt8)
    (hMin : 0xffff < u32le? b0 b1 b2 b3) :
    let bs := RubinFormal.bytes #[0xfe, b0, b1, b2, b3]
    ({ bs := bs, off := 0 } : Cursor).getCompactSize? =
      some (u32le? b0 b1 b2 b3, { bs := bs, off := bs.size }, true) := by
  let bs := RubinFormal.bytes #[0xfe, b0, b1, b2, b3]
  have hSize : bs.size = 5 := rfl
  simpa [hSize] using
    compactSize_from_five_byte_prefix b0 b1 b2 b3
      (c := { bs := bs, off := 0 })
      (c1 := { bs := bs, off := 1 })
      (c2 := { bs := bs, off := 5 })
      rfl rfl hMin

theorem compactSize_nine_byte_roundtrip
    (b0 b1 b2 b3 b4 b5 b6 b7 : UInt8)
    (hMin : 0xffffffff < (u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat) :
    let bs := RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7]
    ({ bs := bs, off := 0 } : Cursor).getCompactSize? =
      some ((u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat, { bs := bs, off := bs.size }, true) := by
  change
    ({ bs := RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7], off := 0 } : Cursor).getCompactSize? =
      some
        ((u64le? b0 b1 b2 b3 b4 b5 b6 b7).toNat,
          { bs := RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7],
            off := (RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7]).size },
          true)
  exact
    compactSize_from_nine_byte_prefix b0 b1 b2 b3 b4 b5 b6 b7
      (c := { bs := RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7], off := 0 })
      (c1 := { bs := RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7], off := 1 })
      (c2 := { bs := RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7],
               off := (RubinFormal.bytes #[0xff, b0, b1, b2, b3, b4, b5, b6, b7]).size })
      rfl
      (compactSize_nine_byte_getBytes b0 b1 b2 b3 b4 b5 b6 b7)
      hMin

/-- Roundtrip over all canonical 1/3/5/9-byte CompactSize prefixes. -/
theorem compactSize_roundtrip {bs : Bytes} {n : Nat} (h : CompactSizeCanonical bs n) :
    ({ bs := bs, off := 0 } : Cursor).getCompactSize? =
      some (n, { bs := bs, off := bs.size }, true) := by
  cases h with
  | oneByte b hTag _ =>
      simpa using compactSize_one_byte_roundtrip b hTag
  | threeByte b0 b1 hMin _ =>
      simpa using compactSize_three_byte_roundtrip b0 b1 hMin
  | fiveByte b0 b1 b2 b3 hMin _ =>
      simpa using compactSize_five_byte_roundtrip b0 b1 b2 b3 hMin
  | nineByte b0 b1 b2 b3 b4 b5 b6 b7 hMin _ =>
      simpa using compactSize_nine_byte_roundtrip b0 b1 b2 b3 b4 b5 b6 b7 hMin

/-- CompactSize canonical prefixes never decode above the UInt64 range. -/
theorem compactSize_overflow_safety {bs : Bytes} {n : Nat} (h : CompactSizeCanonical bs n) :
    n ≤ UInt64.size - 1 := by
  cases h with
  | oneByte _ _ hBound => exact hBound
  | threeByte _ _ _ hBound => exact hBound
  | fiveByte _ _ _ _ _ hBound => exact hBound
  | nineByte _ _ _ _ _ _ _ _ _ hBound => exact hBound

open WireEnc

private theorem uint8_ofNat_toNat_eq (n : Nat) (h : n < 256) :
    (UInt8.ofNat n).toNat = n := by
  simp [UInt8.ofNat, UInt8.toNat, Fin.ofNat, Nat.mod_eq_of_lt h]

private theorem u16le_ofNat_roundtrip (n : Nat) (h : n ≤ 0xffff) :
    u16le? (UInt8.ofNat (n % 256)) (UInt8.ofNat ((n / 256) % 256)) = n := by
  have h0 : n % 256 < 256 := Nat.mod_lt _ (by decide)
  have h1div : n / 256 < 256 := by omega
  have h1 : (UInt8.ofNat ((n / 256) % 256)).toNat = n / 256 := by
    simpa [Nat.mod_eq_of_lt h1div] using
      uint8_ofNat_toNat_eq ((n / 256) % 256) (Nat.mod_lt _ (by decide))
  calc
    u16le? (UInt8.ofNat (n % 256)) (UInt8.ofNat ((n / 256) % 256))
      = (UInt8.ofNat (n % 256)).toNat + ((UInt8.ofNat ((n / 256) % 256)).toNat <<< 8) := by
          rfl
    _ = n % 256 + ((n / 256) <<< 8) := by
          rw [uint8_ofNat_toNat_eq (n % 256) h0, h1]
    _ = n % 256 + (n / 256) * 256 := by
          rw [Nat.shiftLeft_eq, show 2 ^ 8 = 256 by decide]
    _ = n := by
          simpa [Nat.mul_comm] using Nat.mod_add_div n 256

private theorem u32le_ofNat_roundtrip (n : Nat) (h : n ≤ 0xffffffff) :
    u32le?
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
    u32le?
      (UInt8.ofNat (n % 256))
      (UInt8.ofNat ((n / 256) % 256))
      (UInt8.ofNat ((n / 65536) % 256))
      (UInt8.ofNat ((n / 16777216) % 256))
      =
      n % 256 +
      ((n / 256) % 256 * 256) +
      ((n / 65536) % 256 * 65536) +
      ((n / 16777216) * 16777216) := by
          unfold u32le?
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

private theorem u64_digits_nested_eq (n : Nat) (h : n ≤ UInt64.size - 1) :
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

private theorem u64_digits_flat_eq (n : Nat) (h : n ≤ UInt64.size - 1) :
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

private theorem u64le_ofNat_roundtrip (n : Nat) (h : n ≤ UInt64.size - 1) :
    (u64le?
      (UInt8.ofNat (n % 256))
      (UInt8.ofNat ((n / 256) % 256))
      (UInt8.ofNat ((n / 65536) % 256))
      (UInt8.ofNat ((n / 16777216) % 256))
      (UInt8.ofNat ((n / 4294967296) % 256))
      (UInt8.ofNat ((n / 1099511627776) % 256))
      (UInt8.ofNat ((n / 281474976710656) % 256))
      (UInt8.ofNat ((n / 72057594037927936) % 256))).toNat = n := by
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
  have hSumLt :
      n % 256 +
      ((n / 256) % 256 * 256) +
      ((n / 65536) % 256 * 65536) +
      ((n / 16777216) % 256 * 16777216) +
      ((n / 4294967296) % 256 * 4294967296) +
      ((n / 1099511627776) % 256 * 1099511627776) +
      ((n / 281474976710656) % 256 * 281474976710656) +
      ((n / 72057594037927936) % 256 * 72057594037927936) < UInt64.size := by
    simpa [hFlat] using Nat.lt_of_le_of_lt h (by decide)
  calc
    (u64le?
      (UInt8.ofNat (n % 256))
      (UInt8.ofNat ((n / 256) % 256))
      (UInt8.ofNat ((n / 65536) % 256))
      (UInt8.ofNat ((n / 16777216) % 256))
      (UInt8.ofNat ((n / 4294967296) % 256))
      (UInt8.ofNat ((n / 1099511627776) % 256))
      (UInt8.ofNat ((n / 281474976710656) % 256))
      (UInt8.ofNat ((n / 72057594037927936) % 256))).toNat
      =
      (UInt64.ofNat (
        n % 256 +
        ((n / 256) % 256 * 256) +
        ((n / 65536) % 256 * 65536) +
        ((n / 16777216) % 256 * 16777216) +
        ((n / 4294967296) % 256 * 4294967296) +
        ((n / 1099511627776) % 256 * 1099511627776) +
        ((n / 281474976710656) % 256 * 281474976710656) +
        ((n / 72057594037927936) % 256 * 72057594037927936))).toNat := by
          unfold u64le?
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
  _ =
      n % 256 +
      ((n / 256) % 256 * 256) +
      ((n / 65536) % 256 * 65536) +
      ((n / 16777216) % 256 * 16777216) +
      ((n / 4294967296) % 256 * 4294967296) +
      ((n / 1099511627776) % 256 * 1099511627776) +
      ((n / 281474976710656) % 256 * 281474976710656) +
      ((n / 72057594037927936) % 256 * 72057594037927936) := by
          have hSumLtAssoc :
              n % 256 +
                (n / 256 % 256 * 256 +
                  (n / 65536 % 256 * 65536 +
                    (n / 16777216 % 256 * 16777216 +
                      (n / 4294967296 % 256 * 4294967296 +
                        (n / 1099511627776 % 256 * 1099511627776 +
                          (n / 281474976710656 % 256 * 281474976710656 +
                            n / 72057594037927936 % 256 * 72057594037927936)))))) < UInt64.size := by
            omega
          simp [UInt64.ofNat, UInt64.toNat, Fin.ofNat, Nat.mod_eq_of_lt hSumLtAssoc, Nat.add_assoc]
    _ = n := hFlat

set_option maxHeartbeats 20000000 in
theorem compactSize_encode_roundtrip (n : Nat) (hBound : n ≤ UInt64.size - 1) :
    ({ bs := WireEnc.compactSize n, off := 0 } : Cursor).getCompactSize? =
      some (n, { bs := WireEnc.compactSize n, off := (WireEnc.compactSize n).size }, true) := by
  by_cases hOne : n < 0xfd
  · have hByte : (UInt8.ofNat n).toNat < 0xfd := by
      simpa [uint8_ofNat_toNat_eq n (Nat.lt_of_lt_of_le hOne (by decide))] using hOne
    simpa [WireEnc.compactSize, hOne, uint8_ofNat_toNat_eq n (Nat.lt_of_lt_of_le hOne (by decide))] using
      compactSize_one_byte_roundtrip (UInt8.ofNat n) hByte
  · by_cases hThree : n ≤ 0xffff
    · have hMin : 0xfd ≤ u16le? (UInt8.ofNat (n % 256)) (UInt8.ofNat ((n / 256) % 256)) := by
        simpa [u16le_ofNat_roundtrip n hThree] using Nat.not_lt.mp hOne
      simpa [WireEnc.compactSize, hOne, hThree, u16le_ofNat_roundtrip n hThree] using
        compactSize_three_byte_roundtrip
          (UInt8.ofNat (n % 256))
          (UInt8.ofNat ((n / 256) % 256))
          hMin
    · by_cases hFive : n ≤ 0xffffffff
      · have hMin :
          0xffff <
            u32le?
              (UInt8.ofNat (n % 256))
              (UInt8.ofNat ((n / 256) % 256))
              (UInt8.ofNat ((n / 65536) % 256))
              (UInt8.ofNat ((n / 16777216) % 256)) := by
          simpa [u32le_ofNat_roundtrip n hFive] using Nat.lt_of_not_ge hThree
        simpa [WireEnc.compactSize, hOne, hThree, hFive, u32le_ofNat_roundtrip n hFive] using
          compactSize_five_byte_roundtrip
            (UInt8.ofNat (n % 256))
            (UInt8.ofNat ((n / 256) % 256))
            (UInt8.ofNat ((n / 65536) % 256))
            (UInt8.ofNat ((n / 16777216) % 256))
            hMin
      · have hMin :
          0xffffffff <
            (u64le?
              (UInt8.ofNat (n % 256))
              (UInt8.ofNat ((n / 256) % 256))
              (UInt8.ofNat ((n / 65536) % 256))
              (UInt8.ofNat ((n / 16777216) % 256))
              (UInt8.ofNat ((n / 4294967296) % 256))
              (UInt8.ofNat ((n / 1099511627776) % 256))
              (UInt8.ofNat ((n / 281474976710656) % 256))
              (UInt8.ofNat ((n / 72057594037927936) % 256))).toNat := by
          simpa [u64le_ofNat_roundtrip n hBound] using Nat.lt_of_not_ge hFive
        have hRound :=
          compactSize_nine_byte_roundtrip
            (UInt8.ofNat (n % 256))
            (UInt8.ofNat ((n / 256) % 256))
            (UInt8.ofNat ((n / 65536) % 256))
            (UInt8.ofNat ((n / 16777216) % 256))
            (UInt8.ofNat ((n / 4294967296) % 256))
            (UInt8.ofNat ((n / 1099511627776) % 256))
            (UInt8.ofNat ((n / 281474976710656) % 256))
            (UInt8.ofNat ((n / 72057594037927936) % 256))
            hMin
        rw [u64le_ofNat_roundtrip n hBound] at hRound
        simpa [WireEnc.compactSize, WireEnc.u64le, hOne, hThree, hFive, RubinFormal.bytes] using hRound

theorem compactSize_encode_cursor_advances (n : Nat) (hBound : n ≤ UInt64.size - 1) :
    ({ bs := WireEnc.compactSize n, off := 0 } : Cursor).getCompactSize? =
      some (n, { bs := WireEnc.compactSize n, off := (WireEnc.compactSize n).size }, true) ∧
      ({ bs := WireEnc.compactSize n, off := 0 } : Cursor).remaining = (WireEnc.compactSize n).size := by
  refine ⟨compactSize_encode_roundtrip n hBound, rfl⟩

-- ═══════════════════════════════════════════════════════════════════
-- ByteWireV2 structural theorems (F-05 fix, Q-FORMAL-GAP-04)
-- ═══════════════════════════════════════════════════════════════════

/-- getU8? advances the cursor by exactly 1 byte when it succeeds. -/
theorem Cursor.getU8_advances (c : Cursor) (b : UInt8) (c' : Cursor) :
    c.getU8? = some (b, c') → c'.off = c.off + 1 := by
  simp only [Cursor.getU8?]
  split
  · simp only [Option.some.injEq, Prod.mk.injEq, and_imp]
    intro _ h; subst h; rfl
  · simp

/-- getBytes? advances the cursor by exactly n bytes when it succeeds. -/
theorem Cursor.getBytes_advances (c : Cursor) (n : Nat) (bs : Bytes) (c' : Cursor) :
    c.getBytes? n = some (bs, c') → c'.off = c.off + n := by
  simp only [Cursor.getBytes?]
  split
  · simp only [Option.some.injEq, Prod.mk.injEq, and_imp]
    intro _ h; subst h; rfl
  · simp

/-- getU8? only succeeds when there is remaining data (off < size). -/
theorem Cursor.getU8_requires_data (c : Cursor) :
    (∃ b c', c.getU8? = some (b, c')) → c.off < c.bs.size := by
  intro ⟨b, c', h⟩
  simp only [Cursor.getU8?] at h
  split at h <;> [assumption; simp at h]

/-- All four TxErr constructors are pairwise distinct. -/
theorem txerr_all_distinct :
    TxErr.parse ≠ TxErr.witnessOverflow ∧
    TxErr.parse ≠ TxErr.sigAlgInvalid ∧
    TxErr.parse ≠ TxErr.sigNoncanonical ∧
    TxErr.witnessOverflow ≠ TxErr.sigAlgInvalid ∧
    TxErr.witnessOverflow ≠ TxErr.sigNoncanonical ∧
    TxErr.sigAlgInvalid ≠ TxErr.sigNoncanonical := by
  exact ⟨by simp, by simp, by simp, by simp, by simp, by simp⟩

/-- TxErr.toString maps different error codes to different strings. -/
theorem txerr_toString_injective :
    ∀ e1 e2 : TxErr, e1.toString = e2.toString → e1 = e2 := by
  intro e1 e2
  cases e1 <;> cases e2 <;> simp [TxErr.toString] <;> decide

end Wire
end RubinFormal

import RubinFormal.ByteWireV2

/-!
# Primitive Encoding Roundtrip Proofs (§2)

Proves decode-after-encode roundtrip for u16le, u32le, u64le and
fixed-width output length for each encoder.
-/

namespace RubinFormal

open Wire

/-- Encode a Nat as 2-byte little-endian. -/
def encodeU16le (n : Nat) : ByteArray :=
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  ByteArray.mk #[b0, b1]

/-- Encode a Nat as 4-byte little-endian. -/
def encodeU32le (n : Nat) : ByteArray :=
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
  let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
  ByteArray.mk #[b0, b1, b2, b3]

/-- Encode a Nat as 8-byte little-endian. -/
def encodeU64le (n : Nat) : ByteArray :=
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
  let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
  let b4 : UInt8 := UInt8.ofNat ((n / 4294967296) % 256)
  let b5 : UInt8 := UInt8.ofNat ((n / 1099511627776) % 256)
  let b6 : UInt8 := UInt8.ofNat ((n / 281474976710656) % 256)
  let b7 : UInt8 := UInt8.ofNat ((n / 72057594037927936) % 256)
  ByteArray.mk #[b0, b1, b2, b3, b4, b5, b6, b7]

/-! ## Fixed-width output length -/

theorem encodeU16le_length (n : Nat) : (encodeU16le n).size = 2 := by rfl
theorem encodeU32le_length (n : Nat) : (encodeU32le n).size = 4 := by rfl
theorem encodeU64le_length (n : Nat) : (encodeU64le n).size = 8 := by rfl

/-! ## Decode-after-encode roundtrip (concrete vectors) -/

/-- u16le roundtrip for n=0 -/
theorem u16le_roundtrip_0 :
    u16le? (encodeU16le 0).data[0]! (encodeU16le 0).data[1]! = 0 := by rfl

/-- u16le roundtrip for n=0x0102 (258) -/
theorem u16le_roundtrip_258 :
    u16le? (encodeU16le 258).data[0]! (encodeU16le 258).data[1]! = 258 := by rfl

/-- u16le roundtrip for n=0xFFFF (65535) -/
theorem u16le_roundtrip_max :
    u16le? (encodeU16le 65535).data[0]! (encodeU16le 65535).data[1]! = 65535 := by rfl

/-- u32le roundtrip for n=0 -/
theorem u32le_roundtrip_0 :
    u32le? (encodeU32le 0).data[0]! (encodeU32le 0).data[1]!
           (encodeU32le 0).data[2]! (encodeU32le 0).data[3]! = 0 := by rfl

/-- u32le roundtrip for n=0x01020304 -/
theorem u32le_roundtrip_16909060 :
    u32le? (encodeU32le 16909060).data[0]! (encodeU32le 16909060).data[1]!
           (encodeU32le 16909060).data[2]! (encodeU32le 16909060).data[3]! = 16909060 := by rfl

/-- u32le roundtrip for n=0xFFFFFFFF -/
theorem u32le_roundtrip_max :
    u32le? (encodeU32le 4294967295).data[0]! (encodeU32le 4294967295).data[1]!
           (encodeU32le 4294967295).data[2]! (encodeU32le 4294967295).data[3]! = 4294967295 := by rfl

/-- u64le roundtrip for n=0 -/
theorem u64le_roundtrip_0 :
    (u64le? (encodeU64le 0).data[0]! (encodeU64le 0).data[1]!
            (encodeU64le 0).data[2]! (encodeU64le 0).data[3]!
            (encodeU64le 0).data[4]! (encodeU64le 0).data[5]!
            (encodeU64le 0).data[6]! (encodeU64le 0).data[7]!).toNat = 0 := by rfl

/-- u64le roundtrip for n=1000000 -/
theorem u64le_roundtrip_1M :
    (u64le? (encodeU64le 1000000).data[0]! (encodeU64le 1000000).data[1]!
            (encodeU64le 1000000).data[2]! (encodeU64le 1000000).data[3]!
            (encodeU64le 1000000).data[4]! (encodeU64le 1000000).data[5]!
            (encodeU64le 1000000).data[6]! (encodeU64le 1000000).data[7]!).toNat = 1000000 := by rfl

end RubinFormal

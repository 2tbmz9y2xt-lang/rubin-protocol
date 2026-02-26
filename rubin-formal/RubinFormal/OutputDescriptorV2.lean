import RubinFormal.Types
import RubinFormal.SHA3_256

namespace RubinFormal

namespace WireEnc

def u16le (n : Nat) : Bytes :=
  let lo : UInt8 := UInt8.ofNat (n % 256)
  let hi : UInt8 := UInt8.ofNat ((n / 256) % 256)
  RubinFormal.bytes #[lo, hi]

def u32le (n : Nat) : Bytes :=
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
  let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
  RubinFormal.bytes #[b0, b1, b2, b3]

def u64le (n : Nat) : Bytes :=
  let b0 : UInt8 := UInt8.ofNat (n % 256)
  let b1 : UInt8 := UInt8.ofNat ((n / 256) % 256)
  let b2 : UInt8 := UInt8.ofNat ((n / 65536) % 256)
  let b3 : UInt8 := UInt8.ofNat ((n / 16777216) % 256)
  let b4 : UInt8 := UInt8.ofNat ((n / 4294967296) % 256)
  let b5 : UInt8 := UInt8.ofNat ((n / 1099511627776) % 256)
  let b6 : UInt8 := UInt8.ofNat ((n / 281474976710656) % 256)
  let b7 : UInt8 := UInt8.ofNat ((n / 72057594037927936) % 256)
  RubinFormal.bytes #[b0, b1, b2, b3, b4, b5, b6, b7]

def compactSize (n : Nat) : Bytes :=
  if n < 0xfd then
    RubinFormal.bytes #[UInt8.ofNat n]
  else if n ≤ 0xffff then
    (ByteArray.empty.push 0xfd) ++ u16le n
  else if n ≤ 0xffffffff then
    (ByteArray.empty.push 0xfe) ++ u32le n
  else
    (ByteArray.empty.push 0xff) ++ u64le n

end WireEnc

namespace OutputDescriptor

open WireEnc

-- OutputDescriptorBytes = u16le(covenant_type) || CompactSize(covenant_data_len) || covenant_data
-- (value is intentionally excluded; see CANONICAL §18.3 and CV-OUTPUT-DESCRIPTOR fixtures)
def bytes (covenantType : Nat) (covenantData : Bytes) : Bytes :=
  (u16le covenantType) ++ (compactSize covenantData.size) ++ covenantData

def hash (covenantType : Nat) (covenantData : Bytes) : Bytes :=
  SHA3.sha3_256 (bytes covenantType covenantData)

end OutputDescriptor

end RubinFormal

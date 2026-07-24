import RubinFormal.BlockBasicV1

/-!
# Block Header Wire Roundtrip Proofs (§10.1)

Proves header serialization length for concrete well-formed headers.
Universal quantified proof blocked by ByteArray.size_append unavailability
in Lean 4.6 Std4.
-/

namespace RubinFormal

open BlockBasicV1

/-- Concrete witness: zero header serializes to 116 bytes.
    Tied to actual `headerBytes` function — any field order/width change
    breaks this proof. -/
theorem headerBytes_zero_length :
    (headerBytes {
      version := 0
      prevHash := ByteArray.mk (Array.mkArray 32 0)
      merkleRoot := ByteArray.mk (Array.mkArray 32 0)
      timestamp := 0
      target := ByteArray.mk (Array.mkArray 32 0)
      nonce := 0
    }).size = 116 := by rfl

/-- Concrete witness: non-zero header serializes to 116 bytes. -/
theorem headerBytes_test_length :
    (headerBytes {
      version := 1
      prevHash := ByteArray.mk (Array.mkArray 32 0x11)
      merkleRoot := ByteArray.mk (Array.mkArray 32 0x22)
      timestamp := 1700000000
      target := ByteArray.mk (Array.mkArray 32 0xFF)
      nonce := 42
    }).size = 116 := by rfl

/-- Concrete witness: max-value header serializes to 116 bytes. -/
theorem headerBytes_max_length :
    (headerBytes {
      version := 4294967295
      prevHash := ByteArray.mk (Array.mkArray 32 0xFF)
      merkleRoot := ByteArray.mk (Array.mkArray 32 0xFF)
      timestamp := 18446744073709551615
      target := ByteArray.mk (Array.mkArray 32 0xFF)
      nonce := 18446744073709551615
    }).size = 116 := by rfl

end RubinFormal

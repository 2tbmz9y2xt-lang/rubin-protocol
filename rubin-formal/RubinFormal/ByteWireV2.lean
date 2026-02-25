import Std

namespace RubinFormal

abbrev Bytes := ByteArray

namespace Wire

structure Cursor where
  bs : Bytes
  off : Nat
deriving Repr

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
  (UInt64.ofNat b0.toNat) |||
  ((UInt64.ofNat b1.toNat) <<< 8) |||
  ((UInt64.ofNat b2.toNat) <<< 16) |||
  ((UInt64.ofNat b3.toNat) <<< 24) |||
  ((UInt64.ofNat b4.toNat) <<< 32) |||
  ((UInt64.ofNat b5.toNat) <<< 40) |||
  ((UInt64.ofNat b6.toNat) <<< 48) |||
  ((UInt64.ofNat b7.toNat) <<< 56)

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
deriving Repr, DecidableEq

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
deriving Repr

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

end Wire
end RubinFormal


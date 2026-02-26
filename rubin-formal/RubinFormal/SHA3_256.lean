import RubinFormal.Types

namespace RubinFormal

namespace SHA3

-- Keccak-f[1600] constants (FIPS 202).
def rhoOffsets : Array Nat :=
  #[
    0,  1, 62, 28, 27,
   36, 44,  6, 55, 20,
    3, 10, 43, 25, 39,
   41, 45, 15, 21,  8,
   18,  2, 61, 56, 14
  ]

def roundConstants : Array UInt64 :=
  #[
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
  ]

@[inline] def rotl (x : UInt64) (n : Nat) : UInt64 :=
  let k : Nat := n % 64
  if k == 0 then
    x
  else
    let ku := UInt64.ofNat k
    let r := UInt64.ofNat (64 - k)
    (x <<< ku) ||| (x >>> r)

@[inline] def idx (x y : Nat) : Nat := 5*y + x

def keccakF (st : Array UInt64) : Array UInt64 :=
  Id.run do
    let mut a := st
    for rc in roundConstants do
      -- θ
      let c0 := a.get! (idx 0 0) ^^^ a.get! (idx 0 1) ^^^ a.get! (idx 0 2) ^^^ a.get! (idx 0 3) ^^^ a.get! (idx 0 4)
      let c1 := a.get! (idx 1 0) ^^^ a.get! (idx 1 1) ^^^ a.get! (idx 1 2) ^^^ a.get! (idx 1 3) ^^^ a.get! (idx 1 4)
      let c2 := a.get! (idx 2 0) ^^^ a.get! (idx 2 1) ^^^ a.get! (idx 2 2) ^^^ a.get! (idx 2 3) ^^^ a.get! (idx 2 4)
      let c3 := a.get! (idx 3 0) ^^^ a.get! (idx 3 1) ^^^ a.get! (idx 3 2) ^^^ a.get! (idx 3 3) ^^^ a.get! (idx 3 4)
      let c4 := a.get! (idx 4 0) ^^^ a.get! (idx 4 1) ^^^ a.get! (idx 4 2) ^^^ a.get! (idx 4 3) ^^^ a.get! (idx 4 4)

      let d0 := c4 ^^^ (rotl c1 1)
      let d1 := c0 ^^^ (rotl c2 1)
      let d2 := c1 ^^^ (rotl c3 1)
      let d3 := c2 ^^^ (rotl c4 1)
      let d4 := c3 ^^^ (rotl c0 1)

      for y in [0,1,2,3,4] do
        a := a.set! (idx 0 y) (a.get! (idx 0 y) ^^^ d0)
        a := a.set! (idx 1 y) (a.get! (idx 1 y) ^^^ d1)
        a := a.set! (idx 2 y) (a.get! (idx 2 y) ^^^ d2)
        a := a.set! (idx 3 y) (a.get! (idx 3 y) ^^^ d3)
        a := a.set! (idx 4 y) (a.get! (idx 4 y) ^^^ d4)

      -- ρ + π
      let mut b : Array UInt64 := Array.mkArray 25 0
      for x in [0,1,2,3,4] do
        for y in [0,1,2,3,4] do
          let i := idx x y
          let v := rotl (a.get! i) (rhoOffsets.get! i)
          let x' := y
          let y' := (2*x + 3*y) % 5
          b := b.set! (idx x' y') v

      -- χ
      for y in [0,1,2,3,4] do
        let b0 := b.get! (idx 0 y)
        let b1 := b.get! (idx 1 y)
        let b2 := b.get! (idx 2 y)
        let b3 := b.get! (idx 3 y)
        let b4 := b.get! (idx 4 y)
        a := a.set! (idx 0 y) (b0 ^^^ ((~~~b1) &&& b2))
        a := a.set! (idx 1 y) (b1 ^^^ ((~~~b2) &&& b3))
        a := a.set! (idx 2 y) (b2 ^^^ ((~~~b3) &&& b4))
        a := a.set! (idx 3 y) (b3 ^^^ ((~~~b4) &&& b0))
        a := a.set! (idx 4 y) (b4 ^^^ ((~~~b0) &&& b1))

      -- ι
      a := a.set! 0 (a.get! 0 ^^^ rc)
    return a

@[inline] def u64FromLeBytes (b0 b1 b2 b3 b4 b5 b6 b7 : UInt8) : UInt64 :=
  (UInt64.ofNat b0.toNat) |||
  ((UInt64.ofNat b1.toNat) <<< 8) |||
  ((UInt64.ofNat b2.toNat) <<< 16) |||
  ((UInt64.ofNat b3.toNat) <<< 24) |||
  ((UInt64.ofNat b4.toNat) <<< 32) |||
  ((UInt64.ofNat b5.toNat) <<< 40) |||
  ((UInt64.ofNat b6.toNat) <<< 48) |||
  ((UInt64.ofNat b7.toNat) <<< 56)

def xorBlockIntoState (st : Array UInt64) (block : Bytes) : Array UInt64 :=
  Id.run do
    let mut a := st
    -- rate = 136 bytes = 17 lanes
    for lane in [0:17] do
      let off := lane * 8
      let b0 := block.get! (off + 0)
      let b1 := block.get! (off + 1)
      let b2 := block.get! (off + 2)
      let b3 := block.get! (off + 3)
      let b4 := block.get! (off + 4)
      let b5 := block.get! (off + 5)
      let b6 := block.get! (off + 6)
      let b7 := block.get! (off + 7)
      let v := u64FromLeBytes b0 b1 b2 b3 b4 b5 b6 b7
      a := a.set! lane (a.get! lane ^^^ v)
    return a

def padSha3 (msg : Bytes) : Bytes :=
  Id.run do
    let rate := 136
    let mut out := msg
    out := out.push 0x06
    while (out.size % rate) != (rate - 1) do
      out := out.push 0x00
    out := out.push 0x80
    return out

def sha3_256 (msg : Bytes) : Bytes :=
  Id.run do
    let rate := 136
    let padded := padSha3 msg
    let mut st : Array UInt64 := Array.mkArray 25 0
    let mut off : Nat := 0
    while off < padded.size do
      let block := padded.extract off (off + rate)
      st := keccakF (xorBlockIntoState st block)
      off := off + rate

    -- squeeze 32 bytes from first 4 lanes (little-endian)
    let mut out : Bytes := ByteArray.empty
    for lane in [0:4] do
      let v := st.get! lane
      for shift in [0,8,16,24,32,40,48,56] do
        out := out.push (UInt8.ofNat ((v >>> (UInt64.ofNat shift)).toNat &&& 0xff))
    return out.extract 0 32

end SHA3
end RubinFormal

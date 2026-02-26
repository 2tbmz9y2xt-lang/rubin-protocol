import RubinFormal.Types
import RubinFormal.SHA3_256

namespace RubinFormal

namespace PowV1

def u64Max : Nat := (Nat.pow 2 64) - 1
def powLimit : Nat := (Nat.pow 2 256) - 1

def windowSize : Nat := 10080
def targetBlockInterval : Nat := 120
def tExpected : Nat := targetBlockInterval * windowSize -- 1209600

def maxTimestampStepPerBlock : Nat := 1200

def clamp (v lo hi : Nat) : Nat :=
  Nat.max lo (Nat.min v hi)

def bytesToNatBE32? (bs : Bytes) : Option Nat :=
  if bs.size != 32 then
    none
  else
    some <| Id.run do
      let mut acc : Nat := 0
      for i in [0:32] do
        let b := (bs.get! i).toNat
        acc := acc * 256 + b
      return acc

def natToBytesBE32 (n : Nat) : Bytes :=
  RubinFormal.bytes <| (Id.run do
    let mut out : Array UInt8 := Array.mkEmpty 32
    let mut x : Nat := n
    -- Build little-endian bytes, then reverse to big-endian.
    for _ in [0:32] do
      out := out.push (UInt8.ofNat (x % 256))
      x := x / 256
    return out.reverse
  )

structure WindowPattern where
  windowSize : Nat
  start : Nat
  step : Nat
  lastJump : Nat
deriving Repr, DecidableEq

def lastTwo? : List Nat -> Option (Nat × Nat)
  | [] => none
  | [_] => none
  | a :: b :: rest =>
      let rec go (prev : Nat) (cur : Nat) : List Nat -> (Nat × Nat)
        | [] => (prev, cur)
        | x :: xs => go cur x xs
      some (go a b rest)

def replaceLast : List Nat -> Nat -> List Nat
  | [], _ => []
  | [_], v => [v]
  | x :: xs, v => x :: replaceLast xs v

def genWindowTimestamps (p : WindowPattern) : Except String (List Nat) := do
  if p.windowSize < 2 then
    throw "TX_ERR_PARSE"
  if p.windowSize != windowSize then
    throw "TX_ERR_PARSE"
  let out : Array Nat :=
    Id.run do
      let mut ts : Array Nat := Array.mkEmpty p.windowSize
      let mut prev : Nat := p.start
      ts := ts.push prev
      for _ in [0:(p.windowSize - 1)] do
        let next := prev + p.step
        ts := ts.push next
        prev := next
      if p.lastJump != 0 then
        let secLast := ts.get! (p.windowSize - 2)
        ts := ts.set! (p.windowSize - 1) (secLast + p.lastJump)
      return ts
  pure out.toList

def clampWindowTimestamps (raw : List Nat) : Except String (List Nat) := do
  match raw with
  | [] => throw "TX_ERR_PARSE"
  | t0 :: rest =>
      if t0 > u64Max then
        throw "TX_ERR_PARSE"
      let out : Array Nat :=
        Id.run do
          let mut prev : Nat := t0
          let mut acc : Array Nat := Array.mkEmpty raw.length
          acc := acc.push t0
          for t in rest do
            if t > u64Max then
              -- fail-fast: encode as empty and handle below
              return #[]
            let lo := prev + 1
            let hi := prev + maxTimestampStepPerBlock
            if lo > u64Max || hi > u64Max then
              return #[]
            let t' := clamp t lo hi
            acc := acc.push t'
            prev := t'
          return acc
      if out.isEmpty then
        throw "TX_ERR_PARSE"
      pure out.toList

def tActualFromWindow (ts : List Nat) : Except String Nat := do
  let ts' <- clampWindowTimestamps ts
  match ts' with
  | [] => throw "TX_ERR_PARSE"
  | first :: _ =>
      let last := ts'.getLastD first
      if last <= first then
        pure 1
      else
        pure (last - first)

def retargetV1 (targetOld : Bytes) (timestampFirst timestampLast : Nat) (pattern : Option WindowPattern) :
    Except String Bytes := do
  let targetOldNat ←
    match bytesToNatBE32? targetOld with
    | none => throw "TX_ERR_PARSE"
    | some n => pure n
  if targetOldNat == 0 then
    throw "TX_ERR_PARSE"
  if targetOldNat > powLimit then
    throw "TX_ERR_PARSE"
  let tActual ←
    match pattern with
    | some p =>
        let raw <- genWindowTimestamps p
        tActualFromWindow raw
    | none =>
        if timestampFirst > u64Max || timestampLast > u64Max then
          throw "TX_ERR_PARSE"
        if timestampLast <= timestampFirst then
          pure 1
        else
          pure (timestampLast - timestampFirst)
  let candidate := (targetOldNat * tActual) / tExpected
  let lo := Nat.max 1 (targetOldNat / 4)
  let hi := Nat.min (targetOldNat * 4) powLimit
  let targetNew := Nat.max lo (Nat.min candidate hi)
  pure (natToBytesBE32 targetNew)

def blockHash (headerBytes : Bytes) : Bytes :=
  SHA3.sha3_256 headerBytes

def powCheck (headerBytes : Bytes) (targetBytes : Bytes) : Except String Bool := do
  let targetNat ←
    match bytesToNatBE32? targetBytes with
    | none => throw "BLOCK_ERR_TARGET_INVALID"
    | some n => pure n
  if targetNat == 0 || targetNat > powLimit then
    throw "BLOCK_ERR_TARGET_INVALID"
  let h := blockHash headerBytes
  let hashNat :=
    match bytesToNatBE32? h with
    | none => 0
    | some n => n
  if hashNat < targetNat then
    pure true
  else
    throw "BLOCK_ERR_POW_INVALID"

end PowV1

end RubinFormal

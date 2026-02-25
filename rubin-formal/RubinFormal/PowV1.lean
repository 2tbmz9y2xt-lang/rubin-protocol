import Std
import RubinFormal.SHA3_256

namespace RubinFormal

abbrev Bytes := ByteArray

namespace PowV1

def u64Max : Nat := (Nat.pow 2 64) - 1
def powLimit : Nat := (Nat.pow 2 256) - 1

def windowSize : Nat := 10_080
def targetBlockInterval : Nat := 120
def tExpected : Nat := targetBlockInterval * windowSize -- 1_209_600

def maxTimestampStepPerBlock : Nat := 1_200

def clamp (v lo hi : Nat) : Nat :=
  Nat.max lo (Nat.min v hi)

def bytesToNatBE32? (bs : Bytes) : Option Nat :=
  if bs.size != 32 then
    none
  else
    let rec go (i : Nat) (acc : Nat) : Nat :=
      if h : i < 32 then
        let b := (bs.get! i).toNat
        go (i + 1) (acc * 256 + b)
      else
        acc
    some (go 0 0)

def natToBytesBE32 (n : Nat) : Bytes :=
  let rec go (k : Nat) (x : Nat) (acc : List UInt8) : List UInt8 :=
    match k with
    | 0 => acc
    | k+1 => go k (x / 256) (UInt8.ofNat (x % 256) :: acc)
  ByteArray.mk (go 32 n [])

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
  let rec build (k : Nat) (prev : Nat) : List Nat :=
    match k with
    | 0 => []
    | k+1 =>
        let next := prev + p.step
        next :: build k next
  let base := p.start :: build (p.windowSize - 1) p.start
  if p.lastJump == 0 then
    pure base
  else
    match lastTwo? base with
    | none => throw "TX_ERR_PARSE"
    | some (secLast, _) =>
        pure (replaceLast base (secLast + p.lastJump))

def clampWindowTimestamps (raw : List Nat) : Except String (List Nat) := do
  match raw with
  | [] => throw "TX_ERR_PARSE"
  | t0 :: rest =>
      if t0 > u64Max then
        throw "TX_ERR_PARSE"
      let rec go (prev : Nat) (rs : List Nat) (accRev : List Nat) : Except String (List Nat) := do
        match rs with
        | [] => pure accRev.reverse
        | t :: ts =>
            if t > u64Max then
              throw "TX_ERR_PARSE"
            let lo := prev + 1
            let hi := prev + maxTimestampStepPerBlock
            if lo > u64Max || hi > u64Max then
              throw "TX_ERR_PARSE"
            let t' := clamp t lo hi
            go t' ts (t' :: accRev)
      go t0 rest [t0]

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


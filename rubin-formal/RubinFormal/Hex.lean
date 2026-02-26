import RubinFormal.Types

namespace RubinFormal

private def hexNibble? (c : UInt8) : Option UInt8 :=
  let n := c.toNat
  if 48 ≤ n ∧ n ≤ 57 then
    some (UInt8.ofNat (n - 48))
  else if 65 ≤ n ∧ n ≤ 70 then
    some (UInt8.ofNat (n - 65 + 10))
  else if 97 ≤ n ∧ n ≤ 102 then
    some (UInt8.ofNat (n - 97 + 10))
  else
    none

def decodeHex? (input : String) : Option Bytes :=
  let s := input.trim
  let bs := s.toUTF8
  let start :=
    if bs.size >= 2 && bs.get! 0 == (UInt8.ofNat 48) && (bs.get! 1 == (UInt8.ofNat 120) || bs.get! 1 == (UInt8.ofNat 88)) then
      2
    else
      0
  let rem := bs.size - start
  if rem % 2 != 0 then
    none
  else
    Id.run <| do
      let mut out : ByteArray := ByteArray.empty
      let mut i := start
      while i < bs.size do
        let hi? := hexNibble? (bs.get! i)
        let lo? := hexNibble? (bs.get! (i + 1))
        match hi?, lo? with
        | some hi, some lo =>
            let b : UInt8 := (hi <<< 4) ||| lo
            out := out.push b
            i := i + 2
        | _, _ =>
            return none
      return some out

def decodeHexOpt? (o : Option String) : Option Bytes :=
  o.bind decodeHex?

end RubinFormal


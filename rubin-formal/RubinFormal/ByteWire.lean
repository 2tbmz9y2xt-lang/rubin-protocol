import Std

namespace RubinFormal

abbrev Byte := Nat

def encodeCompactSize (n : Nat) : List Byte :=
  if h : n < 253 then
    [n]
  else
    []

def parseCompactSize : List Byte -> Option (Nat × List Byte)
  | [] => none
  | b :: rest =>
      if b < 256 then
        if b < 253 then
          some (b, rest)
        else
          none
      else
        none

theorem parse_encodeCompactSize_roundtrip (n : Nat) (h : n < 253) :
    parseCompactSize (encodeCompactSize n) = some (n, []) := by
  have h256 : n < 256 := Nat.lt_trans h (by decide)
  simp [encodeCompactSize, parseCompactSize, h, h256]

theorem encodeCompactSize_single_byte_unique
    (n m : Nat) (hn : n < 253) (hm : m < 253)
    (hEq : encodeCompactSize n = encodeCompactSize m) :
    n = m := by
  simpa [encodeCompactSize, hn, hm] using hEq

structure TxMini where
  version : Byte
  txKind : Byte
  txNonce : Byte
deriving DecidableEq

def txMiniByteValid (tx : TxMini) : Prop :=
  tx.version < 256 ∧ tx.txKind < 256 ∧ tx.txNonce < 256

def serializeTxMini (tx : TxMini) : List Byte :=
  [tx.version, tx.txKind, tx.txNonce]

def parseTxMini : List Byte -> Option TxMini
  | [version, txKind, txNonce] =>
      if h1 : version < 256 then
        if h2 : txKind < 256 then
          if h3 : txNonce < 256 then
            some { version, txKind, txNonce }
          else
            none
        else
          none
      else
            none
  | _ => none

theorem parse_serializeTxMini_roundtrip (tx : TxMini) (h : txMiniByteValid tx) :
    parseTxMini (serializeTxMini tx) = some tx := by
  cases tx
  simp [txMiniByteValid] at h
  rcases h with ⟨h1, h2, h3⟩
  simp [serializeTxMini, parseTxMini, h1, h2, h3]

theorem parseTxMini_deterministic (bs : List Byte) (a b : TxMini)
    (ha : parseTxMini bs = some a)
    (hb : parseTxMini bs = some b) :
    a = b := by
  rw [ha] at hb
  cases hb
  rfl

end RubinFormal

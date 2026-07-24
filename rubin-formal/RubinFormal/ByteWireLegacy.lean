import Std

/-
Legacy bootstrap-only byte model.

This file intentionally models only the single-byte `CompactSize` case (`n < 253`)
plus a tiny three-byte transaction record used in early toy lemmas. It is not the
real RUBIN wire proof surface. Use `RubinFormal.ByteWireV2` for the byte-accurate
CompactSize/parser model referenced by the coverage registry.
-/
namespace RubinFormal

namespace ByteWireLegacy

abbrev Byte := Nat

def encodeCompactSizeToy (n : Nat) : List Byte :=
  if n < 253 then
    [n]
  else
    []

def parseCompactSizeToy : List Byte -> Option (Nat × List Byte)
  | [] => none
  | b :: rest =>
      if b < 256 then
        if b < 253 then
          some (b, rest)
        else
          none
      else
        none

theorem parse_encodeCompactSizeToy_roundtrip (n : Nat) (h : n < 253) :
    parseCompactSizeToy (encodeCompactSizeToy n) = some (n, []) := by
  have h256 : n < 256 := Nat.lt_trans h (by decide)
  simp [encodeCompactSizeToy, parseCompactSizeToy, h, h256]

theorem encodeCompactSizeToy_single_byte_unique
    (n m : Nat) (hn : n < 253) (hm : m < 253)
    (hEq : encodeCompactSizeToy n = encodeCompactSizeToy m) :
    n = m := by
  simpa [encodeCompactSizeToy, hn, hm] using hEq

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
      if version < 256 then
        if txKind < 256 then
          if txNonce < 256 then
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

end ByteWireLegacy

end RubinFormal

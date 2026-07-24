import RubinFormal.UtxoBasicV1
import RubinFormal.TxWirePrefixLemmas
import RubinFormal.TxWireCompactSizeLemmas
import Std.Tactic.Omega

set_option maxHeartbeats 8000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

def witnessItemStructurallyWellFormed' (w : WitnessItem) : Prop :=
  w.suiteId ≤ 0xff ∧
  w.pubkey.size ≤ UInt64.size - 1 ∧
  w.signature.size ≤ UInt64.size - 1

private theorem bytes_append_empty (bs : Bytes) : bs = bs ++ ByteArray.empty := by
  cases bs
  rename_i data
  ext <;> simp [ByteArray.append, ByteArray.empty, Array.append_assoc]

private theorem cursor_getU8_prefix_exact
    (post : Bytes)
    (b : UInt8) :
    ({ bs := RubinFormal.bytes #[b] ++ post, off := 0 } : Cursor).getU8? =
      some (b, { bs := RubinFormal.bytes #[b] ++ post, off := 1 }) := by
  simpa [ByteArray.empty] using
    (cursor_getU8_after_pre_exact
      (pre := ByteArray.empty)
      (post := post)
      (b := b))

theorem parseWitnessItem_serializeWitnessItem
    (w : WitnessItem)
    (h : witnessItemStructurallyWellFormed' w) :
    parseWitnessItem { bs := serializeWitnessItem w, off := 0 } =
      some (w, { bs := serializeWitnessItem w, off := (serializeWitnessItem w).size }) := by
  rcases h with ⟨hSuite, hPub, hSig⟩
  have hSuiteLt : w.suiteId < 256 := by omega
  have hSuiteNat : (UInt8.ofNat w.suiteId).toNat = w.suiteId := by
    simpa using uint8_ofNat_toNat_eq w.suiteId hSuiteLt
  have hSuiteSize : (RubinFormal.bytes #[UInt8.ofNat w.suiteId]).size = 1 := by
    rfl
  let pubCompact : Bytes := RubinFormal.WireEnc.compactSize w.pubkey.size
  let sigCompact : Bytes := RubinFormal.WireEnc.compactSize w.signature.size
  let rest : Bytes := pubCompact ++ (w.pubkey ++ (sigCompact ++ w.signature))
  let bs : Bytes := RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++ rest
  unfold parseWitnessItem
  unfold serializeWitnessItem
  rw [show
      RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
        RubinFormal.WireEnc.compactSize w.pubkey.size ++
        w.pubkey ++
        RubinFormal.WireEnc.compactSize w.signature.size ++
        w.signature =
      RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
        (RubinFormal.WireEnc.compactSize w.pubkey.size ++
          (w.pubkey ++
            (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))) by
        simp [cursor_bytes_left_assoc]]
  have hSuiteRead :
      Cursor.getU8?
        {
          bs := bs,
          off := 0
        } =
      some
        (UInt8.ofNat w.suiteId,
          {
            bs := bs,
            off := 1
          }) := by
    simpa [bs, rest, pubCompact, sigCompact] using
      (cursor_getU8_prefix_exact
        (post := rest)
        (b := UInt8.ofNat w.suiteId))
  rw [hSuiteRead]
  simp [hSuiteNat]
  have hCompactPub :
      Cursor.getCompactSize?
        {
          bs :=
            RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
              (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                (w.pubkey ++
                  (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
          off := 1
        } =
      some
        (w.pubkey.size,
          {
            bs :=
              RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                  (w.pubkey ++
                    (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
            off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size
          },
          true) := by
    simpa [hSuiteSize, Nat.add_assoc, cursor_bytes_left_assoc] using
      (cursor_getCompactSize_after_pre
        (pre := RubinFormal.bytes #[UInt8.ofNat w.suiteId])
        (rest := w.pubkey ++
          (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))
        (n := w.pubkey.size)
        hPub)
  have hPubBytes :
      Cursor.getBytes?
        {
          bs :=
            RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
              (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                (w.pubkey ++
                  (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
          off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size
        }
        w.pubkey.size =
      some
        (w.pubkey,
          {
            bs :=
              RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                  (w.pubkey ++
                    (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
            off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size
          }) := by
    have hPreSize :
        (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          RubinFormal.WireEnc.compactSize w.pubkey.size).size =
        1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size := by
      rw [ByteArray.size_append, hSuiteSize]
    simpa [hPreSize, Nat.add_assoc, cursor_bytes_left_assoc] using
      (cursor_getBytes_after_pre_exact
        (pre := RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          RubinFormal.WireEnc.compactSize w.pubkey.size)
        (mid := w.pubkey)
        (post := RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature)
        (n := w.pubkey.size)
        rfl)
  have hCompactSig :
      Cursor.getCompactSize?
        {
          bs :=
            RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
              (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                (w.pubkey ++
                  (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
          off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size
        } =
      some
        (w.signature.size,
          {
            bs :=
              RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                  (w.pubkey ++
                    (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
            off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size +
              (RubinFormal.WireEnc.compactSize w.signature.size).size
          },
          true) := by
    have hBsCompactSig :
        RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          (RubinFormal.WireEnc.compactSize w.pubkey.size ++
            (w.pubkey ++
              (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))) =
        (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          RubinFormal.WireEnc.compactSize w.pubkey.size ++ w.pubkey) ++
          RubinFormal.WireEnc.compactSize w.signature.size ++
          w.signature := by
      simp [cursor_bytes_left_assoc]
    have hPreSize :
        (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          RubinFormal.WireEnc.compactSize w.pubkey.size ++ w.pubkey).size =
        1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size := by
      rw [ByteArray.size_append, ByteArray.size_append, hSuiteSize]
    simpa [hBsCompactSig, hPreSize, Nat.add_assoc] using
      (cursor_getCompactSize_after_pre
        (pre := RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          RubinFormal.WireEnc.compactSize w.pubkey.size ++ w.pubkey)
        (rest := w.signature)
        (n := w.signature.size)
        hSig)
  have hSigBytes :
      Cursor.getBytes?
        {
          bs :=
            RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
              (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                (w.pubkey ++
                  (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
          off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size +
            (RubinFormal.WireEnc.compactSize w.signature.size).size
        }
        w.signature.size =
      some
        (w.signature,
          {
            bs :=
              RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                  (w.pubkey ++
                    (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
            off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size +
              (RubinFormal.WireEnc.compactSize w.signature.size).size + w.signature.size
          }) := by
    have hBsSig :
        RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          (RubinFormal.WireEnc.compactSize w.pubkey.size ++
            (w.pubkey ++
              (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))) =
        (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          RubinFormal.WireEnc.compactSize w.pubkey.size ++
          w.pubkey ++
          RubinFormal.WireEnc.compactSize w.signature.size) ++
          w.signature ++ ByteArray.empty := by
      calc
        RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
            (RubinFormal.WireEnc.compactSize w.pubkey.size ++
              (w.pubkey ++
                (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))) =
          (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
            RubinFormal.WireEnc.compactSize w.pubkey.size ++
            w.pubkey ++
            RubinFormal.WireEnc.compactSize w.signature.size) ++ w.signature := by
              simp [cursor_bytes_left_assoc]
        _ =
          (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
            RubinFormal.WireEnc.compactSize w.pubkey.size ++
            w.pubkey ++
            RubinFormal.WireEnc.compactSize w.signature.size) ++ w.signature ++ ByteArray.empty := by
              simpa using
                bytes_append_empty
                  ((RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                    RubinFormal.WireEnc.compactSize w.pubkey.size ++
                    w.pubkey ++
                    RubinFormal.WireEnc.compactSize w.signature.size) ++ w.signature)
    have hPreSize :
        (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          RubinFormal.WireEnc.compactSize w.pubkey.size ++
          w.pubkey ++
          RubinFormal.WireEnc.compactSize w.signature.size).size =
        1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size +
          (RubinFormal.WireEnc.compactSize w.signature.size).size := by
      rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, hSuiteSize]
    simpa [hBsSig, hPreSize, Nat.add_assoc] using
      (cursor_getBytes_after_pre_exact
        (pre := RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          RubinFormal.WireEnc.compactSize w.pubkey.size ++
          w.pubkey ++
          RubinFormal.WireEnc.compactSize w.signature.size)
        (mid := w.signature)
        (post := ByteArray.empty)
        (n := w.signature.size)
        rfl)
  refine ⟨(w.pubkey.size,
    {
      bs :=
        RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          (RubinFormal.WireEnc.compactSize w.pubkey.size ++
            (w.pubkey ++
              (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
      off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size
    },
    true), hCompactPub, ?_⟩
  constructor
  · refine ⟨(), by simp [requireMinimal]⟩
  · refine ⟨(w.pubkey,
      {
        bs :=
          RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
            (RubinFormal.WireEnc.compactSize w.pubkey.size ++
              (w.pubkey ++
                (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
        off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size
      }), hPubBytes, ?_⟩
    refine ⟨(w.signature.size,
      {
        bs :=
          RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
            (RubinFormal.WireEnc.compactSize w.pubkey.size ++
              (w.pubkey ++
                (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
        off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size +
          (RubinFormal.WireEnc.compactSize w.signature.size).size
      },
      true), hCompactSig, ?_⟩
    constructor
    · refine ⟨(), by simp [requireMinimal]⟩
    · refine ⟨(w.signature,
        {
          bs :=
            RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
              (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                (w.pubkey ++
                  (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature))),
          off := 1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size +
            (RubinFormal.WireEnc.compactSize w.signature.size).size + w.signature.size
        }), hSigBytes, ?_⟩
      constructor
      · rfl
      · have hSerializeWitnessItemSize :
            (serializeWitnessItem w).size =
              1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size +
                (RubinFormal.WireEnc.compactSize w.signature.size).size + w.signature.size := by
          rw [show serializeWitnessItem w =
              RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                RubinFormal.WireEnc.compactSize w.pubkey.size ++
                w.pubkey ++
                RubinFormal.WireEnc.compactSize w.signature.size ++
                w.signature by rfl]
          rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, ByteArray.size_append,
            hSuiteSize]
        have hSerializeWitnessExpandedSize :
            ByteArray.size
              (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                  (w.pubkey ++
                    (RubinFormal.WireEnc.compactSize w.signature.size ++ w.signature)))) =
              1 + (RubinFormal.WireEnc.compactSize w.pubkey.size).size + w.pubkey.size +
                (RubinFormal.WireEnc.compactSize w.signature.size).size + w.signature.size := by
          simpa [serializeWitnessItem, cursor_bytes_left_assoc] using hSerializeWitnessItemSize
        rw [hSerializeWitnessExpandedSize]

end UtxoBasicV1

end RubinFormal

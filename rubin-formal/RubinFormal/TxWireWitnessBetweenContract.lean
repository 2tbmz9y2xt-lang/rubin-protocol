import RubinFormal.TxWireWitnessPostContract

set_option maxHeartbeats 5000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private theorem singleton_bytes_size (b : UInt8) :
    (RubinFormal.bytes #[b]).size = 1 := rfl

private theorem cursor_getCompactSize_after_prefix_exact
    (pre rest : Bytes)
    (n : Nat)
    (hN : n ≤ UInt64.size - 1) :
    Cursor.getCompactSize?
      {
        bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest,
        off := pre.size
      } =
      some
        (n,
          {
            bs := pre ++ RubinFormal.WireEnc.compactSize n ++ rest,
            off := pre.size + (RubinFormal.WireEnc.compactSize n).size
          },
          true) := by
  simpa [cursor_bytes_left_assoc, Nat.add_assoc] using
    (cursor_getCompactSize_after_pre
      (pre := pre)
      (rest := rest)
      (n := n)
      hN)

private theorem cursor_getBytes_after_prefix_exact'
    (pre mid post : Bytes) :
    Cursor.getBytes?
      {
        bs := pre ++ mid ++ post,
        off := pre.size
      }
      mid.size =
      some
        (mid,
          {
            bs := pre ++ mid ++ post,
            off := pre.size + mid.size
          }) := by
  simpa [cursor_bytes_left_assoc, Nat.add_assoc] using
    (cursor_getBytes_after_pre_exact
      (pre := pre)
      (mid := mid)
      (post := post)
      (n := mid.size)
      rfl)

theorem parseWitnessItem_serializeWitnessItem_between
    (pre : Bytes)
    (w : WitnessItem)
    (post : Bytes)
    (h : witnessItemStructurallyWellFormed' w) :
    parseWitnessItem { bs := pre ++ serializeWitnessItem w ++ post, off := pre.size } =
      some
        (w,
          {
            bs := pre ++ serializeWitnessItem w ++ post,
            off := pre.size + (serializeWitnessItem w).size
          }) := by
  rcases h with ⟨hSuite, hPub, hSig⟩
  have hSuiteLt : w.suiteId < 256 := by omega
  have hSuiteNat : (UInt8.ofNat w.suiteId).toNat = w.suiteId := by
    simpa using uint8_ofNat_toNat_eq w.suiteId hSuiteLt
  have hSuiteSize : (RubinFormal.bytes #[UInt8.ofNat w.suiteId]).size = 1 := by
    rfl
  let suiteBytes : Bytes := RubinFormal.bytes #[UInt8.ofNat w.suiteId]
  let pubCompact : Bytes := RubinFormal.WireEnc.compactSize w.pubkey.size
  let sigCompact : Bytes := RubinFormal.WireEnc.compactSize w.signature.size
  let rest : Bytes := pubCompact ++ (w.pubkey ++ (sigCompact ++ (w.signature ++ post)))
  let bs : Bytes := pre ++ suiteBytes ++ rest
  unfold parseWitnessItem
  unfold serializeWitnessItem
  rw [show
      pre ++
        (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          RubinFormal.WireEnc.compactSize w.pubkey.size ++
          w.pubkey ++
          RubinFormal.WireEnc.compactSize w.signature.size ++
          w.signature) ++ post =
      pre ++
        (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          (RubinFormal.WireEnc.compactSize w.pubkey.size ++
            (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))) by
        simp [cursor_bytes_left_assoc]]
  have hSuiteRead :
      ({ bs := bs, off := pre.size } : Cursor).getU8? =
        some
          (UInt8.ofNat w.suiteId,
            {
              bs := bs,
              off := pre.size + 1
            }) := by
    simpa [bs, suiteBytes, rest, pubCompact, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getU8_after_pre_exact
        (pre := pre)
        (post := rest)
        (b := UInt8.ofNat w.suiteId))
  have hSuiteReadExp :
      ({ bs :=
          pre ++
            (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
              (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
         off := pre.size } : Cursor).getU8? =
        some
          (UInt8.ofNat w.suiteId,
            {
              bs :=
                pre ++
                  (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                    (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                      (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
              off := pre.size + 1
            }) := by
    simpa [bs, suiteBytes, rest, pubCompact, sigCompact, cursor_bytes_left_assoc] using hSuiteRead
  rw [hSuiteReadExp]
  simp [hSuiteNat]
  let pubPre : Bytes := pre ++ suiteBytes
  have hPubPreSize : pubPre.size = pre.size + 1 := by
    rw [ByteArray.size_append, hSuiteSize]
  have hCompactPub :
      Cursor.getCompactSize? { bs := bs, off := pre.size + 1 } =
        some
          (w.pubkey.size,
            {
              bs := bs,
              off := pre.size + 1 + pubCompact.size
            },
            true) := by
    rw [show bs = pubPre ++ pubCompact ++ (w.pubkey ++ (sigCompact ++ (w.signature ++ post))) by
      simp [bs, rest, pubPre, suiteBytes, pubCompact, sigCompact, cursor_bytes_left_assoc]]
    rw [← hPubPreSize]
    simpa [pubPre, suiteBytes, pubCompact, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getCompactSize_after_prefix_exact
        (pre := pubPre)
        (rest := w.pubkey ++ (sigCompact ++ (w.signature ++ post)))
        (n := w.pubkey.size)
        hPub)
  have hCompactPubExp :
      Cursor.getCompactSize?
        {
          bs :=
            pre ++
              (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                  (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
          off := pre.size + 1
        } =
      some
        (w.pubkey.size,
          {
            bs :=
              pre ++
                (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                  (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                    (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
            off := pre.size + 1 + pubCompact.size
          },
          true) := by
    simpa [bs, suiteBytes, rest, pubCompact, sigCompact, cursor_bytes_left_assoc] using hCompactPub
  let pubBytesPre : Bytes := pubPre ++ pubCompact
  have hPubBytesPreSize :
      pubBytesPre.size = pre.size + 1 + pubCompact.size := by
    rw [ByteArray.size_append, hPubPreSize]
  have hPubBytes :
      Cursor.getBytes? { bs := bs, off := pre.size + 1 + pubCompact.size } w.pubkey.size =
        some
          (w.pubkey,
            {
              bs := bs,
              off := pre.size + 1 + pubCompact.size + w.pubkey.size
            }) := by
    rw [show bs = pubBytesPre ++ w.pubkey ++ (sigCompact ++ (w.signature ++ post)) by
      simp [bs, rest, pubBytesPre, pubPre, suiteBytes, pubCompact, sigCompact, cursor_bytes_left_assoc]]
    rw [← hPubBytesPreSize]
    simpa [pubBytesPre, pubPre, suiteBytes, pubCompact, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getBytes_after_prefix_exact'
        (pre := pubBytesPre)
        (mid := w.pubkey)
        (post := sigCompact ++ (w.signature ++ post)))
  have hPubBytesExp :
      Cursor.getBytes?
        {
          bs :=
            pre ++
              (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                  (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
          off := pre.size + 1 + pubCompact.size
        }
        w.pubkey.size =
      some
        (w.pubkey,
          {
            bs :=
              pre ++
                (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                  (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                    (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
            off := pre.size + 1 + pubCompact.size + w.pubkey.size
          }) := by
    simpa [bs, suiteBytes, rest, pubCompact, sigCompact, cursor_bytes_left_assoc] using hPubBytes
  let sigPre : Bytes := pubBytesPre ++ w.pubkey
  have hSigPreSize :
      sigPre.size = pre.size + 1 + pubCompact.size + w.pubkey.size := by
    rw [ByteArray.size_append, hPubBytesPreSize]
  have hCompactSig :
      Cursor.getCompactSize?
        { bs := bs, off := pre.size + 1 + pubCompact.size + w.pubkey.size } =
        some
          (w.signature.size,
            {
              bs := bs,
              off := pre.size + 1 + pubCompact.size + w.pubkey.size + sigCompact.size
            },
            true) := by
    rw [show bs = sigPre ++ sigCompact ++ (w.signature ++ post) by
      simp [bs, rest, sigPre, pubBytesPre, pubPre, suiteBytes, pubCompact, sigCompact, cursor_bytes_left_assoc]]
    rw [← hSigPreSize]
    simpa [sigPre, pubBytesPre, pubPre, suiteBytes, pubCompact, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getCompactSize_after_prefix_exact
        (pre := sigPre)
        (rest := w.signature ++ post)
        (n := w.signature.size)
        hSig)
  have hCompactSigExp :
      Cursor.getCompactSize?
        {
          bs :=
            pre ++
              (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                  (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
          off := pre.size + 1 + pubCompact.size + w.pubkey.size
        } =
      some
        (w.signature.size,
          {
            bs :=
              pre ++
                (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                  (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                    (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
            off := pre.size + 1 + pubCompact.size + w.pubkey.size + sigCompact.size
          },
          true) := by
    simpa [bs, suiteBytes, rest, pubCompact, sigCompact, cursor_bytes_left_assoc] using hCompactSig
  let sigBytesPre : Bytes := sigPre ++ sigCompact
  have hSigBytesPreSize :
      sigBytesPre.size = pre.size + 1 + pubCompact.size + w.pubkey.size + sigCompact.size := by
    rw [ByteArray.size_append, hSigPreSize]
  have hSigBytes :
      Cursor.getBytes?
        { bs := bs, off := pre.size + 1 + pubCompact.size + w.pubkey.size + sigCompact.size }
        w.signature.size =
        some
          (w.signature,
            {
              bs := bs,
              off := pre.size + 1 + pubCompact.size + w.pubkey.size + sigCompact.size + w.signature.size
            }) := by
    rw [show bs = sigBytesPre ++ w.signature ++ post by
      simp [bs, rest, sigBytesPre, sigPre, pubBytesPre, pubPre, suiteBytes, pubCompact, sigCompact, cursor_bytes_left_assoc]]
    rw [← hSigBytesPreSize]
    simpa [sigBytesPre, sigPre, pubBytesPre, pubPre, suiteBytes, pubCompact, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getBytes_after_prefix_exact'
        (pre := sigBytesPre)
        (mid := w.signature)
        (post := post))
  have hSigBytesExp :
      Cursor.getBytes?
        {
          bs :=
            pre ++
              (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                  (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
          off := pre.size + 1 + pubCompact.size + w.pubkey.size + sigCompact.size
        }
        w.signature.size =
      some
        (w.signature,
          {
            bs :=
              pre ++
                (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                  (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                    (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
            off := pre.size + 1 + pubCompact.size + w.pubkey.size + sigCompact.size + w.signature.size
          }) := by
    simpa [bs, suiteBytes, rest, pubCompact, sigCompact, cursor_bytes_left_assoc] using hSigBytes
  refine ⟨(w.pubkey.size,
      {
        bs :=
          pre ++
            (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
              (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
        off := pre.size + 1 + pubCompact.size
      },
      true), hCompactPubExp, ?_⟩
  · constructor
    · refine ⟨(), by simp [requireMinimal]⟩
    · refine ⟨(w.pubkey,
          {
            bs :=
              pre ++
                (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                  (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                    (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
            off := pre.size + 1 + pubCompact.size + w.pubkey.size
          }),
          hPubBytesExp, ?_⟩
      · refine ⟨(w.signature.size,
          {
            bs :=
              pre ++
                (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                  (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                    (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
            off := pre.size + 1 + pubCompact.size + w.pubkey.size + sigCompact.size
          },
          true), hCompactSigExp, ?_⟩
        · constructor
          · refine ⟨(), by simp [requireMinimal]⟩
          · refine ⟨(w.signature,
              { bs :=
                  pre ++
                    (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                      (RubinFormal.WireEnc.compactSize w.pubkey.size ++
                        (w.pubkey ++ (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post))))),
                off := pre.size + 1 + pubCompact.size + w.pubkey.size + sigCompact.size + w.signature.size }),
              hSigBytesExp, ?_⟩
            · constructor
              · rfl
              · have hSerializeWitnessItemSize :
                    (serializeWitnessItem w).size =
                      1 + pubCompact.size + w.pubkey.size + sigCompact.size + w.signature.size := by
                  simp [serializeWitnessItem, suiteBytes, pubCompact, sigCompact, hSuiteSize, cursor_bytes_left_assoc,
                    ByteArray.size_append, Nat.add_assoc]
                have hSerializeWitnessExpandedSize :
                    ByteArray.size
                      (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                        RubinFormal.WireEnc.compactSize w.pubkey.size ++
                        w.pubkey ++
                        RubinFormal.WireEnc.compactSize w.signature.size ++
                        w.signature) =
                      1 + pubCompact.size + w.pubkey.size + sigCompact.size + w.signature.size := by
                  simpa [serializeWitnessItem, suiteBytes, pubCompact, sigCompact, cursor_bytes_left_assoc] using
                    hSerializeWitnessItemSize
                rw [hSerializeWitnessExpandedSize]
                simpa [Nat.add_assoc]

end UtxoBasicV1

end RubinFormal

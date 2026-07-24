import RubinFormal.TxWireWitnessContract

set_option maxHeartbeats 1000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

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

private theorem singleton_bytes_size (b : UInt8) :
    (RubinFormal.bytes #[b]).size = 1 := rfl

private theorem cursor_getCompactSize_after_singleton_prefix
    (b : UInt8)
    (mid post : Bytes)
    (n : Nat)
    (hN : n ≤ UInt64.size - 1) :
    Cursor.getCompactSize?
      {
        bs := RubinFormal.bytes #[b] ++ RubinFormal.WireEnc.compactSize n ++ mid ++ post,
        off := 1
      } =
      some
        (n,
          {
            bs := RubinFormal.bytes #[b] ++ RubinFormal.WireEnc.compactSize n ++ mid ++ post,
            off := 1 + (RubinFormal.WireEnc.compactSize n).size
          },
          true) := by
  simpa [singleton_bytes_size b, cursor_bytes_left_assoc, Nat.add_assoc] using
    (cursor_getCompactSize_after_pre
      (pre := RubinFormal.bytes #[b])
      (rest := mid ++ post)
      (n := n)
      hN)

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

theorem parseWitnessItem_serializeWitnessItem_post
    (w : WitnessItem)
    (post : Bytes)
    (h : witnessItemStructurallyWellFormed' w) :
    parseWitnessItem { bs := serializeWitnessItem w ++ post, off := 0 } =
      some (w, { bs := serializeWitnessItem w ++ post, off := (serializeWitnessItem w).size }) := by
  rcases h with ⟨hSuite, hPub, hSig⟩
  have hSuiteLt : w.suiteId < 256 := by omega
  have hSuiteNat : (UInt8.ofNat w.suiteId).toNat = w.suiteId := by
    simpa using uint8_ofNat_toNat_eq w.suiteId hSuiteLt
  have hSuiteSize : (RubinFormal.bytes #[UInt8.ofNat w.suiteId]).size = 1 := by
    rfl
  let pubCompact : Bytes := RubinFormal.WireEnc.compactSize w.pubkey.size
  let sigCompact : Bytes := RubinFormal.WireEnc.compactSize w.signature.size
  let rest : Bytes := pubCompact ++ (w.pubkey ++ (sigCompact ++ (w.signature ++ post)))
  let bs : Bytes := RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++ rest
  have hBsExpand :
      bs =
        RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
          RubinFormal.WireEnc.compactSize w.pubkey.size ++
          w.pubkey ++
          RubinFormal.WireEnc.compactSize w.signature.size ++
          w.signature ++ post := by
    simp [bs, rest, pubCompact, sigCompact, cursor_bytes_left_assoc]
  unfold parseWitnessItem
  unfold serializeWitnessItem
  rw [show
      RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
        RubinFormal.WireEnc.compactSize w.pubkey.size ++
        w.pubkey ++
        RubinFormal.WireEnc.compactSize w.signature.size ++
        w.signature ++ post =
      RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
        (RubinFormal.WireEnc.compactSize w.pubkey.size ++
          (w.pubkey ++
            (RubinFormal.WireEnc.compactSize w.signature.size ++ (w.signature ++ post)))) by
        simp [cursor_bytes_left_assoc]]
  have hSuiteRead :
      Cursor.getU8? { bs := bs, off := 0 } =
        some (UInt8.ofNat w.suiteId, { bs := bs, off := 1 }) := by
    simpa [bs, rest, pubCompact, sigCompact] using
      (cursor_getU8_prefix_exact
        (post := rest)
        (b := UInt8.ofNat w.suiteId))
  rw [hSuiteRead]
  simp [hSuiteNat]
  have hCompactPub :
      Cursor.getCompactSize? { bs := bs, off := 1 } =
        some
          (w.pubkey.size,
            { bs := bs, off := 1 + pubCompact.size },
            true) := by
    rw [hBsExpand]
    simpa [pubCompact, sigCompact, cursor_bytes_left_assoc] using
      (cursor_getCompactSize_after_singleton_prefix
        (b := UInt8.ofNat w.suiteId)
        (mid := w.pubkey)
        (post := sigCompact ++ (w.signature ++ post))
        (n := w.pubkey.size)
        hPub)
  let pubPre : Bytes := RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++ pubCompact
  have hPubPreSize :
      pubPre.size = 1 + pubCompact.size := by
    rw [ByteArray.size_append, hSuiteSize]
  have hPubBytes :
      Cursor.getBytes? { bs := bs, off := 1 + pubCompact.size } w.pubkey.size =
        some
          (w.pubkey,
            { bs := bs, off := 1 + pubCompact.size + w.pubkey.size }) := by
    rw [hBsExpand, ← hPubPreSize]
    simpa [pubPre, pubCompact, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getBytes_after_prefix_exact'
        (pre := pubPre)
        (mid := w.pubkey)
        (post := sigCompact ++ (w.signature ++ post)))
  let sigPre : Bytes := RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++ pubCompact ++ w.pubkey
  have hSigPreSize :
      sigPre.size = 1 + pubCompact.size + w.pubkey.size := by
    rw [ByteArray.size_append, ByteArray.size_append, hSuiteSize]
  have hBsSigExpand :
      bs = sigPre ++ sigCompact ++ w.signature ++ post := by
    simp [bs, rest, pubCompact, sigCompact, sigPre, cursor_bytes_left_assoc]
  have hCompactSig :
      Cursor.getCompactSize? { bs := bs, off := 1 + pubCompact.size + w.pubkey.size } =
        some
          (w.signature.size,
            { bs := bs, off := 1 + pubCompact.size + w.pubkey.size + sigCompact.size },
            true) := by
    rw [hBsSigExpand, ← hSigPreSize]
    simpa [sigPre, pubCompact, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getCompactSize_after_prefix_exact
        (pre := sigPre)
        (rest := w.signature ++ post)
        (n := w.signature.size)
        hSig)
  let sigBytesPre : Bytes := sigPre ++ sigCompact
  have hSigBytesPreSize :
      sigBytesPre.size = 1 + pubCompact.size + w.pubkey.size + sigCompact.size := by
    rw [ByteArray.size_append, hSigPreSize]
  have hSigBytes :
      Cursor.getBytes? { bs := bs, off := 1 + pubCompact.size + w.pubkey.size + sigCompact.size }
        w.signature.size =
        some
          (w.signature,
            { bs := bs, off := 1 + pubCompact.size + w.pubkey.size + sigCompact.size + w.signature.size }) := by
    rw [hBsSigExpand, ← hSigBytesPreSize]
    simpa [sigPre, sigBytesPre, pubCompact, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getBytes_after_prefix_exact'
        (pre := sigBytesPre)
        (mid := w.signature)
        (post := post))
  refine ⟨(w.pubkey.size, { bs := bs, off := 1 + pubCompact.size }, true), hCompactPub, ?_⟩
  constructor
  · refine ⟨(), by simp [requireMinimal]⟩
  · refine ⟨(w.pubkey, { bs := bs, off := 1 + pubCompact.size + w.pubkey.size }), hPubBytes, ?_⟩
    refine ⟨(w.signature.size,
      { bs := bs, off := 1 + pubCompact.size + w.pubkey.size + sigCompact.size },
      true), hCompactSig, ?_⟩
    constructor
    · refine ⟨(), by simp [requireMinimal]⟩
    · refine ⟨(w.signature,
        { bs := bs, off := 1 + pubCompact.size + w.pubkey.size + sigCompact.size + w.signature.size }),
        hSigBytes, ?_⟩
      constructor
      · rfl
      · have hSerializeWitnessItemSize :
            (serializeWitnessItem w).size =
              1 + pubCompact.size + w.pubkey.size + sigCompact.size + w.signature.size := by
          simp [serializeWitnessItem, pubCompact, sigCompact, hSuiteSize, cursor_bytes_left_assoc,
            ByteArray.size_append, Nat.add_assoc]
        have hSerializeWitnessExpandedSize :
            ByteArray.size
              (RubinFormal.bytes #[UInt8.ofNat w.suiteId] ++
                RubinFormal.WireEnc.compactSize w.pubkey.size ++
                w.pubkey ++
                RubinFormal.WireEnc.compactSize w.signature.size ++
                w.signature) =
              1 + pubCompact.size + w.pubkey.size + sigCompact.size + w.signature.size := by
          simpa [serializeWitnessItem, pubCompact, sigCompact, cursor_bytes_left_assoc] using
            hSerializeWitnessItemSize
        rw [hSerializeWitnessExpandedSize]

end UtxoBasicV1

end RubinFormal

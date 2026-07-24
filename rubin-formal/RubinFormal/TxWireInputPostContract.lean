import RubinFormal.TxWireFullContract

set_option maxHeartbeats 1000000

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private theorem wire_u32le_size (n : Nat) : (RubinFormal.WireEnc.u32le n).size = 4 := rfl

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

theorem parseInput_serializeInput_post
    (i : TxIn)
    (post : Bytes)
    (h : inputStructurallyWellFormed i) :
    parseInput { bs := serializeInput i ++ post, off := 0 } =
      some (i, { bs := serializeInput i ++ post, off := (serializeInput i).size }) := by
  rcases h with ⟨hTxid, hVout, hSeq, hSig⟩
  let voutBytes : Bytes := RubinFormal.WireEnc.u32le i.prevVout
  let sigCompact : Bytes := RubinFormal.WireEnc.compactSize i.scriptSig.size
  let bs : Bytes := i.prevTxid ++ voutBytes ++ sigCompact ++ i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence ++ post
  have hVoutSize : voutBytes.size = 4 := by
    simpa [voutBytes] using wire_u32le_size i.prevVout
  have hSeqSize : (RubinFormal.WireEnc.u32le i.sequence).size = 4 := by
    simpa using wire_u32le_size i.sequence
  have hBsExpand :
      bs =
        i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size ++
          i.scriptSig ++
          RubinFormal.WireEnc.u32le i.sequence ++
          post := by
    simp [bs, voutBytes, sigCompact, cursor_bytes_left_assoc]
  unfold parseInput
  unfold serializeInput
  rw [show
      i.prevTxid ++ RubinFormal.WireEnc.u32le i.prevVout ++
        RubinFormal.WireEnc.compactSize i.scriptSig.size ++
        i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence ++ post =
      i.prevTxid ++
        (RubinFormal.WireEnc.u32le i.prevVout ++
          (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
            (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))) by
        simp [cursor_bytes_left_assoc]]
  rw [cursor_getBytes_prefix_exact
    (pre := i.prevTxid)
    (rest := RubinFormal.WireEnc.u32le i.prevVout ++
      (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
        (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))
    (n := 32)
    hTxid]
  simp
  have hVoutRead :
      Cursor.getU32le?
        {
          bs := bs,
          off := 32
        } =
      some
        (i.prevVout,
          {
            bs := bs,
            off := 32 + 4
          }) := by
    rw [hBsExpand]
    simpa [voutBytes, sigCompact, hTxid, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getU32le_after_pre
        (pre := i.prevTxid)
        (rest := RubinFormal.WireEnc.compactSize i.scriptSig.size ++
          (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))
        (n := i.prevVout)
        hVout)
  have hCompact :
      Cursor.getCompactSize?
        {
          bs := bs,
          off := 32 + 4
        } =
      some
        (i.scriptSig.size,
          {
            bs := bs,
            off := 32 + 4 + sigCompact.size
          },
          true) := by
    let sigPre : Bytes := i.prevTxid ++ voutBytes
    have hSigPreSize : sigPre.size = 32 + 4 := by
      rw [ByteArray.size_append, hTxid, hVoutSize]
    rw [hBsExpand, ← hSigPreSize]
    simpa [sigPre, voutBytes, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getCompactSize_after_prefix_exact
        (pre := sigPre)
        (rest := i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))
        (n := i.scriptSig.size)
        hSig)
  have hSigBytes :
      Cursor.getBytes?
        {
          bs := bs,
          off := 32 + 4 + sigCompact.size
        }
        i.scriptSig.size =
      some
        (i.scriptSig,
          {
            bs := bs,
            off := 32 + 4 + sigCompact.size + i.scriptSig.size
          }) := by
    let scriptPre : Bytes := i.prevTxid ++ voutBytes ++ sigCompact
    have hScriptPreSize : scriptPre.size = 32 + 4 + sigCompact.size := by
      rw [ByteArray.size_append, ByteArray.size_append, hTxid, hVoutSize]
    rw [hBsExpand, ← hScriptPreSize]
    simpa [scriptPre, voutBytes, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getBytes_after_prefix_exact'
        (pre := scriptPre)
        (mid := i.scriptSig)
        (post := RubinFormal.WireEnc.u32le i.sequence ++ post))
  have hSeqRead :
      Cursor.getU32le?
        {
          bs := bs,
          off := 32 + 4 + sigCompact.size + i.scriptSig.size
        } =
      some
        (i.sequence,
          {
            bs := bs,
            off := 32 + 4 + sigCompact.size + i.scriptSig.size + 4
          }) := by
    let seqPre : Bytes := i.prevTxid ++ voutBytes ++ sigCompact ++ i.scriptSig
    have hSeqPreSize : seqPre.size = 32 + 4 + sigCompact.size + i.scriptSig.size := by
      rw [ByteArray.size_append, ByteArray.size_append, ByteArray.size_append, hTxid, hVoutSize]
    rw [hBsExpand, ← hSeqPreSize]
    simpa [seqPre, voutBytes, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getU32le_after_pre
        (pre := seqPre)
        (rest := post)
        (n := i.sequence)
        hSeq)
  have hVoutReadExp :
      Cursor.getU32le?
        {
          bs :=
            i.prevTxid ++
              (RubinFormal.WireEnc.u32le i.prevVout ++
                (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                  (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))),
          off := 32
        } =
      some
        (i.prevVout,
          {
            bs :=
              i.prevTxid ++
                (RubinFormal.WireEnc.u32le i.prevVout ++
                  (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                    (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))),
            off := 32 + 4
          }) := by
    simpa [bs, voutBytes, sigCompact, cursor_bytes_left_assoc] using hVoutRead
  have hCompactExp :
      Cursor.getCompactSize?
        {
          bs :=
            i.prevTxid ++
              (RubinFormal.WireEnc.u32le i.prevVout ++
                (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                  (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))),
          off := 32 + 4
        } =
      some
        (i.scriptSig.size,
          {
            bs :=
              i.prevTxid ++
                (RubinFormal.WireEnc.u32le i.prevVout ++
                  (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                    (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))),
            off := 32 + 4 + sigCompact.size
          },
          true) := by
    simpa [bs, voutBytes, sigCompact, cursor_bytes_left_assoc] using hCompact
  have hSigBytesExp :
      Cursor.getBytes?
        {
          bs :=
            i.prevTxid ++
              (RubinFormal.WireEnc.u32le i.prevVout ++
                (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                  (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))),
          off := 32 + 4 + sigCompact.size
        }
        i.scriptSig.size =
      some
        (i.scriptSig,
          {
            bs :=
              i.prevTxid ++
                (RubinFormal.WireEnc.u32le i.prevVout ++
                  (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                    (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))),
            off := 32 + 4 + sigCompact.size + i.scriptSig.size
          }) := by
    simpa [bs, voutBytes, sigCompact, cursor_bytes_left_assoc] using hSigBytes
  have hSeqReadExp :
      Cursor.getU32le?
        {
          bs :=
            i.prevTxid ++
              (RubinFormal.WireEnc.u32le i.prevVout ++
                (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                  (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))),
          off := 32 + 4 + sigCompact.size + i.scriptSig.size
        } =
      some
        (i.sequence,
          {
            bs :=
              i.prevTxid ++
                (RubinFormal.WireEnc.u32le i.prevVout ++
                  (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                    (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))),
            off := 32 + 4 + sigCompact.size + i.scriptSig.size + 4
          }) := by
    simpa [bs, voutBytes, sigCompact, cursor_bytes_left_assoc] using hSeqRead
  rw [hVoutReadExp]
  simp
  rw [hCompactExp]
  simp [requireMinimal]
  rw [hSigBytesExp]
  simp
  rw [hSeqReadExp]
  simp
  have hSerializeInputSize :
      (serializeInput i).size =
        32 + 4 + sigCompact.size + i.scriptSig.size + 4 := by
    simp [serializeInput, voutBytes, sigCompact, hTxid, hVoutSize,
      hSeqSize, ByteArray.size_append, Nat.add_assoc]
  have hSerializeInputExpandedSize :
      ByteArray.size
        (i.prevTxid ++
          RubinFormal.WireEnc.u32le i.prevVout ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size ++
          i.scriptSig ++
          RubinFormal.WireEnc.u32le i.sequence) =
        32 + 4 + sigCompact.size + i.scriptSig.size + 4 := by
    simpa [serializeInput, voutBytes, sigCompact, cursor_bytes_left_assoc] using
      hSerializeInputSize
  rw [hSerializeInputExpandedSize]

end UtxoBasicV1

end RubinFormal

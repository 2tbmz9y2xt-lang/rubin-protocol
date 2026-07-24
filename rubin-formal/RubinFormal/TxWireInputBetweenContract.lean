import RubinFormal.TxWireInputPostContract

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

theorem parseInput_serializeInput_between
    (pre : Bytes)
    (i : TxIn)
    (post : Bytes)
    (h : inputStructurallyWellFormed i) :
    parseInput { bs := pre ++ serializeInput i ++ post, off := pre.size } =
      some
        (i,
          {
            bs := pre ++ serializeInput i ++ post,
            off := pre.size + (serializeInput i).size
          }) := by
  rcases h with ⟨hTxid, hVout, hSeq, hSig⟩
  let voutBytes : Bytes := RubinFormal.WireEnc.u32le i.prevVout
  let sigCompact : Bytes := RubinFormal.WireEnc.compactSize i.scriptSig.size
  let rest : Bytes := voutBytes ++ (sigCompact ++ (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))
  let bs : Bytes := pre ++ i.prevTxid ++ rest
  have hVoutSize : voutBytes.size = 4 := by
    simpa [voutBytes] using wire_u32le_size i.prevVout
  have hSeqSize : (RubinFormal.WireEnc.u32le i.sequence).size = 4 := by
    simpa using wire_u32le_size i.sequence
  have hBsExpand :
      bs =
        pre ++
          i.prevTxid ++
          RubinFormal.WireEnc.u32le i.prevVout ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size ++
          i.scriptSig ++
          RubinFormal.WireEnc.u32le i.sequence ++
          post := by
    simp [bs, rest, voutBytes, sigCompact, cursor_bytes_left_assoc]
  unfold parseInput
  unfold serializeInput
  rw [show
      pre ++
        (i.prevTxid ++
          RubinFormal.WireEnc.u32le i.prevVout ++
          RubinFormal.WireEnc.compactSize i.scriptSig.size ++
          i.scriptSig ++ RubinFormal.WireEnc.u32le i.sequence) ++ post =
      pre ++
        (i.prevTxid ++
          (RubinFormal.WireEnc.u32le i.prevVout ++
            (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
              (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))) by
        simp [cursor_bytes_left_assoc]]
  have hTxidRead :
      Cursor.getBytes? { bs := bs, off := pre.size } 32 =
        some
          (i.prevTxid,
            {
              bs := bs,
              off := pre.size + 32
            }) := by
    simpa [bs, rest, voutBytes, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getBytes_after_pre_exact
        (pre := pre)
        (mid := i.prevTxid)
        (post := rest)
        (n := 32)
        hTxid)
  have hTxidReadExp :
      Cursor.getBytes?
        {
          bs :=
            pre ++
              (i.prevTxid ++
                (RubinFormal.WireEnc.u32le i.prevVout ++
                  (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                    (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))),
          off := pre.size
        }
        32 =
      some
        (i.prevTxid,
          {
            bs :=
              pre ++
                (i.prevTxid ++
                  (RubinFormal.WireEnc.u32le i.prevVout ++
                    (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                      (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))),
            off := pre.size + 32
          }) := by
    simpa [bs, rest, voutBytes, sigCompact, cursor_bytes_left_assoc] using hTxidRead
  rw [hTxidReadExp]
  simp
  let voutPre : Bytes := pre ++ i.prevTxid
  have hVoutPreSize : voutPre.size = pre.size + 32 := by
    rw [ByteArray.size_append, hTxid]
  have hVoutRead :
      Cursor.getU32le? { bs := bs, off := pre.size + 32 } =
        some
          (i.prevVout,
            {
              bs := bs,
              off := pre.size + 32 + 4
            }) := by
    rw [show
      bs =
        voutPre ++
          RubinFormal.WireEnc.u32le i.prevVout ++
          (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
            (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))) by
      simp [bs, rest, voutPre, voutBytes, sigCompact, cursor_bytes_left_assoc]]
    rw [← hVoutPreSize]
    simpa [voutPre, voutBytes, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getU32le_after_pre
        (pre := voutPre)
        (rest := RubinFormal.WireEnc.compactSize i.scriptSig.size ++
          (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)))
        (n := i.prevVout)
        hVout)
  have hVoutReadExp :
      Cursor.getU32le?
        {
          bs :=
            pre ++
              (i.prevTxid ++
                (RubinFormal.WireEnc.u32le i.prevVout ++
                  (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                    (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))),
          off := pre.size + 32
        } =
      some
        (i.prevVout,
          {
            bs :=
              pre ++
                (i.prevTxid ++
                  (RubinFormal.WireEnc.u32le i.prevVout ++
                    (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                      (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))),
            off := pre.size + 32 + 4
          }) := by
    simpa [bs, rest, voutBytes, sigCompact, cursor_bytes_left_assoc] using hVoutRead
  rw [hVoutReadExp]
  simp
  let sigPre : Bytes := pre ++ i.prevTxid ++ voutBytes
  have hSigPreSize : sigPre.size = pre.size + 32 + 4 := by
    rw [ByteArray.size_append, ByteArray.size_append, hTxid, hVoutSize]
  have hCompact :
      Cursor.getCompactSize? { bs := bs, off := pre.size + 32 + 4 } =
        some
          (i.scriptSig.size,
            {
              bs := bs,
              off := pre.size + 32 + 4 + sigCompact.size
            },
            true) := by
    rw [show
      bs =
        sigPre ++ RubinFormal.WireEnc.compactSize i.scriptSig.size ++
          (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post)) by
      simp [bs, rest, sigPre, voutBytes, sigCompact, cursor_bytes_left_assoc]]
    rw [← hSigPreSize]
    simpa [sigPre, voutBytes, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getCompactSize_after_prefix_exact
        (pre := sigPre)
        (rest := i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))
        (n := i.scriptSig.size)
        hSig)
  have hCompactExp :
      Cursor.getCompactSize?
        {
          bs :=
            pre ++
              (i.prevTxid ++
                (RubinFormal.WireEnc.u32le i.prevVout ++
                  (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                    (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))),
          off := pre.size + 32 + 4
        } =
      some
        (i.scriptSig.size,
          {
            bs :=
              pre ++
                (i.prevTxid ++
                  (RubinFormal.WireEnc.u32le i.prevVout ++
                    (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                      (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))),
            off := pre.size + 32 + 4 + sigCompact.size
          },
          true) := by
    simpa [bs, rest, voutBytes, sigCompact, cursor_bytes_left_assoc] using hCompact
  rw [hCompactExp]
  simp [requireMinimal]
  let scriptPre : Bytes := sigPre ++ sigCompact
  have hScriptPreSize : scriptPre.size = pre.size + 32 + 4 + sigCompact.size := by
    rw [ByteArray.size_append, hSigPreSize]
  have hSigBytes :
      Cursor.getBytes?
        { bs := bs, off := pre.size + 32 + 4 + sigCompact.size }
        i.scriptSig.size =
      some
        (i.scriptSig,
          {
            bs := bs,
            off := pre.size + 32 + 4 + sigCompact.size + i.scriptSig.size
          }) := by
    rw [show bs = scriptPre ++ i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post) by
      simp [bs, rest, scriptPre, sigPre, voutBytes, sigCompact, cursor_bytes_left_assoc]]
    rw [← hScriptPreSize]
    simpa [scriptPre, sigPre, voutBytes, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getBytes_after_prefix_exact'
        (pre := scriptPre)
        (mid := i.scriptSig)
        (post := RubinFormal.WireEnc.u32le i.sequence ++ post))
  have hSigBytesExp :
      Cursor.getBytes?
        {
          bs :=
            pre ++
              (i.prevTxid ++
                (RubinFormal.WireEnc.u32le i.prevVout ++
                  (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                    (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))),
          off := pre.size + 32 + 4 + sigCompact.size
        }
        i.scriptSig.size =
      some
        (i.scriptSig,
          {
            bs :=
              pre ++
                (i.prevTxid ++
                  (RubinFormal.WireEnc.u32le i.prevVout ++
                    (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                      (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))),
            off := pre.size + 32 + 4 + sigCompact.size + i.scriptSig.size
          }) := by
    simpa [bs, rest, voutBytes, sigCompact, cursor_bytes_left_assoc] using hSigBytes
  rw [hSigBytesExp]
  simp
  let seqPre : Bytes := scriptPre ++ i.scriptSig
  have hSeqPreSize : seqPre.size = pre.size + 32 + 4 + sigCompact.size + i.scriptSig.size := by
    rw [ByteArray.size_append, hScriptPreSize]
  have hSeqRead :
      Cursor.getU32le?
        { bs := bs, off := pre.size + 32 + 4 + sigCompact.size + i.scriptSig.size } =
      some
        (i.sequence,
          {
            bs := bs,
            off := pre.size + 32 + 4 + sigCompact.size + i.scriptSig.size + 4
          }) := by
    rw [show bs = seqPre ++ RubinFormal.WireEnc.u32le i.sequence ++ post by
      simp [bs, rest, seqPre, scriptPre, sigPre, voutBytes, sigCompact, cursor_bytes_left_assoc]]
    rw [← hSeqPreSize]
    simpa [seqPre, scriptPre, sigPre, voutBytes, sigCompact, cursor_bytes_left_assoc, Nat.add_assoc] using
      (cursor_getU32le_after_pre
        (pre := seqPre)
        (rest := post)
        (n := i.sequence)
        hSeq)
  have hSeqReadExp :
      Cursor.getU32le?
        {
          bs :=
            pre ++
              (i.prevTxid ++
                (RubinFormal.WireEnc.u32le i.prevVout ++
                  (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                    (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))),
          off := pre.size + 32 + 4 + sigCompact.size + i.scriptSig.size
        } =
      some
        (i.sequence,
          {
            bs :=
              pre ++
                (i.prevTxid ++
                  (RubinFormal.WireEnc.u32le i.prevVout ++
                    (RubinFormal.WireEnc.compactSize i.scriptSig.size ++
                      (i.scriptSig ++ (RubinFormal.WireEnc.u32le i.sequence ++ post))))),
            off := pre.size + 32 + 4 + sigCompact.size + i.scriptSig.size + 4
          }) := by
    simpa [bs, rest, voutBytes, sigCompact, cursor_bytes_left_assoc] using hSeqRead
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
  simpa [Nat.add_assoc]

end UtxoBasicV1

end RubinFormal

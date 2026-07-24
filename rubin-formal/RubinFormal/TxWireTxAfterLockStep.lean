import RubinFormal.TxWireTxAfterLockDaCoreExtract
import RubinFormal.TxWireTxAfterLockDaCoreRead

set_option maxHeartbeats 50000000
set_option maxRecDepth 8192

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem parseTxAfterLock_after_read_extract
    (txBytes daCoreBytes : Bytes)
    (ver tk nonce : Nat)
    (ins : List TxIn)
    (outs : List TxOut)
    (lock : Nat)
    (c8 c9 : Cursor)
    (daCoreLen : Nat)
    (hRead : DaCoreV1.parseDaCoreFieldsWithBytes tk c8 = some (c9, daCoreLen))
    (hExtract : txBytes.extract c8.off (c8.off + daCoreLen) = daCoreBytes) :
    parseTxAfterLock txBytes ver tk nonce ins outs lock c8 =
      parseTxAfterDaCore txBytes ver tk nonce ins outs lock daCoreBytes c9 := by
  unfold parseTxAfterLock
  simp [hRead, hExtract]

theorem parseTxAfterLock_after_pre_step
    (pre : Bytes)
    (tx : Tx)
    (h : txStructurallyWellFormed tx) :
    let pre' : Bytes := pre ++ tx.daCoreBytes
    let payloadCountBytes : Bytes := RubinFormal.WireEnc.compactSize tx.daPayloadLen
    let post : Bytes := serializeWitness tx.witness ++ payloadCountBytes ++ tx.daPayload
    let txBytes : Bytes := pre' ++ post
    parseTxAfterLock
        txBytes
        tx.version tx.txKind tx.txNonce tx.inputs tx.outputs tx.locktime
        { bs := txBytes,
          off := pre.size } =
      parseTxAfterDaCore
        txBytes
        tx.version tx.txKind tx.txNonce tx.inputs tx.outputs tx.locktime tx.daCoreBytes
        { bs := txBytes,
          off := pre'.size } := by
  let pre' : Bytes := pre ++ tx.daCoreBytes
  let payloadCountBytes : Bytes := RubinFormal.WireEnc.compactSize tx.daPayloadLen
  let post : Bytes := serializeWitness tx.witness ++ payloadCountBytes ++ tx.daPayload
  let txBytes : Bytes := pre' ++ post
  let c8 : Cursor := { bs := txBytes, off := pre.size }
  let c9 : Cursor := { bs := txBytes, off := pre.size + tx.daCoreBytes.size }
  have hRead :
      DaCoreV1.parseDaCoreFieldsWithBytes tx.txKind c8 =
        some (c9, tx.daCoreBytes.size) := by
    simpa [pre', payloadCountBytes, post, txBytes, c8, c9, Nat.add_assoc] using
      parseTxAfterLock_daCore_read_after_pre (pre := pre) (tx := tx) h
  have hExtract :
      txBytes.extract c8.off (c8.off + tx.daCoreBytes.size) = tx.daCoreBytes := by
    simpa [pre', payloadCountBytes, post, txBytes, c8, Nat.add_assoc] using
      parseTxAfterLock_daCore_extract_after_pre (pre := pre) (tx := tx)
  have hStep :=
    parseTxAfterLock_after_read_extract
      (txBytes := txBytes)
      (daCoreBytes := tx.daCoreBytes)
      (ver := tx.version)
      (tk := tx.txKind)
      (nonce := tx.txNonce)
      (ins := tx.inputs)
      (outs := tx.outputs)
      (lock := tx.locktime)
      (c8 := c8)
      (c9 := c9)
      (daCoreLen := tx.daCoreBytes.size)
      hRead
      hExtract
  simpa [pre', payloadCountBytes, post, txBytes, c8, c9, ByteArray.size_append, Nat.add_assoc] using hStep

end UtxoBasicV1

end RubinFormal

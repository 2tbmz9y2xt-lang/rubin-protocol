import RubinFormal.TxWireDaCoreContract

set_option maxHeartbeats 50000000
set_option maxRecDepth 8192

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem parseTxAfterLock_daCore_read_after_pre
    (pre : Bytes)
    (tx : Tx)
    (h : txStructurallyWellFormed tx) :
    let witnessBytes : Bytes := serializeWitness tx.witness
    let payloadCountBytes : Bytes := RubinFormal.WireEnc.compactSize tx.daPayloadLen
    let post : Bytes := witnessBytes ++ payloadCountBytes ++ tx.daPayload
    RubinFormal.DaCoreV1.parseDaCoreFieldsWithBytes tx.txKind
        { bs := pre ++ tx.daCoreBytes ++ post,
          off := pre.size } =
      some
        ({ bs := pre ++ tx.daCoreBytes ++ post,
           off := pre.size + tx.daCoreBytes.size }, tx.daCoreBytes.size) := by
  rcases h with
    ⟨_, hKind, _, _, _, _, _, _, hDaCore, _, _, _, _, _⟩
  let witnessBytes : Bytes := serializeWitness tx.witness
  let payloadCountBytes : Bytes := RubinFormal.WireEnc.compactSize tx.daPayloadLen
  let post : Bytes := witnessBytes ++ payloadCountBytes ++ tx.daPayload
  exact
    parseDaCoreFieldsWithBytes_between
      (txKind := tx.txKind)
      (pre := pre)
      (daCoreBytes := tx.daCoreBytes)
      (post := post)
      hKind
      hDaCore

end UtxoBasicV1

end RubinFormal

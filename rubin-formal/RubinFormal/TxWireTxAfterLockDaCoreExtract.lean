import RubinFormal.TxWireExtractExact

set_option maxHeartbeats 50000000
set_option maxRecDepth 8192

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem parseTxAfterLock_daCore_extract_after_pre
    (pre : Bytes)
    (tx : Tx) :
    let witnessBytes : Bytes := serializeWitness tx.witness
    let payloadCountBytes : Bytes := RubinFormal.WireEnc.compactSize tx.daPayloadLen
    let post : Bytes := witnessBytes ++ payloadCountBytes ++ tx.daPayload
    (pre ++ tx.daCoreBytes ++ post).extract pre.size
        (pre.size + tx.daCoreBytes.size) =
      tx.daCoreBytes := by
  let witnessBytes : Bytes := serializeWitness tx.witness
  let payloadCountBytes : Bytes := RubinFormal.WireEnc.compactSize tx.daPayloadLen
  let post : Bytes := witnessBytes ++ payloadCountBytes ++ tx.daPayload
  exact
    extract_after_pre_exact
      (pre := pre)
      (mid := tx.daCoreBytes)
      (post := post)

end UtxoBasicV1

end RubinFormal

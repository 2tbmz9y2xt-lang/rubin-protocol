import RubinFormal.TxWireTxAfterLockStep

set_option maxHeartbeats 8000000
set_option maxRecDepth 8192

namespace RubinFormal

open Wire

namespace UtxoBasicV1

theorem parseTxAfterLock_of_afterDaCore_ok
    (txBytes : Bytes)
    (ver tk nonce : Nat)
    (ins : List TxIn)
    (outs : List TxOut)
    (lock : Nat)
    (daCoreBytes : Bytes)
    (c8 c9 : Cursor)
    (txVal : Tx)
    (hStep :
      parseTxAfterLock txBytes ver tk nonce ins outs lock c8 =
        parseTxAfterDaCore txBytes ver tk nonce ins outs lock daCoreBytes c9)
    (hOk :
      parseTxAfterDaCore txBytes ver tk nonce ins outs lock daCoreBytes c9 =
        Except.ok txVal) :
    parseTxAfterLock txBytes ver tk nonce ins outs lock c8 = Except.ok txVal := by
  rw [hStep, hOk]

end UtxoBasicV1

end RubinFormal

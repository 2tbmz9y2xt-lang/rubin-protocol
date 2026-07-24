import RubinFormal.TxWireTxWitnessReadContract

set_option maxHeartbeats 50000000
set_option maxRecDepth 8192

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private theorem witnessItemStructurallyWellFormed_to_prime
    (w : WitnessItem)
    (h : witnessItemStructurallyWellFormed w) :
    witnessItemStructurallyWellFormed' w := h

theorem parseTxAfterDaCore_of_parseWitness_some_withWitness
    (tx : Bytes)
    (ver tk nonce : Nat)
    (ins : List TxIn)
    (outs : List TxOut)
    (lock : Nat)
    (daCoreBytes : Bytes)
    (c9 : Cursor)
    (wit : List WitnessItem)
    (cW : Cursor)
    (hParse : parseWitness c9 = some (wit, cW)) :
    parseTxAfterDaCore tx ver tk nonce ins outs lock daCoreBytes c9 =
      parseTxAfterDaCoreWithWitness tx ver tk nonce ins outs lock daCoreBytes wit cW := by
  unfold parseTxAfterDaCore
  rw [hParse]
  rfl

theorem parseTxAfterDaCore_after_pre_step
    (pre : Bytes)
    (tx : Tx)
    (h : txStructurallyWellFormed tx) :
    let post : Bytes := RubinFormal.WireEnc.compactSize tx.daPayloadLen ++ tx.daPayload
    let txBytes : Bytes := pre ++ serializeWitness tx.witness ++ post
    parseTxAfterDaCore
        txBytes
        tx.version tx.txKind tx.txNonce tx.inputs tx.outputs tx.locktime tx.daCoreBytes
        { bs := txBytes, off := pre.size } =
      parseTxAfterDaCoreWithWitness
        txBytes
        tx.version tx.txKind tx.txNonce tx.inputs tx.outputs tx.locktime tx.daCoreBytes tx.witness
        { bs := txBytes, off := pre.size + (serializeWitness tx.witness).size } := by
  rcases h with
    ⟨_, _, _, _, _, _, _, _, _, hWitnessWF, hWitnessLen, _, _, _⟩
  have hWitnessWF' : ∀ w, w ∈ tx.witness → witnessItemStructurallyWellFormed' w := by
    intro w hw
    exact witnessItemStructurallyWellFormed_to_prime w (hWitnessWF w hw)
  let post : Bytes := RubinFormal.WireEnc.compactSize tx.daPayloadLen ++ tx.daPayload
  let txBytes : Bytes := pre ++ serializeWitness tx.witness ++ post
  have hParse :
      parseWitness
          { bs := txBytes, off := pre.size } =
        some
          (tx.witness,
            { bs := txBytes, off := pre.size + (serializeWitness tx.witness).size }) := by
    exact
      parseWitness_tx_after_pre_of_wf
        (pre := pre)
        (wit := tx.witness)
        (daPayloadLen := tx.daPayloadLen)
        (daPayload := tx.daPayload)
        hWitnessLen
        hWitnessWF'
  exact
    parseTxAfterDaCore_of_parseWitness_some_withWitness
      (tx := txBytes)
      (ver := tx.version)
      (tk := tx.txKind)
      (nonce := tx.txNonce)
      (ins := tx.inputs)
      (outs := tx.outputs)
      (lock := tx.locktime)
      (daCoreBytes := tx.daCoreBytes)
      (c9 := { bs := txBytes, off := pre.size })
      (wit := tx.witness)
      (cW := { bs := txBytes, off := pre.size + (serializeWitness tx.witness).size })
      hParse

end UtxoBasicV1

end RubinFormal

import RubinFormal.TxWireListContract

set_option maxHeartbeats 50000000
set_option maxRecDepth 8192

namespace RubinFormal

open Wire

namespace UtxoBasicV1

private theorem witnessItemStructurallyWellFormed_to_prime
    (w : WitnessItem)
    (h : witnessItemStructurallyWellFormed w) :
    witnessItemStructurallyWellFormed' w := h

theorem parseWitness_tx_after_pre_of_wf
    (pre : Bytes)
    (wit : List WitnessItem)
    (daPayloadLen : Nat)
    (daPayload : Bytes)
    (hLen : wit.length ≤ UInt64.size - 1)
    (hWF' : ∀ w, w ∈ wit → witnessItemStructurallyWellFormed' w) :
    let post : Bytes := RubinFormal.WireEnc.compactSize daPayloadLen ++ daPayload
    parseWitness
        { bs := pre ++ serializeWitness wit ++ post,
          off := pre.size } =
      some
        (wit,
          { bs := pre ++ serializeWitness wit ++ post,
            off := pre.size + (serializeWitness wit).size }) := by
  exact
    parseWitness_serializeWitness_between
      (pre := pre)
      (wit := wit)
      (post := RubinFormal.WireEnc.compactSize daPayloadLen ++ daPayload)
      hLen
      hWF'

end UtxoBasicV1

end RubinFormal

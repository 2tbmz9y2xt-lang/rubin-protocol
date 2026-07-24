import RubinFormal.BlockValidationOrder
namespace RubinFormal
open BlockBasicV1

/-- Section 25 behavioral closure: every input is either accepted
    (with full §25 witness) or rejected (with error). -/
theorem section25_behavioral_closed
    (blockBytes : Bytes) (ph pt : Option Bytes) :
    section25AcceptWitness blockBytes ph pt ∨
    (∃ err, validateBlockBasic blockBytes ph pt = .error err) :=
  validateBlockBasic_accept_or_reject blockBytes ph pt

end RubinFormal

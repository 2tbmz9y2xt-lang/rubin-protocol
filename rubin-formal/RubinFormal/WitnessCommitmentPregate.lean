import RubinFormal.BlockValidationOrder
namespace RubinFormal
open BlockBasicV1

/-- Witness commitment check is reached only after parse+PoW pass.
    Uses existing validateBlockBasic_pow_passes from BlockValidationOrder. -/
theorem witness_commitment_requires_parse_pow
    (blockBytes : Bytes) (ph pt : Option Bytes)
    (hOk : validateBlockBasic blockBytes ph pt = .ok ()) :
    ∃ pb, parseBlock blockBytes = .ok pb ∧ powCheck pb.header = .ok () :=
  let ⟨pb, hp, hpow, _⟩ := validateBlockBasic_pow_passes blockBytes ph pt hOk
  ⟨pb, hp, hpow⟩

end RubinFormal

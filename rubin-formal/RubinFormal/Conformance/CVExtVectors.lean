-- Placeholder for CV-EXT conformance vectors.
-- Full Lean replay requires Q-FORMAL-CORE-EXT-01.

namespace RubinFormal.Conformance

structure CVExtVector where
  id : String
  covenantDataHex : String
  expectOk : Bool
  expectErr : Option String

def cvExtVectors : List CVExtVector := [
  { id := "CV-EXT-01", covenantDataHex := "0x001000", expectOk := true, expectErr := none },
  { id := "CV-EXT-02", covenantDataHex := "0x01", expectOk := false, expectErr := some "TX_ERR_COVENANT_TYPE_INVALID" },
  { id := "CV-EXT-03", covenantDataHex := "0x001000", expectOk := true, expectErr := none },
  { id := "CV-EXT-04", covenantDataHex := "0x00100101", expectOk := false, expectErr := some "TX_ERR_SIG_ALG_INVALID" },
  { id := "CV-EXT-05", covenantDataHex := "0x0010050102", expectOk := false, expectErr := some "TX_ERR_COVENANT_TYPE_INVALID" },
  { id := "CV-EXT-06", covenantDataHex := "0x070000", expectOk := false, expectErr := some "TX_ERR_COVENANT_TYPE_INVALID" }
]

end RubinFormal.Conformance

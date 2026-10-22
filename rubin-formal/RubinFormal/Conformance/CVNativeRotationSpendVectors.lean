-- Manually maintained legacy model; IDs are owned by CV-NATIVE-ROTATION-SPEND.json.
-- Bounded suite-list replay only; retained *-02 rows differ from JSON semantics.

set_option maxHeartbeats 10000000
set_option maxRecDepth 50000

namespace RubinFormal.Conformance

structure CVNativeRotationSpendVector where
  id : String
  height : Nat
  suiteId : Nat
  oldSuiteId : Nat
  newSuiteId : Nat
  spendHeight : Nat
  expectOk : Bool

def cvNativeRotationSpendVectors : List CVNativeRotationSpendVector := [
  -- CORE_P2PK
  { id := "NATIVE-ROT-SPEND-P2PK-01", height := 199, suiteId := 1, oldSuiteId := 1, newSuiteId := 2, spendHeight := 200, expectOk := true },
  { id := "NATIVE-ROT-SPEND-P2PK-02", height := 199, suiteId := 2, oldSuiteId := 1, newSuiteId := 2, spendHeight := 200, expectOk := false },
  { id := "NATIVE-ROT-SPEND-P2PK-03", height := 200, suiteId := 2, oldSuiteId := 1, newSuiteId := 2, spendHeight := 200, expectOk := true },
  -- CORE_MULTISIG
  { id := "NATIVE-ROT-SPEND-MULTISIG-01", height := 199, suiteId := 1, oldSuiteId := 1, newSuiteId := 2, spendHeight := 200, expectOk := true },
  { id := "NATIVE-ROT-SPEND-MULTISIG-02", height := 199, suiteId := 2, oldSuiteId := 1, newSuiteId := 2, spendHeight := 200, expectOk := false },
  { id := "NATIVE-ROT-SPEND-MULTISIG-03", height := 200, suiteId := 2, oldSuiteId := 1, newSuiteId := 2, spendHeight := 200, expectOk := true },
  -- CORE_VAULT
  { id := "NATIVE-ROT-SPEND-VAULT-01", height := 199, suiteId := 1, oldSuiteId := 1, newSuiteId := 2, spendHeight := 200, expectOk := true },
  { id := "NATIVE-ROT-SPEND-VAULT-02", height := 199, suiteId := 2, oldSuiteId := 1, newSuiteId := 2, spendHeight := 200, expectOk := false },
  { id := "NATIVE-ROT-SPEND-VAULT-03", height := 200, suiteId := 2, oldSuiteId := 1, newSuiteId := 2, spendHeight := 200, expectOk := true }
]

end RubinFormal.Conformance


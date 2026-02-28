import RubinFormal.Conformance.Index

namespace RubinFormal.Conformance

private def collectFails {α : Type} (xs : List α) (idOf : α → String) (ok : α → Bool) : List String :=
  xs.foldl (fun acc x => if ok x then acc else acc.concat (idOf x)) []

private def reportGate (name : String) (fails : List String) : IO Bool := do
  if fails.isEmpty then
    IO.println s!"[OK]   {name}"
    pure true
  else
    IO.println s!"[FAIL] {name} ({fails.length} failures)"
    let preview := fails.take 20
    for fid in preview do
      IO.println s!"  - {fid}"
    if fails.length > preview.length then
      IO.println s!"  ... +{fails.length - preview.length} more"
    pure false

def run : IO UInt32 := do
  let mut okAll := true

  okAll := (← reportGate "CV-PARSE" (collectFails cvParseVectors (·.id) checkParseVector)) && okAll
  okAll := (← reportGate "CV-MERKLE" (collectFails cvMerkleVectors (·.id) checkMerkleVector)) && okAll
  okAll := (← reportGate "CV-OUTPUT-DESCRIPTOR" (collectFails cvOutputDescriptorVectors (·.id) checkODVector)) && okAll
  okAll := (← reportGate "CV-SIGHASH" (collectFails cvSighashVectors (·.id) sighashVectorPass)) && okAll
  okAll := (← reportGate "CV-POW" (collectFails cvPowVectors (·.id) powVectorPass)) && okAll
  okAll := (← reportGate "CV-WEIGHT" (collectFails cvWeightVectors (·.id) weightVectorPass)) && okAll
  okAll := (← reportGate "CV-UTXO-BASIC" (collectFails cvUtxoBasicVectors (·.id) vectorPass)) && okAll
  okAll := (← reportGate "CV-BLOCK-BASIC" (collectFails cvBlockBasicVectors (·.id) checkBlockBasicVector)) && okAll
  okAll := (← reportGate "CV-CANONICAL-INVARIANT" (collectFails cvCanonicalInvariantVectors (·.id) checkCanonicalInvariantVector)) && okAll
  okAll := (← reportGate "CV-SUBSIDY" (collectFails cvSubsidyVectors (·.id) subsidyVectorPass)) && okAll
  okAll := (← reportGate "CV-DA-INTEGRITY" (collectFails cvDaIntegrityVectors (·.id) daIntegrityVectorPass)) && okAll
  okAll := (← reportGate "CV-COVENANT-GENESIS" (collectFails cvCovenantGenesisVectors (·.id) covenantGenesisVectorPass)) && okAll
  okAll := (← reportGate "CV-VAULT" (collectFails cvUtxoApplyVectors_CV_VAULT (·.id) vaultVectorPass)) && okAll
  okAll := (← reportGate "CV-HTLC" (collectFails cvUtxoApplyVectors_CV_HTLC (·.id) htlcVectorPass)) && okAll
  okAll := (← reportGate "CV-VAULT-POLICY" (collectFails cvVaultPolicyVectors (·.id) vaultPolicyVectorPass)) && okAll
  okAll := (← reportGate "CV-HTLC-ORDERING" (collectFails cvHtlcOrderingVectors (·.id) htlcOrderingVectorPass)) && okAll
  okAll := (← reportGate "CV-DETERMINISM" (collectFails cvDeterminismVectors (·.id) checkDeterminismVector)) && okAll
  okAll := (← reportGate "CV-FORK-CHOICE" (collectFails cvForkChoiceVectors (·.id) checkForkChoiceVector)) && okAll
  okAll := (← reportGate "CV-VALIDATION-ORDER" (collectFails cvValidationOrderVectors (·.id) checkValidationOrderVector)) && okAll
  okAll := (← reportGate "CV-REPLAY" (collectFails cvReplayVectors (·.id) checkReplayVector)) && okAll
  okAll := (← reportGate "CV-TIMESTAMP" (collectFails cvTimestampVectors (·.id) checkTimestampVector)) && okAll
  okAll := (← reportGate "CV-SIG" (collectFails cvSigVectors (·.id) checkSigVector)) && okAll
  okAll := (← reportGate "CV-COMPACT" (collectFails cvCompactVectors_CV_COMPACT (·.id) compactVectorPass)) && okAll

  if okAll then
    pure 0
  else
    pure 1

end RubinFormal.Conformance

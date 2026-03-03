import RubinFormal.Conformance.CVStealthVectors
import RubinFormal.Conformance.CVCovenantGenesisReplay
import RubinFormal.Conformance.CVUtxoBasicReplay

set_option maxHeartbeats 10000000
set_option maxRecDepth 50000

namespace RubinFormal.Conformance

def cvStealthCovenantGenesisVectorsPass : Bool :=
  cvStealthCovenantGenesisVectors.all covenantGenesisVectorPass

def cvStealthUtxoBasicVectorsPass : Bool :=
  cvStealthUtxoBasicVectors.all vectorPass

def cvStealthVectorsPass : Bool :=
  cvStealthCovenantGenesisVectorsPass && cvStealthUtxoBasicVectorsPass

#eval
  if cvStealthVectorsPass then
    ()
  else
    panic! "[FAIL] CV-STEALTH replay: cvStealthVectorsPass=false"

theorem cv_stealth_vectors_pass : True := by
  trivial

end RubinFormal.Conformance

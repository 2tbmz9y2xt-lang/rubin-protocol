import RubinFormal.Types
import RubinFormal.SubsidyV1
import RubinFormal.SHA3_256
import RubinFormal.Hex
import RubinFormal.Conformance.CVDevnetGenesisVectors
import RubinFormal.Conformance.CVDevnetGenesisReplay
import RubinFormal.Conformance.CVDevnetMaturityVectors
import RubinFormal.Conformance.CVDevnetMaturityReplay

namespace RubinFormal

open RubinFormal
open RubinFormal.SubsidyV1
open RubinFormal.Conformance

instance : Inhabited CVDevnetGenesisVector :=
  ⟨{ id := "", op := CVDevnetGenesisOp.connect_block_basic, blockHex := "", expectedPrevHashHex := none,
      expectedTargetHex := none, height := 0, alreadyGenerated := 0, sumFees := none, utxos := [],
      expectOk := false, expectErr := none }⟩

instance : Inhabited CVUtxoApplyVector_CV_DEVNET_MATURITY :=
  ⟨{ id := "", txHex := "", utxos := [], height := 0, blockTimestamp := 0, blockMtp := none,
      expectOk := true, expectErr := none, expectFee := none, expectUtxoCount := none }⟩

/-! ## Devnet genesis validity -/

def devnetGenesisVector0 : CVDevnetGenesisVector :=
  cvDevnetGenesisVectors.get! 0

theorem thm_devnet_genesis_valid_utxo :
    devnetGenesisVectorPass devnetGenesisVector0 = true := by
  native_decide

/-! ## Subsidy accumulation bounded by `MINEABLE_CAP` -/

def accumulateSubsidy : Nat → Nat
| 0 => 0
| n + 1 =>
    let generated := accumulateSubsidy n
    let subsidy := blockSubsidy (n + 1) generated
    Nat.min (generated + subsidy) MINEABLE_CAP

theorem thm_devnet_subsidy_bounded (n : Nat) :
    accumulateSubsidy n ≤ MINEABLE_CAP := by
  induction n with
  | zero =>
      simp [accumulateSubsidy, MINEABLE_CAP]
  | succ n _ih =>
      -- `Nat.min` clamps the accumulator at `MINEABLE_CAP`.
      have hmin : Nat.min (accumulateSubsidy n + blockSubsidy (n + 1) (accumulateSubsidy n)) MINEABLE_CAP
          ≤ MINEABLE_CAP := Nat.min_le_right _ _
      simpa [accumulateSubsidy] using hmin

/-! ## Chain ID determinism -/

def deriveChainId (genesisBlock : Bytes) : Bytes :=
  SHA3.sha3_256 genesisBlock

theorem thm_devnet_chainid_deterministic (g1 g2 : Bytes) (h : g1 = g2) :
    deriveChainId g1 = deriveChainId g2 := by
  simpa [deriveChainId, h]

/-! ## Coinbase maturity enforcement -/

def devnetMaturityVector0 : CVUtxoApplyVector_CV_DEVNET_MATURITY :=
  cvUtxoApplyVectors_CV_DEVNET_MATURITY.get! 0

theorem thm_devnet_coinbase_maturity :
    devnetMaturityVectorPass devnetMaturityVector0 = true := by
  native_decide

end RubinFormal

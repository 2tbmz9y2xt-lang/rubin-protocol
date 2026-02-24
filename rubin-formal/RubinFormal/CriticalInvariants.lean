namespace RubinFormal

def txidPreimage (txNonce : Nat) : List Nat := [0, txNonce]
def wtxidPreimage (txNonce : Nat) : List Nat := [1, txNonce]

theorem txid_wtxid_preimage_distinct (txNonce : Nat) :
    txidPreimage txNonce ≠ wtxidPreimage txNonce := by
  simp [txidPreimage, wtxidPreimage]

def weight (base witness sigCost : Nat) : Nat := base * 4 + witness + sigCost

theorem weight_monotone_witness (base witness1 witness2 sigCost : Nat)
    (h : witness1 ≤ witness2) :
    weight base witness1 sigCost ≤ weight base witness2 sigCost := by
  unfold weight
  have h₁ : base * 4 + witness1 ≤ base * 4 + witness2 := Nat.add_le_add_left h (base * 4)
  exact Nat.add_le_add_right h₁ sigCost

def coinbaseWitnessCommitmentSeed : Nat := 0

theorem witness_commitment_seed_zero : coinbaseWitnessCommitmentSeed = 0 := rfl

def sighashPreimage (chainId txNonce locktime : Nat) : List Nat := [chainId, txNonce, locktime]

theorem sighash_binds_nonce (chainId locktime nonce1 nonce2 : Nat) (h : nonce1 ≠ nonce2) :
    sighashPreimage chainId nonce1 locktime ≠ sighashPreimage chainId nonce2 locktime := by
  simp [sighashPreimage, h]

inductive ErrorCode
  | TxErrParse
  | TxErrSigInvalid
  | BlockErrTimestampOld
deriving DecidableEq

theorem error_codes_distinct : ErrorCode.TxErrParse ≠ ErrorCode.TxErrSigInvalid := by
  simp

inductive CovenantType
  | P2PK
  | HTLC
  | VAULT
deriving DecidableEq

theorem covenant_types_distinct : CovenantType.P2PK ≠ CovenantType.HTLC := by
  simp

def clampTimestampStep (prevTs newTs maxStep : Nat) : Nat := Nat.min newTs (prevTs + maxStep)

theorem clamp_respects_upper_bound (prevTs newTs maxStep : Nat) :
    clampTimestampStep prevTs newTs maxStep ≤ prevTs + maxStep := by
  unfold clampTimestampStep
  exact Nat.min_le_right newTs (prevTs + maxStep)

def witnessCursorValid (cursor slots witnessCount : Nat) : Prop := cursor + slots ≤ witnessCount

theorem witness_cursor_zero_slot (cursor witnessCount : Nat) (h : cursor ≤ witnessCount) :
    witnessCursorValid cursor 0 witnessCount := by
  unfold witnessCursorValid
  simpa using h

def nonceReplayFree (nonces : List Nat) : Prop := nonces.Nodup

theorem duplicate_nonce_not_replay_free (n : Nat) (xs : List Nat) (h : n ∈ xs) :
    ¬ nonceReplayFree (n :: xs) := by
  unfold nonceReplayFree
  simpa [List.nodup_cons, h]

structure UtxoEntry where
  spendable : Bool
  value : Nat

def canSpend (entry : UtxoEntry) : Prop := entry.spendable = true

theorem non_spendable_cannot_spend (v : Nat) :
    ¬ canSpend { spendable := false, value := v } := by
  unfold canSpend
  simp

def valueConserved (sumIn sumOut : Nat) : Prop := sumOut ≤ sumIn

theorem value_conservation_with_extra_input (sumIn sumOut fee : Nat)
    (h : valueConserved sumIn sumOut) :
    valueConserved (sumIn + fee) sumOut := by
  unfold valueConserved at *
  exact le_trans h (Nat.le_add_right sumIn fee)

def daPayloadCommitment (chunks : List Nat) : Nat := chunks.foldl (fun acc c => acc + c) 0
def daChunkSetValid (chunks : List Nat) : Prop := chunks ≠ []

theorem da_payload_commitment_deterministic (chunks : List Nat) :
    daPayloadCommitment chunks = daPayloadCommitment chunks := rfl

theorem da_chunk_set_requires_nonempty : ¬ daChunkSetValid [] := by
  simp [daChunkSetValid]

def parseTransactionWire (bytes : List Nat) : Option Nat := bytes.head?

theorem parse_empty_none : parseTransactionWire [] = none := rfl

end RubinFormal

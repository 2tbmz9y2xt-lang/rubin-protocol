
# RUBIN Protocol v1.0
## MASTER CANONICAL SPECIFICATION (FULL FORMAL EDITION)

Status: CANONICAL
Consensus: Deterministic UTXO + Proof-of-Work
Cryptography: Post-Quantum (ML-DSA-87, SLH-DSA, SHA3-256)
Governance: Fully Permissionless (VERSION_BITS only)
Layer-2: RETL (Non-Consensus, Anchored)

=====================================================================
TABLE OF CONTENTS
=====================================================================
I.   Design Principles
II.  Cryptographic Primitives
III. Transaction & Serialization Model
IV.  UTXO Algebra & State Transition
V.   Consensus Validation Rules
VI.  Economic Invariants
VII. VERSION_BITS Formal FSM
VIII. Fork Choice & PoW Model
IX.  Network & Liveness Model
X.   Probabilistic Security Bounds
XI.  Byzantine Threshold Analysis
XII. Economic Game-Theory Model
XIII. Attack Surface Matrix
XIV. Conformance & Coverage Matrix
XV.  Formal State Machine (TLA+ Abstract)
XVI. Coq Algebraic Invariants (Formal Summary)
XVII. RETL Layer (Non-Consensus)
XVIII. RETL Bond Model
XIX. zk Validity & FRI Model
XX.  Recursive Aggregation Architecture
XXI. Release Gates & Canonical Requirements
XXII. Formal Stability Envelope

=====================================================================
I. DESIGN PRINCIPLES
=====================================================================

1. No privileged keys.
2. No controller override.
3. Deterministic validation.
4. Pure UTXO accounting.
5. Post-quantum cryptography only.
6. Strict separation of L1 consensus and L2 execution.

=====================================================================
II. CRYPTOGRAPHIC PRIMITIVES
=====================================================================

Hash: SHA3-256

txid = SHA3-256(TxNoWitnessBytes)
block_hash = SHA3-256(BlockHeaderBytes)
hash_tx_sig = SHA3-256(preimage_tx_sig)
ctv_template_hash = SHA3-256(template_serialization)
anchor_commitment = SHA3-256(anchor_data)

Signature suites:
0x01 → ML-DSA-87
0x02 → SLH-DSA-SHA2-256s

Verification model (single mode):
digest = SHA3-256(preimage_tx_sig)
verify(pubkey, signature, digest)

Direct preimage signing forbidden.

=====================================================================
III. TRANSACTION & SERIALIZATION MODEL
=====================================================================

Canonical transaction structure:

version: u32le
input_count: CompactSize
inputs[]
output_count: CompactSize
outputs[]
locktime: u32le

Rules:
- CompactSize MUST be minimally encoded.
- parse(serialize(x)) == x
- Non-minimal encoding → TX_ERR_PARSE

=====================================================================
IV. UTXO ALGEBRA & STATE TRANSITION
=====================================================================

State at height h:

S_h = UTXO_h

UTXO entry:

UtxoEntry {
  value: u64
  covenant_type: u8
  covenant_data: bytes
  creation_height: u32
}

State transition:

S_h = ApplyBlock(S_{h-1}, B_h)

UTXO_h =
  (UTXO_{h-1} \ Spent(B_h))
  ∪ Created(B_h)

=====================================================================
V. CONSENSUS VALIDATION RULES
=====================================================================

Validation order (non-coinbase):

1. Parse
2. UTXO lookup
3. Coinbase maturity
4. Covenant binding
5. Deployment gate
6. Covenant evaluation
7. Signature verification
8. Value conservation

Order MUST NOT change.

=====================================================================
VI. ECONOMIC INVARIANTS
=====================================================================

Value conservation:
Σ(outputs.value) ≤ Σ(inputs.value)

Coinbase constraint:
Σ(coinbase_outputs.value) ≤ block_subsidy(height) + Σ(fees)

Coinbase maturity:
spend_height - creation_height ≥ 100

=====================================================================
VII. VERSION_BITS FSM
=====================================================================

States:
DEFINED → STARTED → LOCKED_IN → ACTIVE → FAILED

window_index = floor((height - START_HEIGHT)/SIGNAL_WINDOW)

Activation condition:
signal_count ≥ THRESHOLD

SIGNAL_WINDOW > 0 mandatory.

=====================================================================
VIII. FORK CHOICE & POW MODEL
=====================================================================

Select chain with highest cumulative work.

Tie-break:
lexicographically smaller block_hash.

Security assumption:
α < 0.5

=====================================================================
IX. NETWORK & LIVENESS MODEL
=====================================================================

Partially synchronous network.
After GST:
Δ bounded.

Orphan probability:
p_orphan ≈ 1 - e^{-Δ/τ}

Require:
Δ << τ

=====================================================================
X. PROBABILISTIC SECURITY BOUNDS
=====================================================================

Reorg probability:

P_reorg(k) = (α / (1 - α))^k

Finality depth:

k ≥ log(ε) / log(α / (1 - α))

=====================================================================
XI. BYZANTINE THRESHOLD ANALYSIS
=====================================================================

Safety if:
α < 0.5

Selfish mining profitable if:
α > (1 - γ) / (3 - 2γ)

=====================================================================
XII. ECONOMIC GAME-THEORY MODEL
=====================================================================

Honest payoff:
π_h = βR - C

Selfish payoff:
π_s = f(α, γ)R - C

Stable if:
π_h ≥ π_s

=====================================================================
XIII. ATTACK SURFACE MATRIX
=====================================================================

Serialization → canonical rules
Binding → formulaic rules
PoW → α threshold
Network → peer diversity
L2 equivocation → permanent invalidation
Bond spam → MIN_RETL_BOND

=====================================================================
XIV. COVERAGE MATRIX
=====================================================================

MUST cover:
- Parse vectors
- Binding vectors
- Deployment vectors
- Serialization vectors
- Coinbase vectors
- Block vectors
- Reorg vectors

Cross-client parity required.

=====================================================================
XV. FORMAL STATE MACHINE (TLA+ ABSTRACT)
=====================================================================

S_h = ApplyBlock(S_{h-1}, B_h)
Deterministic transition.
No inflation invariant.
No non-spendable leakage.

=====================================================================
XVI. COQ ALGEBRAIC INVARIANTS
=====================================================================

Theorems:
- NoDoubleSpend
- NoInflation
- Determinism
- NonSpendableSafety

=====================================================================
XVII. RETL LAYER (NON-CONSENSUS)
=====================================================================

RETLDomainDescriptor {
  retl_format_version
  evm_spec_id
  sequencer_pubkey
  genesis_state_root
  policy_flags
  bond_outpoint
}

retl_domain_id =
SHA3-256("RUBINv1-retl-domain/" || chain_id || serialize(descriptor))

=====================================================================
XVIII. RETL BOND MODEL
=====================================================================

Bond MUST:
- Be spendable UTXO
- value ≥ MIN_RETL_BOND

Domain inactive if bond absent.

=====================================================================
XIX. ZK VALIDITY MODEL
=====================================================================

State transition:
S_{n+1} = F(S_n, batch)

Proof π:
Verify(π, S_n, S_{n+1}, batch_root) = TRUE

FRI folding:
f'(x) = f(x) + ρ f(-x)

Soundness:
Pr[accept invalid] ≤ ε

=====================================================================
XX. RECURSIVE AGGREGATION
=====================================================================

π_agg = Aggregate(π₁…πₖ)
Verify(π_agg) = TRUE

Proof size ≈ O(log N)

=====================================================================
XXI. RELEASE GATES
=====================================================================

Release MUST satisfy:
- 100% vector coverage
- Cross-client parity
- Deterministic serialization
- Fuzz coverage
- FSM coverage
- Reorg tests

=====================================================================
XXII. FORMAL STABILITY ENVELOPE
=====================================================================

Under:
- α < 0.5
- PQ secure signatures
- SHA3 secure
- Deterministic implementation
- Bounded Δ

Protocol guarantees:
- No inflation
- No signature forgery
- Bounded reorg probability
- L2 isolation
- No privileged override

=====================================================================
END MASTER CANONICAL v1.0
=====================================================================

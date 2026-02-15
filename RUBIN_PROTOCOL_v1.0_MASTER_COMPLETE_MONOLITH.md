# RUBIN Protocol v1.0
## MASTER COMPLETE FORMAL SPECIFICATION

Status: CANONICAL  
Model: Fully Permissionless  
Consensus: Deterministic PQ-UTXO + Proof-of-Work (Longest Chain)  
Layer-2: RETL (Non-Consensus Anchored)  
Cryptography: ML-DSA-87 / SLH-DSA + SHA3-256

---

# I. FORMAL CONSENSUS MODEL

## 1. State Space

Let:

- 𝕌ₕ : 𝕆 → UtxoEntry is the spendable UTXO map at height h  
- 𝕊ₕ = 𝕌ₕ denotes the protocol state  
- 𝔅ₕ is the block at height h  
- 𝕋 is the set of canonical transactions

Define:

```
UtxoEntry = (value, covenant_type, covenant_data, creation_height)
```

State transition:

```
𝕊ₕ = ApplyBlock(𝕊ₕ₋₁, 𝔅ₕ)
```

Where:

```
𝕌ₕ = (𝕌ₕ₋₁ \ ⋃_{T ∈ 𝔅ₕ.txs} Spent(T)) ∪ ⋃_{T ∈ 𝔅ₕ.txs} Created(T)
```

Spent(T) = inputs of T  
Created(T) = outputs of T except non-spendable covenant types

---

# II. CRYPTOGRAPHIC PRIMITIVES

## 1. Hash Functions

The following definitions use **SHA3-256**:

```
txid               = SHA3-256(TxNoWitnessBytes(T))
block_hash         = SHA3-256(BlockHeaderBytes(B))
hash_tx_sig        = SHA3-256(preimage_tx_sig)
ctv_template_hash  = SHA3-256(template_serialization)
anchor_commitment  = SHA3-256(anchor_data)
```

Collision resistance assumption:

```
Pr[SHA3-256(x) = SHA3-256(y) ∧ x ≠ y] ≤ ε (negligible)
```

---

## 2. Signature Model

All signature verification must use:

```
digest = SHA3-256(preimage_tx_sig)
verify(pubkey, signature, digest)
```

Security assumption: ML-DSA-87 and SLH-DSA are EUF-CMA secure.

Direct signing of raw preimage not allowed.

---

# III. TRANSACTION & SERIALIZATION

## Canonical Transaction Structure

```
Tx {
  version : u32le
  input_count : CompactSize
  inputs[]
  output_count : CompactSize
  outputs[]
  locktime : u32le
}
```

Witness is excluded from txid.

### Canonical Encoding Rules

- CompactSize must be minimally encoded.  
- parse(serialize(x)) == x  
- Non-minimal encoding → TX_ERR_PARSE

---

# IV. ECONOMIC INVARIANTS

## 1. Value Conservation

For any non-coinbase transaction T:

```
Σ(outputs.value) ≤ Σ(inputs.value)
```

Where:

```
Σ(inputs.value) = ∑ UTXO[input_i].value
Σ(outputs.value) = ∑ output_j.value
```

Violation ⇒ TX_ERR_VALUE_CONSERVATION.

---

## 2. Coinbase Rules

Define subsidy function:

```
Subsidy : ℕ → ℕ
```

Then for block B at height h:

```
Σ(coinbase_outputs.value) ≤ Subsidy(h) + Σ(fees(B))
```

Total supply is bounded:

```
Supply(h) = ∑_{i=0..h} Subsidy(i)
```

---

## 3. Coinbase Maturity

```
spend_height - creation_height ≥ 100
```

Else ⇒ TX_ERR_COINBASE_IMMATURE.

---

# V. DETERMINISTIC VALIDATION ORDER

For each non-coinbase transaction:

1. Canonical parse  
2. UTXO lookup  
3. Coinbase maturity  
4. Covenant binding  
5. Deployment gate  
6. Covenant evaluation  
7. Signature verification  
8. Value conservation

This order is invariant.

---

# VI. VERSION_BITS FSM

Define finite state machine:

```
S ∈ {DEFINED, STARTED, LOCKED_IN, ACTIVE, FAILED}
```

Window:

```
window_index = floor((height - START_HEIGHT)/SIGNAL_WINDOW)
```

Signal count:

```
signal_count = |{b ∈ window : bit_flag(b.version) = 1}|
```

Transition:

```
if signal_count ≥ THRESHOLD then LOCKED_IN
```

Constraint:

```
SIGNAL_WINDOW > 0
```

---

# VII. FORK CHOICE & POW MODEL

## 1. Chainwork

```
work(B) = ⌊2^256 / target(B)⌋
ChainWork(chain) = ∑ work(Bi)
```

Canonical chain = one with greatest ChainWork.

If tie:

```
smaller block_hash lex wins
```

---

# VIII. PROBABILISTIC SECURITY

Let α ∈ (0,1) be the adversary hashrate share.

Define β = 1 − α.

### Random Walk Model

Define lead difference:

```
D_t = HonestWork(t) − AttackerWork(t)
```

Expectation:

```
E[D_{t+1} − D_t] = β − α
```

If α < 0.5, then β − α > 0.

### Catch-up Probability

Let attacker be k blocks behind:

```
q = α / β
P_catchup(k) ≤ q^k
```

As α < 0.5:

```
lim_{k→∞} q^k = 0
```

### Finality Depth Requirement

For desired reorg risk ε:

```
k ≥ log(ε) / log(q)
```

---

# IX. SELFISH MINING BOUND

Selfish mining profitable condition:

```
α > (1 − γ) / (3 − 2γ)
```

Where γ is the tie win probability.

Worst-case γ=0:

```
α > ⅓
```

---

# X. NETWORK & LATENCY MODEL

Assume partial synchrony after GST (Global Stabilization Time).

Let:

```
τ = average block time
Δ = maximum honest propagation delay
```

Define stale probability:

```
p_stale ≈ 1 − e^{−Δ/τ}
```

Security improves as Δ/τ → 0.

---

# XI. COVERAGE & CONFORMANCE MATRIX

Consensus vectors must cover:

| Category | Vector ID Prefix |
|----------|------------------|
| Parse | CV-PARSE |
| Binding | CV-BIND |
| Deployment | CV-DEP |
| Coinbase | CV-CB |
| Serialization | CV-SER |
| Block weight | CV-BLOCK |
| Reorg | CV-REORG |

All vectors MUST pass before release.

Cross-client parity mandatory.

---

# XII. RETL (NON-CONSENSUS LAYER)

### Domain Identity

```
retl_domain_id =
SHA3-256("RUBINv1-retl-domain/" || chain_id || descriptor_bytes)
```

### Bond Model

Bond must be:

- spendable UTXO
- value ≥ MIN_RETL_BOND

If no active bond, domain is inactive.

### Batch Structure

```
RETLBatch {
  retl_domain_id
  batch_number
  prev_batch_hash
  state_root
  tx_data_root
  withdrawals_root
  sequencer_sig
}
```

sequencer_sig verified over SHA3-256(signing_message).

L1 does not verify sequencer sig.

### Anti-Equivocation

If same batch_number with different state_root:

```
domain invalid forever
```

---

# XIII. ZK VALIDITY & FRI

State transition:

```
S_{n+1} = F(S_n, batch)
```

Proof π is valid if:

```
Verify(π, S_n, S_{n+1}, batch_root) = TRUE
```

FRI folding step:

```
f_{i+1}(x) = f_i(x) + ρ_i·f_i(−x)
```

Soundness:

```
Pr[accept invalid proof] ≤ ε_sound
```

Recursive aggregation of proofs:

```
π_agg = Agg(π₁ … πₖ)
```

Proof size O(log N). Verification time O(log N).

---

# XIV. FORMAL INVARIANTS

Under assumptions:

- α < 0.5
- SHA3 collision resistance
- ML-DSA EUF-CMA security
- Deterministic implementation
- Bounded network delay after GST

RUBIN guarantees:

- No inflation
- No signature forgery
- Bounded reorg probability
- L2 isolation (RETL)
- No privileged override
- Deterministic validation

---

# XV. RELEASE GATES

A release is valid if:

1. All conformance vectors pass
2. Cross-client parity
3. Deterministic serialization proven
4. Reorg replay tests pass
5. FSM coverage complete
6. Fuzz tests cover parser & covenant

---

# XVI. FIPS / CNSA COMPLIANCE PATH

## 1. Cryptographic Module Baseline

- Reference implementations for hash, signature, and key-generation operations SHALL be validated through FIPS 140-3 compliant module boundaries.
- Canonical verification libraries in production **MUST** execute through auditable builds where approved cryptographic algorithms are explicitly pinned.
- wolfCrypt integration path:
  - Algorithm profile: ML-DSA-87 + SHA3-256 for protocol-level signatures and commitments.
  - Hash and key-handling APIs are wrapped through explicit key handle abstraction to avoid algorithm confusion.
  - Deterministic test vectors must be executable without internet/network at validation time.

## 2. Parameter and Domain Separation

- Signature verification domain tags SHALL be explicit and constant-time across implementations.
- No raw preimage signing; protocol MUST serialize the preimage fields through TxSigPreimage canonicalization.
- Context-specific separation:
  - `ctx=consensus-tx`
  - `ctx=retl-batch`
  - `ctx=zk-proof`

## 3. Governance for Crypto Agility

- All cryptographic upgrades require:
  - soft-deploy candidate in staging and shadow mode,
  - formal proofs / proofs-of-concept for migration,
  - on-chain rollback condition (if activation fails threshold, revert activation path),
  - controller resolution recorded in `spec/CONTROLLER_DECISIONS.md`.
- Default migration strategy is hybrid mode first (classic + PQ), then PQ-only after confidence period and risk review.

---

# XVII. ENTERPRISE ADD-ONS AND RETL BOUNDARIES

1. RETL remains non-consensus and is not allowed to alter layer-0 state transition rules.
2. Domain signatures for public RETL domains are mandatory; private internal deployments may use a restricted profile with equivalent auditability.
3. Bond model is application-layer only and cannot be interpreted as consensus staking.
4. Enterprise extensions are separately licensed add-ons, optional at deployment time, and are explicitly outside core protocol guarantees.

---

# XVIII. OPERATIONS, ROLLOUT, AND RISK MITIGATION

## 1. Dual-sign Rollout for Post-Quantum Migration

1. Nodes and wallets maintain dual attestation state per account key:
   - classic key slot
   - PQ key slot
2. During transition, validators accept transactions carrying either scheme.
3. Shadow transaction streams run in parallel and must show no divergence before PQ-only enforcement activates.

## 2. HN/DL Threat Controls

1. Archive-sensitive payloads in short-lived encrypted blobs where long-term confidentiality is required.
2. Re-keying policies are mandatory on key rollover thresholds and post-incident remediation.
3. Public RETL message archives exposed longer than long-term safety horizon must include forward-secure storage and periodic re-wrap.

## 3. Rollback and Incident Handling

1. Any failed conformance run in mainnet shadow mode raises a circuit breaker at gate level.
2. Failed upgrade candidates are quarantined; activation is delayed until re-run passes deterministic replay and validator quorum re-approval.
3. Emergency response requires controller approval and explicit incident note in governance log.

---

# END OF SPECIFICATION

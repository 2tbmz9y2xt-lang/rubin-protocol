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


# XIX. CRYPTO-AGILITY & ALGORITHM LIFECYCLE

## 1. Multi-Algorithm Acceptance Set

At any block height h, the accepted signature set is:

```
SigSet(h) = {ML_DSA_87, SLH_DSA, (legacy_ecdsa ∧ h < legacy_cutoff)}
```

Where `legacy_cutoff` is a soft-fork-configured constant and must remain zero only in emergency mode.

## 2. Algorithm Selection Policy

- Default protocol path: `ML_DSA_87` for consensus signing and transaction authentication.
- Post-quantum fallback path: `SLH_DSA` for long-lived archival credentials and non-repudiation archives.
- Legacy fallback path: retained for compatibility until full migration window closure.

Selection is governed by on-chain activation gates and governance review in `CONTROLLER_DECISIONS`.

## 3. Safe Deprecation Semantics

An algorithm transition shall never be abrupt. For algorithm `A_old -> A_new`:

1. Announcement phase: 2 epoch notice in governance docs.
2. Shadow phase: both accepted, no enforcement bias.
3. Quarantine phase: A_old outputs flagged for audit only (non-fatal).
4. Enforcement phase: A_old rejected by consensus.
5. Rollback window: bounded rollback policy with signed controller approval.

## 4. WolfCrypt Binding Requirements

- All production nodes MUST use module wrappers that enforce algorithm identity by OID-like algorithm tags.
- Key imports into wolfCrypt must validate key-size, signature length, hash binding, and canonical prefix.
- KAT (Known Answer Test) vectors used in CI must be identical across implementations.

# XX. FORMAL POST-QUANTUM MIGRATION PROTOCOL

## 1. Dual-Sign Address Format

Each account key record MAY carry both:

- `legacy_pubkey` (optional during migration)
- `pq_pubkey` (required from migration checkpoint)

Validation rule for migration window w:

```
accept(tx_sig) :=
  (isLegacyAllowed(w) ∧ verify_legacy(tx_sig_legacy, legacy_pubkey)) ∨
  verify_ml_dsa(tx_sig_pq, pq_pubkey)
```

## 2. Shadow Transaction Replay

During transition, wallets SHOULD publish mirror transactions:

- primary stream: active signing algorithm
- shadow stream: migration candidate algorithm

Divergence invariant:

```
ReplaySet(primary) == ReplaySet(shadow)
```

Any mismatch blocks migration to enforcement phase.

## 3. Staged Rollout to Mainnet

1. Staging nets validate parser parity and conformance suite.
2. Canary shards run mixed-mode under opt-in governance.
3. Mainnet shadow-phase for N blocks with no critical divergences.
4. Final activation by explicit FSM transition and on-chain governance checkpoint.

# XXI. THREAT MODEL & MITIGATIONS (Q1 ADAPTATION)

## 1. Adversary Classes

- Computational: owns α hashrate.
- Quantum-capable offline: can attack recorded classical signatures and old sessions.
- Network: can delay/withhold up to Δ delay in partial synchrony model.
- Insider: compromised validator infrastructure or signing keys.

## 2. Harvest-Now/Decrypt-Later Controls

- Historical sensitive payloads in public channels are encrypted with hybrid session keys.
- Retention windows are bounded by rekey policies and cryptographic refresh epochs.
- Replay-safe archival proofs MUST use fresh domain separation and nonces.

## 3. L2 Boundary Threat Controls

- RETL batch signatures are required for public domains.
- Domain invalidation is immediate on equivocation detection.
- L1 never validates sequencer behavior, only anchoring commitments.

# XXII. OPERATIONAL REQUIREMENTS & HARDENING

## 1. Validator Crypto Inventory

Each validator must attest:

- secure boot / attestation chain (if available),
- HSM or equivalent protection for signing keys,
- reproducible build provenance for consensus software,
- no raw private key material in process memory dumps (strict policy).

## 2. Network Hardening

- Anti-eclipse client rotation policy.
- minimum peer diversity checks across ASNs and geographies.
- anti-DoS admission throttles for malformed signatures and invalid witness encodings.

## 3. Monitoring Gates

- chainwork delta anomaly detector,
- reorg depth alert for k > configured safety threshold,
- covenant execution failure spikes.

# XXIII. EXTENDED CONFORMANCE MATRICES

The following minimum conformance axes are mandatory for any release candidate:

1. Deterministic encode/decode roundtrip.
2. Consensus replay with reference and optimized validator implementations.
3. Crypto regression vectors for ML-DSA and SLH-DSA across implementations.
4. RETL bond lifecycle, anchor commitments, and equivocation checks.
5. FSM progression at all edge heights.

## 1. Negative Tests (Must-Fail)

- malformed compact-size encodings,
- invalid nonces and duplicated signatures,
- malformed covenant bytecode,
- invalid anchor commitments,
- anti-equviocation violations.

## 2. Positive Tests (Must-Pass)

- standard spend/receive flows,
- deep reorg replay under bounded hash-power assumptions,
- dual-sign migration mode,
- deterministic canonical serialization in all languages.

# XXIV. OPEN ISSUES FOR FUTURE REVISIONS

1. Exact parameterization of `legacy_cutoff` and migration durations.
2. Finalization thresholds for validator slashing in quantum key-rotation incidents.
3. Standardized enterprise add-on interface contract and license metadata schema.
4. Optional formalization of zk proof soundness bounds with concrete
   reduction parameters.

# XXV. END OF CURRENT EDITION

# END OF SPECIFICATION

# APPENDIX — MATHEMATICAL FORMALIZATION

## APPENDIX A — Formal Probability Space for PoW

### A.1 Block Production as Bernoulli Process

Пусть в каждом “шаге” времени производится ровно один блок (модель редуцирована к последовательности событий).
Вероятность того, что следующий блок найден атакующим:

\[
Pr[A] = \alpha,\quad Pr[H] = \beta = 1-\alpha
\]

Последовательность блоков — i.i.d. процесс Бернулли.

### A.2 Biased Random Walk

Определим разность работы:

\[
D_t = W_H(t) - W_A(t)
\]

где ( W_H, W_A ) — накопленная работа честной и атакующей цепи.

Шаг:

\[
D_{t+1} =
\begin{cases}
D_t + 1 & \text{с вероятностью } \beta \\
D_t - 1 & \text{с вероятностью } \alpha
\end{cases}
\]

Математическое ожидание шага:

\[
\mathbb{E}[D_{t+1}-D_t] = \beta - \alpha
\]

Если ( \alpha < 0.5 ), то ( \beta - \alpha > 0 ), и процесс имеет положительный дрейф.

### A.3 Catch-Up Probability

Если атакующий отстаёт на ( k ) блоков, вероятность догнать:

\[
q = \frac{\alpha}{\beta}
\]

\[
P_{\text{catchup}}(k) = q^k
\]

При ( \alpha < 0.5 \Rightarrow q < 1 \Rightarrow \lim_{k\to\infty} q^k = 0 ).

### A.4 Exact Negative Binomial Expression

Число атакующих блоков до появления ( k ) честных:

\[
X \sim \text{NegBin}(k, \beta)
\]

Тогда точная вероятность переписывания истории глубины ( k ):

\[
P_{\text{reorg}}(k)
=\sum_{i=0}^{\infty}
\binom{k+i-1}{i}
\beta^k \alpha^i
\cdot
Pr[\text{attacker overtakes from deficit } k-i]
\]

Приближение:

\[
P_{\text{reorg}}(k) \approx \left(\frac{\alpha}{\beta}\right)^k
\]

## APPENDIX B — Formal Finality Bound

Для заданной вероятности риска ( \varepsilon ):

\[
k \ge
\frac{\log(\varepsilon)}{\log(\alpha/\beta)}
\]

Пример:

\[
\alpha = 0.1,\ \varepsilon = 10^{-9}
\Rightarrow k \approx 10
\]

## APPENDIX C — Formal UTXO Algebra

### C.1 UTXO Set

\[
\mathcal{U}_h \subseteq \mathcal{O} \to \mathbb{N}
\]

где ( \mathcal{O} = {(txid, vout)} ).

Переход:

\[
\mathcal{U}_h =
(\mathcal{U}_{h-1} \setminus \text{Spent})
\cup
\text{Created}
\]

### C.2 Inflation Safety Proof Sketch

Для любого блока ( B_h ):

\[
\sum_{\text{coinbase}} \le Subsidy(h) + \sum_{\text{fees}}
\]

Так как:

* non-coinbase: ( \sum out \le \sum in )
* coinbase ограничен subsidy

Следовательно:

\[
\sum value(\mathcal{U}_h)
\le
\sum_{i=0}^h Subsidy(i)
\]

## APPENDIX D — VERSION_BITS FSM Formal Model

Состояния:

\[
S \in {DEFINED, STARTED, LOCKED_IN, ACTIVE, FAILED}
\]

Окно:

\[
W_i = [H_0 + i \cdot SIGNAL_WINDOW,\ H_0 + (i+1)\cdot SIGNAL_WINDOW)
\]

Сигнал:

\[
signal_i =
\left|\{b \in W_i : (b.version \& (1 << BIT)) \neq 0\}\right|
\]

Переход:

\[
signal_i \ge THRESHOLD \Rightarrow LOCKED_IN
\]

Монотонность:

\[
S_{h+1} \ge S_h
\]

## APPENDIX E — Partial Synchrony Model

Пусть:

* ( \tau ) — средний интервал блока
* ( \Delta ) — максимальная задержка после GST

Вероятность stale-блока:

\[
p_{stale} = 1 - e^{-\Delta/\tau}
\]

При малых ( \Delta/\tau ):

\[
p_{stale} \approx \frac{\Delta}{\tau}
\]

Требование устойчивости:

\[
\Delta \ll \tau
\]

## APPENDIX F — zk-FRI Soundness Bound

Пусть:

* ( p(x) ) — многочлен степени < d
* ( |F| ) — размер поля
* r — число запросов FRI

Soundness bound:

\[
Pr[\text{accept invalid proof}]
\le
\left(\frac{d}{|F|}\right)^r
\]

При увеличении r экспоненциальное снижение вероятности ошибки.

## APPENDIX G — Recursive Aggregation Complexity

Пусть:

* N — число батчей
* k — фактор агрегации

Тогда глубина:

\[
d = \log_k N
\]

Размер итогового доказательства:

\[
O(\log N)
\]

Верификация:

\[
O(\log N)
\]

## APPENDIX H — Composite Stability Theorem

При выполнении:

1. ( \alpha < 0.5 )
2. SHA3 collision resistance
3. ML-DSA EUF-CMA security
4. Deterministic implementation
5. ( \Delta ) bounded after GST

RUBIN удовлетворяет:

* Вероятностной финальности
* Инфляционной безопасности
* Криптографической стойкости
* Изоляции L2
* Отсутствию централизованного контроля

# END OF MATHEMATICAL APPENDIX


# APPENDIX I — FORMAL FRAMEWORK

## I.1 Primitive Notation

- `α` — attacker mining share, `β = 1 - α`.
- `D_t` — honest_work minus attacker_work at local PoW step t.
- `𝒰_h` — UTXO set at height h.
- `ApplyBlock` — deterministic state transition function over block body.
- `Verify` — deterministic signature/zk/encoding verification predicate.
- `S_h` — protocol state at height h (alias `𝒰_h` when only UTXO is needed).
- `P[X]` — probability measure over probabilistic experiment X.
- `Conf` — conformance suite.
- `SAT` — satisfaction predicate under all mandatory checks.

## I.2 Deterministic Semantics

### Definition D1 (Well-Formed Block)
A block `B` at height h is well-formed iff all header fields satisfy syntax constraints and all tx in `B.txs` pass deterministic transaction checks as defined in Section V order.

### Definition D2 (Valid Chain)
A chain is valid iff:
1) genesis is valid, and
2) each block is well-formed, and
3) each block is reference-valid w.r.t. parent via `ApplyBlock`.

### Definition D3 (Reference Validity)
A block candidate `B` is reference-valid if `ApplyBlock(S_{h-1}, B)` is total and returns a unique `S_h`.

## I.3 Core Lemmas

### Lemma L1 (Deterministic State Function)
For fixed parent state `S` and fixed block `B`, `ApplyBlock(S, B)` returns one unique state or fails with a unique rejection code.

#### Assumptions
- Parser is deterministic.
- Validation order is fixed.
- Verification functions are deterministic.

#### Sketch
All checks in Sections IV, V are pure functions over serialized bytes + current state + consensus constants. Composition of pure checks preserves determinism.

### Lemma L2 (Monotone FSM)
For VERSION_BITS state index `s_h` at block height h, `s_{h+1} ≥ s_h` under transition constraints.

#### Assumptions
- Legal transition relation excludes backward edges except allowed recovery state as specified.
- Windowed signaling uses monotone counter `signal_i`.

#### Sketch
FSM transition predicates depend on cumulative historical properties of full windows and cannot decrease state by definition of DEFINED→STARTED→LOCKED_IN→ACTIVE/FAILED progression.

### Lemma L3 (UTXO Conservation under No-Inflation Rule)
Assuming all non-coinbase txs satisfy value conservation and coinbase is bounded by subsidy + fees, total spendable value never exceeds cumulative subsidy bound.

#### Assumptions
- Every non-coinbase tx obeys `Σ outputs ≤ Σ inputs`.
- Coinbase rule from Section IV.2 is enforced.
- Outputs created are exactly what `Created(B_h)` defines.

#### Sketch
Directly by induction over h. For base h=0, bound holds by genesis definition. At step h, remove spent set then add created outputs; non-coinbase preserves input-output upper bound while coinbase introduces only subsidy+fees credit.

### Lemma L4 (Positive Drift Under Honest Majority)
If `α < 0.5`, expected drift of `D_t` is strictly positive: `E[D_{t+1}-D_t] = β-α > 0`.

#### Assumptions
- PoW step model of A.2.

#### Sketch
Substitute transition probabilities into one-step expectation.

### Lemma L5 (Eventual Divergence Escape)
Under `α < 0.5`, for any initial deficit k, `P_catchup(k)` decreases exponentially in k via `q^k`, `q=α/β < 1`.

#### Assumptions
- Random walk approximation in Appendix A.

#### Sketch
Classical random walk result for gambler’s ruin with upward drift (`β>α`).

### Lemma L6 (UTXO Set Boundedness by Index)
If no soft errors in block/tx execution, `ApplyBlock` cannot produce negative output values and cannot remove non-existent UTXOs.

#### Assumptions
- Spent set existence checks on UTXO lookup.
- Parsing rejects malformed amounts.
- Value types are integers with no underflow.

#### Sketch
All operations are guarded by preconditions before subtraction or state replacement.

## I.4 Main Theorems

### Theorem T1 (Safety: No Double Spend Under Correct State)
If two valid blocks at same height reference same parent and one of them spends an already-spent output, both cannot be jointly valid.

#### Assumptions
- UTXO lookup is strict and deterministic.
- Spent outputs are removed exactly once from `𝒰_{h-1}`.

#### Proof Sketch
The first block to spend such output transitions state with the output removed. The second, applied on same parent in valid-path reasoning, fails spent-check. Therefore no two valid children can both spend same UTXO.

### Theorem T2 (Eventual Consistency Under Valid Chain Selection)
Among finite fork candidates at fixed height window, protocol selects chain with maximum ChainWork and tie-breaker by smaller hash, so state mapping `h ↦ S_h` is functionally well-defined.

#### Assumptions
- ChainWork definition from VII.
- Tie-break order is total on block_hash bytes.

#### Proof Sketch
Fork-choice relation is total for equal heights via numeric max with deterministic tiebreak. Deterministic validity means each chosen parent yields unique child state.

### Theorem T3 (Finality Risk Bound)
Given target risk `ε`, any `k` satisfying Appendix B bound yields reorg risk ≤ ε in the PoW approximation.

#### Assumptions
- Catch-up approximation `P_reorg(k) ≈ q^k`.
- `α < 0.5` so `q<1`.

#### Proof Sketch
Algebraic rearrangement of `q^k ≤ ε` using `q<1` and monotonicity.

### Theorem T4 (RETL Isolation Invariant)
RETLayer signatures and batch commitments do not alter consensus UTXO transition semantics.

#### Assumptions
- L1 does not invoke sequencer signature checks in consensus path.
- Only optional anchor fields are parsed for availability checks.

#### Proof Sketch
`ApplyBlock` depends only on L1 fields and `B.txs`; RETL data is side-channel at consensus layer, so can not affect `𝒰_h` transitions.

### Theorem T5 (Conformance Gate Progression)
If `SAT = true` then all required checks in release gates are satisfied, and deployment of candidate spec bundle is admissible.

#### Assumptions
- Required checks list in XV and XII implemented.
- `SAT` includes negative/positive mandatory suites.

#### Sketch
Direct definitionally from release-gate contract and completeness requirement of conformance matrix.

## I.5 Counterexample Template (Invalid Configuration)

If `α ≥ 0.5`, then `q ≥ 1` and catch-up probability bound loses exponential decay, so Theorem T3 assumptions break.

Если `Verify` is non-deterministic, Lemma L1 and Theorem T2 fail (multiple possible `ApplyBlock` outcomes).

Если VERSION_BITS transitions permit backward edges, Lemma L2 fails.

## I.6 Cross-Reference Mapping

- D1, Lemma L1, L2, T2 map to Sections V, VI, VII.
- D3, L3, L6 map to Section IV and I.
- L4, L5, T3 map to Appendices A/B.
- T4 maps to XII.
- T5 maps to XV and XII.
- Soundness notation maps to Appendix F and XVIII.

# APPENDIX J — MEASURE-THEORETIC POW MODEL

## J.1 Probability Space

### Lemma J.1 (Product Bernoulli Space)

Определим вероятностное пространство:

\[
(\Omega, \mathcal{F}, \mathbb{P})
\]

где:

- \( \Omega = {H,A}^{\mathbb{N}} \) — бесконечные последовательности блоков (Honest/Attacker)
- \( \mathcal{F} \) — σ-алгебра цилиндрических множеств
- \( \mathbb{P} \) — произведение мер Бернулли:

\[
\mathbb{P}(H) = \beta,\quad
\mathbb{P}(A) = \alpha
\]

Блок-процесс является i.i.d. последовательностью.

### Lemma J.2 (IID and Canonical Increments)

---

## J.2 Random Walk as Martingale with Drift

### Lemma J.3 (Drift Formula)

Пусть:

\[
D_n = \sum_{i=1}^n X_i
\]

где:

\[
X_i =
\begin{cases}
+1 & \text{если блок честный} \\
-1 & \text{если блок атакующий}
\end{cases}
\]

Тогда:

\[
\mathbb{E}[X_i] = \beta - \alpha
\]

Если ( \alpha < 0.5 ), процесс имеет положительный дрейф.

По Strong Law of Large Numbers:

\[
\lim_{n\to\infty} \frac{D_n}{n} = \beta - \alpha
\]

почти наверное.

Следовательно:

\[
\lim_{n\to\infty} D_n = +\infty \quad \text{almost surely}
\]

### Theorem J.1 (Almost-Sure Honest Dominance)

---

# APPENDIX K — MARKOV CHAIN MODEL OF FORK COMPETITION

### Definition K.1 (Lead-State Markov Chain)

Определим состояние цепочки как разность глубины:

\[
S_t = k
\]

где k — число блоков преимущества честной цепи.

Переходы:

\[
P(k \to k+1) = \beta
\]
\[
P(k \to k-1) = \alpha
\]

Это однородная марковская цепь на \(\mathbb{Z}\).

### Lemma K.1 (Step-Transition Equations)

Вероятность достижения 0 (catch-up) из состояния k:

\[
P_{\text{hit}}(k) =
\begin{cases}
1 & \alpha \ge \beta \\
(\alpha/\beta)^k & \alpha < \beta
\end{cases}
\]

### Theorem K.1 (Catch-up Probability Threshold)

Если \(\alpha < \beta\), вероятность догонять из состояния k строго меньше 1 и убывает как \((\alpha/\beta)^k\). При \(\alpha \ge \beta\), 

\[
P_{\text{hit}}(k)=1.
\]

---

# APPENDIX L — ENTROPY ANALYSIS OF BLOCK HEADER

### Lemma L.1 (Entropy Sources)

Block header entropy sources:

- nonce
- merkle root
- timestamp
- previous block hash

Let H be SHA3-256 output.

Assume SHA3 acts as random oracle.

Entropy of header before hashing:

\[
H_{input} \approx H_{nonce} + H_{merkle}
\]

Given 256-bit hash:

\[
H_{output} \approx 256 \text{ bits}
\]

Grover attack reduces effective security to \(\approx 128\) bits, still sufficient.

### Theorem L.1 (Post-Grover Entropy Margin)

With 
\[H_{output}=256\], the quantum adversary complexity is \(\Theta(2^{128})\), preserving practical collision/discrete-search margins under honest assumptions.

---

# APPENDIX M — ADAPTIVE ADVERSARY MODEL

### Lemma M.1 (Average Workshare Bound)

Let α(t) be time-dependent attacker fraction.

Define average:

\[
\bar{\alpha}_T =
\frac{1}{T} \int_0^T \alpha(t),dt
\]

Security holds if:

\[
\limsup_{T\to\infty} \bar{\alpha}_T < 0.5
\]

Short-term burst cannot permanently alter long-term dominance.

### Theorem M.1 (Long-Run Honest Dominance)

Under the bound
\( \limsup_{T\to\infty} \bar{\alpha}_T < 0.5 \), adaptive short-term bursts do not overturn asymptotic lead persistence.

---

# APPENDIX N — DIFFICULTY ADJUSTMENT STABILITY

### Definition N.1 (Retarget Update Rule)

Retarget formula:

\[
target_{new} = target_{old} \cdot \frac{\Delta_{actual}}{\Delta_{expected}}
\]

Clamp constraint:

\[
\frac{1}{4} \le \frac{target_{new}}{target_{old}} \le 4
\]

Let hashpower jump by factor γ.

### Lemma N.1 (Clamp Bound)

Convergence condition:

\[
target_n \to equilibrium \quad \text{geometrically}
\]

Oscillation bounded by clamp.

### Theorem N.1 (Bounded Stability)

If difficulty updates respect the clamp, chain-target updates remain bounded and cannot diverge in finite time under bounded hashrate shocks.

---

# APPENDIX O — L2 COMPOSABILITY THEOREM

### Theorem O.1 (L1 Safety under L2 Anchoring)

Let:

- L1 state: \(\mathbb{S}_h\)
- L2 state: \(\mathbb{S}_h^{L2}\)

L2 publishes only commitment:

\[
anchor_commitment = SHA3(anchor_data)
\]

L1 does not interpret L2 state.

Thus:

\[
\forall h:
\mathbb{S}_h^{L2} \not\subseteq \mathbb{S}_h^{L1}
\]

Failure of L2 cannot alter \(\mathbb{S}_h\).

Isolation theorem:

\[
\text{L2 compromise} \not\Rightarrow \text{L1 safety violation}
\]

### Corollary O.1 (Non-Propagation of L2 Faults)

Failure in 
\(\mathbb{S}_h^{L2}\) does not induce a state transition rule change in 
\(\mathbb{S}_h\).

---

# APPENDIX P — COMPOSITE SECURITY ENVELOPE (FORMAL STATEMENT)

### Theorem P.1 (Composite Security Envelope)

Given:

1. ( \alpha < 0.5 )
2. SHA3-256 random oracle assumption
3. ML-DSA EUF-CMA security
4. Deterministic validation
5. Bounded Δ after GST
6. Correct VERSION_BITS activation

Then:

- Inflation impossible
- Signature forgery negligible
- Reorg probability decays exponentially
- Fork persistence probability → 0
- L2 isolation holds
- No privileged override exists

---

# END OF EXTENDED FORMAL APPENDIX


# APPENDIX Q — MEASURE-THEORETIC POW FORMALIZATION

### Definition Q.1 (σ-algebraic PoW Process)

## Q.1 Probability Space

Определим:

\[
\Omega = \{H,A\}^{\mathbb{N}}
\]

где каждый элемент \(\omega \in \Omega\) — бесконечная последовательность блоков.

σ-алгебра:

\[
\mathcal{F} = \text{σ-algebra generated by cylinder sets}
\]

Мера:

\[
\mathbb{P} = \prod_{i=1}^{\infty} \mu
\]

где:

\[
\mu(H) = \beta,\quad \mu(A) = \alpha
\]

### Lemma Q.1 (Equivalent Coin-Toss Representation)

---

## Q.2 Law of Large Numbers

### Lemma Q.2 (SLLN Convergence)

Define:

\[
X_i =
\begin{cases}
+1 & H \\
-1 & A
\end{cases}
\]

\[
D_n = \sum_{i=1}^n X_i
\]

If \(\alpha < 0.5\):

\[
\mathbb{E}[X_i] = \beta - \alpha > 0
\]

By Strong Law:

\[
\frac{D_n}{n} \to \beta - \alpha \quad a.s.
\]

Thus:

\[
D_n \to +\infty \quad a.s.
\]

Almost sure honest dominance.

### Theorem Q.1 (Consistency with Appendix J)

Model Q explicitly constructs \(\Omega,\mathcal{F},\mathbb{P}\) as an infinite Bernoulli product space and is consistent with Appendix J random-walk representation.

---

# APPENDIX R — SELFISH MINING PAYOFF DERIVATION

### Theorem R.1 (Selfish Mining Payoff Threshold)

Let:

* \(\alpha\) = attacker share
* \(\beta\) = honest share
* \(\gamma\) = tie advantage

Expected revenue ratio \(R\):

\[
R =
\frac{\alpha (1-\alpha)^2(1+\beta) + \alpha^2 \beta \gamma + \alpha^3}{\beta^2 + \alpha\beta(1+\beta) + \alpha^2}
\]

Equivalent canonical simplification used in the design text:

\[
R =
\frac{\alpha(1-\alpha)^2(1+\gamma(1-\alpha))}{1 - \alpha(1 + (2-\alpha)\alpha)}
\]

Selfish mining is profitable if:

\[
R > \alpha
\]

Solve inequality:

\[
\alpha > \frac{1-\gamma}{3-2\gamma}
\]

### Corollary R.1 (Worst-Case Threshold)

Для 
\(\gamma=0\)
получаем классический порог 
\(\alpha>1/3\).

---

# APPENDIX S — QUANTUM ENTROPY BOUND

### Lemma S.1 (Grover Complexity Shift)

Assume Grover speedup for search.

Classical brute force complexity:

\[
2^{256}
\]

Quantum complexity:

\[
2^{128}
\]

Thus effective PoW security is 128-bit under Grover.

If honest and attacker both quantum-enabled, the share \(\alpha\) is normalized by effective mining rates and remains the decision ratio for chain selection under the drift model.

Security condition remains:

\[
\alpha < 0.5
\]

### Theorem S.1 (Security Threshold under Quantum Mining)

При масштабировании вычислительных возможностей обоих классов участников одинаковым квантовым усилением порог доли атаки по модели конкуренции сохраняется.

---

# APPENDIX T — ZK-SNARK CONSTRAINT ALGEBRA

### Definition T.1 (Algebraic Constraint Language)

Let:

* \(\mathbb{F}\) = finite field
* witness vector \(w\)
* constraints represented as polynomial equations

Define circuit predicate:

\[
C(w) = 0
\]

State transition constraint:

\[
\text{MerkleRoot}(state') - F(state, tx\_batch) = 0
\]

Proof system:

\[
\pi = Prove(C, w)
\]

Verification:

\[
Verify(\pi, public\_inputs) = TRUE
\]

Soundness:

\[
\Pr[\text{false statement accepted}] \le \epsilon
\]

Completeness:

\[
\Pr[\text{true statement accepted}] = 1
\]

Knowledge-extractability assumption (standard model):

\[
\Pr[\mathcal{A}(\pi, pk) \to w^*] 
\approx 1 \Rightarrow C(w^*)=0
\]

### Lemma T.1 (Constraint Realisability)

Если witness существует и satisfies, то \(\pi=Prove(C,w)\) образует корректное доказательство в целевой системе.

### Theorem T.1 (Soundness-Completeness Contract)

Система удовлетворяет стандартной компромиссу: полнота равна 1, а soundness bounded by \(\epsilon\).

---

# APPENDIX U — ADAPTIVE ADVERSARY AS MDP

### Definition U.1 (MDP Adversary Control)

State space:

\[
\mathcal{S} = \{k : lead\,difference\}
\]

Action space:

\[
\mathcal{A} = \{mine\_honest, mine\_selfish, withhold, publish\}
\]

Transition kernel:

\[
P(s'|s,a)
\]

Reward:

\[
R(s,a)
\]

Objective:

\[
\max_{\pi \in \Pi} \mathbb{E}\left[\sum_{t=0}^{\infty} \gamma^t R(s_t, a_t)\right],\quad a_t = \pi(s_t)
\]

Stationary deterministic policy \(\pi^*\) with value \(V^{\pi^*}\).

A security regime is enforced when

\[
\forall s\in\mathcal{S}:\ V^{\pi_{honest}}(s) \ge V^{\pi}(s)
\]

for any \(\pi\) representing profitable selfish deviations, under \(\alpha < \alpha^* = \frac{1-\gamma}{3-2\gamma}\).

### Theorem U.1 (Policy Dominance Region)

При 
\(\alpha < \alpha^*\)
честная политика может быть выбрана как стационарная оптимальная и не проигрывает selfish deviations в бесконечном горизонте дисконтированных вознаграждений.

---

# APPENDIX V — COMPOSITE FORMAL THEOREM

### Theorem V.1 (Canonical Composite Security)

Under assumptions:

1. \(\alpha < 0.5\)
2. SHA3 collision resistance
3. ML-DSA EUF-CMA security
4. Deterministic implementation
5. Bounded \(\Delta\)
6. Proper VERSION_BITS FSM

Then:

- Honest chain dominance almost surely
- Inflation impossible
- Signature forgery negligible
- Fork persistence probability decays exponentially
- L2 compromise cannot affect L1
- No centralized override exists

---


# APPENDIX INDEX — UNIFIED CATALOG (A…V)

## 1. Unified Order

- A–V denote all appendix blocks currently in this file, preserving local continuity and direct cross-references.
- A–H are included in `APPENDIX — MATHEMATICAL FORMALIZATION` as a sub-block cluster.
- I–V are additional standalone advanced appendices.

## 2. Alphabetical Registry

- A `APPENDIX A — Formal Probability Space for PoW` (within `APPENDIX — MATHEMATICAL FORMALIZATION`) — base PoW probability model.
- B `APPENDIX B — Formal Finality Bound` (within `APPENDIX — MATHEMATICAL FORMALIZATION`) — finality threshold algebra.
- C `APPENDIX C — Formal UTXO Algebra` (within `APPENDIX — MATHEMATICAL FORMALIZATION`) — state transitions and inflation sketch.
- D `APPENDIX D — VERSION_BITS FSM Formal Model` (within `APPENDIX — MATHEMATICAL FORMALIZATION`) — activation state machine.
- E `APPENDIX E — Partial Synchrony Model` (within `APPENDIX — MATHEMATICAL FORMALIZATION`) — network model and stale probability.
- F `APPENDIX F — zk-FRI Soundness Bound` (within `APPENDIX — MATHEMATICAL FORMALIZATION`) — soundness probability model.
- G `APPENDIX G — Recursive Aggregation Complexity` (within `APPENDIX — MATHEMATICAL FORMALIZATION`) — complexity formulas.
- H `APPENDIX H — Composite Stability Theorem` (within `APPENDIX — MATHEMATICAL FORMALIZATION`) — global safety summary.
- I `APPENDIX I — FORMAL FRAMEWORK` — definitions, lemmas, theorems, and cross-maps.
- J `APPENDIX J — MEASURE-THEORETIC POW MODEL` — sample-space and martingale formalization.
- K `APPENDIX K — MARKOV CHAIN MODEL OF FORK COMPETITION` — fork-state transition chain.
- L `APPENDIX L — ENTROPY ANALYSIS OF BLOCK HEADER` — header entropy and effective hash randomness.
- M `APPENDIX M — ADAPTIVE ADVERSARY MODEL` — α(t) and long-run average attack bound.
- N `APPENDIX N — DIFFICULTY ADJUSTMENT STABILITY` — target retarget dynamics and bounded oscillation.
- O `APPENDIX O — L2 COMPOSABILITY THEOREM` — formal L1/L2 separation at commitment level.
- P `APPENDIX P — COMPOSITE SECURITY ENVELOPE (FORMAL STATEMENT)` — security condition implication list.
- Q `APPENDIX Q — MEASURE-THEORETIC POW FORMALIZATION` — expanded construction with SLLN statement and asymptotic dominance.
- R `APPENDIX R — SELFISH MINING PAYOFF DERIVATION` — utility ratio and profitability threshold.
- S `APPENDIX S — QUANTUM ENTROPY BOUND` — Grover bound and security interpretation.
- T `APPENDIX T — ZK-SNARK CONSTRAINT ALGEBRA` — field constraints, soundness, completeness, extractability.
- U `APPENDIX U — ADAPTIVE ADVERSARY AS MDP` — Markov decision process representation of adaptive strategies.
- V `APPENDIX V — COMPOSITE FORMAL THEOREM` — consolidated formal implications.

## 3. Cross-Reference Graph

- A, J, Q form the PoW probability chain; J and Q refine A and use tools from Q.2 in Q.
- I is the foundation for all later formal assertions and should be read before dependent theorem blocks.
- K uses the drift process defined in A and J.
- R refines selfish-mining condition stated in I assumptions and informs MDP analysis in U.
- J, K, N, and V together support chain stability under bounded latency and adaptive behavior.
- O, P, V are compositional safety consequences and should be used as a final validation checklist.

## 4. Dependency Checklist

- For inflation safety proofs: read C then H.
- For conformance and governance safety reasoning: read D, I, P, and V.
- For network-liveness and finality: read E, J, K, R, and V.
- For L2 security claims: read O, I, and P.
- For PQ/crypto claims and SNARK path: read L, T, and F.

## 5. Canonical Appendix Citation Format

Use canonical names exactly as written in section titles.

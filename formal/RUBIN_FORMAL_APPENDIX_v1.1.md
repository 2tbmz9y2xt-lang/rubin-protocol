# RUBIN Formal Appendix v1.1

Status: NON-NORMATIVE (active — toolchain selected, invariants stated, initial Lean 4 proofs started)
Date: 2026-02-18
Audience: implementers, auditors, formal-methods contributors

This appendix records the formal-verification strategy for RUBIN L1 consensus rules.
It does not modify normative consensus rules in `spec/RUBIN_L1_CANONICAL_v1.1.md`.

---

## 1. Toolchain Decision

**Selected: Lean 4**

Rationale:
- Native dependent types allow precise modeling of fixed-width integers (u8, u32, u64, u256) without external axioms.
- `Std4` and `Mathlib4` provide verified arithmetic, list/set lemmas, and finite-state machines directly applicable to VERSION_BITS and UTXO state transitions.
- Lean 4 supports extraction to verified executable code (Lean → C via `extern`), enabling future integration with the Go/Rust consensus runners.
- Active community with precedent in protocol verification (e.g., EVM formalization efforts).

Alternatives considered:
- **Coq + CompCert**: stronger extraction story, but higher onboarding cost and less active blockchain-specific library ecosystem.
- **Isabelle/HOL**: strong automation (sledgehammer), but Lean 4 preferred for team familiarity and ergonomics.
- **TLA+**: appropriate for liveness/safety of distributed protocols, insufficient for arithmetic/byte-level consensus rules. May be added in a separate TLA+ module for fork-choice and VERSION_BITS liveness.

**Repository (GitHub):**
```
https://github.com/2tbmz9y2xt-lang/rubin-formal
```
Current local formal repo (development-only, local git):
```
/Users/gpt/Documents/rubin-formal
commit: 6a51a34c9102586dff12e65769eed5fbc6554f1c
```
Legacy local workspace path (no longer in this repo):
```
formal/rubin-formal/   (moved out on 2026-02-18)
```
Before production freeze, this repository MUST exist at a stable revision and be linked
from this file with a pinned commit hash. Controller approval required before the link
is published.

Lean 4 version: `leanprover/lean4:v4.6.0` (to be pinned at freeze).
Mathlib4 version: pinned via `lake-manifest.json` in formal repo.

---

## 2. Scope

The formal model covers:

1. **Core data types** — `BlockHeader`, `Tx`, `TxInput`, `TxOutput`, `WitnessItem`, `CovenantData` as Lean 4 structures with exact byte-width fields.
2. **Serialization** — `CompactSize`, `TxBytes`, `BlockHeaderBytes` as total functions with round-trip lemmas.
3. **UTXO state machine** — `UTXOSet` as a finite map `(txid × vout) → TxOutput`; `SpendTx` and `ApplyBlock` as state transitions.
4. **Consensus validation rules** — `ValidateTx`, `ValidateBlock` as predicates over state + bytes.
5. **VERSION_BITS FSM** — deployment state as a finite automaton; monotonicity and terminal-state lemmas.
6. **Weight formula** — `BlockWeight` as a pure arithmetic function; overflow-freedom lemma.
7. **Sighash preimage** — `SighashPreimage` as a total function; collision-resistance modeled as an axiom over SHA3-256.

Out of scope (v1.1):
- P2P protocol liveness (planned for TLA+ module)
- Cryptographic security of ML-DSA / SLH-DSA (treated as axiomatic)
- Miner incentive compatibility

---

## 3. Invariant Index

See `formal/THEOREM_INDEX_v1.1.md` for full index. Summary:

| ID | Invariant | Spec ref | Evidence | Proof status |
|----|-----------|----------|----------|--------------|
| T-001 | Sighash determinism — output_count=0 edge case | §4.2 hashOutputs | CV-SIGHASH SIGHASH-06 | spec+vector |
| T-002 | Difficulty retarget 320-bit arithmetic | §6.4 | CV-BLOCK BLOCK-09 | spec+vector |
| T-003 | VERSION_BITS boundary transition ordering | §8 FSM | CV-DEP DEP-05 | spec+vector |
| T-004 | ApplyBlock determinism | §9 inv-1 | CV-BLOCK, CV-UTXO | lean4-proven (local model) |
| T-005 | Value conservation — non-coinbase | §9 inv-2 | CV-FEES FEES-02 | lean4-proven (checked u64 model) |
| T-006 | Non-spendable ANCHOR exclusion from UTXO | §9 inv-3 | CV-UTXO | spec+vector |
| T-007 | VERSION_BITS monotonicity | §9 inv-4 | CV-DEP DEP-04 | lean4-proven (terminal-at-boundary core) |
| T-008 | Sighash preimage injectivity (chain_id domain separation) | §4.2 | CV-SIGHASH | spec+axiom |
| T-009 | HTLC_V2 envelope uniqueness — prefix-scoped matching | §4.1 item 6 | CV-HTLC-ANCHOR HTLC2-08/09 | spec+vector |
| T-010 | Replay protection — (chain_id, tx_nonce) uniqueness | §3.4 | CV-UTXO | spec+vector |
| T-011 | CORE_VAULT_V1 spend_delay monotonicity | §4.1 item 5 | CV-VAULT VAULT-06 | spec+vector |
| T-012 | CompactSize round-trip — encode ∘ decode = id | §3.2.1 | CV-COMPACTSIZE | spec+vector |
| T-013 | Merkle root collision resistance | §5.1.1 | CV-BLOCK BLOCK-05 | spec+axiom |
| T-014 | Block weight non-overflow (u64 bound) | §4.3, §11 | CV-WEIGHT | spec+vector |

**Proof status legend:**
- `spec+vector` — invariant is stated in canonical spec and covered by at least one conformance vector; Lean 4 proof pending.
- `spec+axiom` — invariant depends on cryptographic hardness assumption (SHA3-256 collision resistance, ML-DSA unforgeability); stated as `axiom` in Lean 4 model.
- `lean4-proven` — machine-checked Lean 4 proof exists (currently local workspace; to be pinned to a separate repo commit at freeze).

Clarification (non-normative):
- Current `lean4-proven` items are machine-checked at `/Users/gpt/Documents/rubin-protocol/formal/rubin-formal/`.
- The next milestone for "spec-faithful" is to align the models to byte-level encodings and full state transitions.

---

## 4. Invariant Statements (Informal)

### T-004 ApplyBlock Determinism

> For any fixed `UTXOSet S`, `chain_id`, `height`, `timestamp`, and `BlockBytes B`:
> `ApplyBlock(S, B)` is a total function returning either `(S', Ok)` or `(S, Err e)`.
> The outcome is uniquely determined by `(S, B)` — no non-determinism from implementation choices.

Formal preconditions: `S` is a valid UTXO set (no duplicate keys), `B` is well-formed bytes.

### T-005 Value Conservation

> For any non-coinbase `Tx T` in a valid block:
> `Σ output.value ≤ Σ input_utxo.value`
> where `Σ input_utxo.value` is the sum of values of the outputs being spent.

Corollary: fee = `Σ input_utxo.value − Σ output.value ≥ 0`.

### T-007 VERSION_BITS Monotonicity

> For any deployment `D` and chain `C`, if `state(D, h) = ACTIVE` then
> for all `h' > h`: `state(D, h') = ACTIVE`.
> Similarly: `FAILED` is terminal.
> Formally: the state transition function is monotone on the partial order
> `DEFINED < STARTED < LOCKED_IN < ACTIVE` and `DEFINED < STARTED < FAILED`.

### T-008 Sighash Domain Separation

> For any two inputs `(I1, ctx1)` and `(I2, ctx2)` with `ctx1.chain_id ≠ ctx2.chain_id`:
> `SHA3-256(SighashPreimage(I1, ctx1)) ≠ SHA3-256(SighashPreimage(I2, ctx2))`
> with probability `1 − 2^{-256}` (modeled as a cryptographic axiom).

This ensures a valid signature for chain A cannot be replayed on chain B.

### T-009 HTLC_V2 Envelope Uniqueness

> For any transaction `T` with a `CORE_HTLC_V2` input, the matching set
> `M = { o ∈ T.outputs : o.covenant_type = CORE_ANCHOR ∧ |o.anchor_data| = 54 ∧ o.anchor_data[0:22] = "RUBINv1-htlc-preimage/" }`
> determines path selection deterministically:
> - `|M| = 0` → refund path
> - `|M| = 1` → claim path
> - `|M| ≥ 2` → `TX_ERR_PARSE` (non-deterministic, rejected)
> Non-HTLC ANCHOR outputs (wrong prefix or length) do not affect `|M|`.

---

## 5. CI Integration Plan

Before production freeze, the following CI gates MUST be operational:

1. **Lean 4 build check** — `lake build` in `formal/` directory passes with zero errors.
2. **`#check` smoke** — all theorem statements type-check (even if `sorry`-filled initially).
3. **Proof completeness gate** — at minimum T-004, T-005, T-007 must be `lean4-proven` (no `sorry`).
4. **Conformance parity** — for each `lean4-proven` theorem, a corresponding conformance vector exists and passes.

CI workflow (planned): `.github/workflows/formal.yml` running `lean4-action` on every PR touching `spec/` or `formal/`.

Current status: **CI not yet configured.** Blocked on formal repo creation.
Tracking issue: `formal/README.md` controller decision 2026-02-16.

---

## 6. Known Gaps and Open Questions

1. **Coinbase subsidy overflow** — T-005 covers non-coinbase value conservation. Coinbase subsidy arithmetic (epoch halving, integer rounding) is not yet formally stated. Needs T-015.
2. **Reorg safety** — ApplyBlock determinism (T-004) does not cover reorg scenarios. A `ReorgSafe` lemma is needed: applying the same sequence of blocks from the same initial state always produces the same UTXO set.
3. **Anchor relay cap non-interference** — the relay policy `MAX_ANCHOR_PAYLOAD_RELAY = 1024` (H-002) is non-consensus. A separation lemma is needed: no relay-rejected tx can affect the validity of a block (i.e., relay caps are strictly stricter than consensus caps).
4. **Formal model of `CompactSize` rejection** — T-012 covers round-trip. Malformed CompactSize (e.g., non-canonical two-byte encoding for values < 253) needs a separate `RejectNonCanonical` lemma.

These gaps are tracked in `formal/THEOREM_INDEX_v1.1.md` as pending entries T-015 through T-018.

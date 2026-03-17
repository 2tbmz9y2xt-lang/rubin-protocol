# PR Review Template — Parallel Validation (Rubin)

Use this template only for PRs that implement or modify **implementation-only parallel validation**.
Do not use it for PRs that change consensus rules, wire format, or canonical validation order.

---

## 1) PR Classification

- [ ] This PR does **not** change consensus rules
- [ ] This PR does **not** change wire format
- [ ] This PR does **not** change `SECTION_HASHES.json`
- [ ] This PR is strictly implementation-layer parallel validation
- [ ] The PR uses the term **parallel validation** (not misleading "parallel execution")

If any item above is false, split the PR or move it to a consensus-track process.

---

## 2) Reviewer Summary

### What this PR does

<!-- short module/path summary -->

### What this PR does NOT do

- [ ] Does not change `ApplyBlock(State, Block)` semantics
- [ ] Does not change block validity rules
- [ ] Does not change covenant semantics
- [ ] Does not change canonical error mapping
- [ ] Does not claim protocol TPS increase

### Feature flags / rollout mode

- [ ] `off`
- [ ] `shadow`
- [ ] `on`

Flags/config:

```text
<flags here>
```

---

## 3) Canonical Boundary Checklist

### Validation order

- [ ] Canonical block validation order is preserved
- [ ] No new consensus error-producing steps inserted between canonical steps
- [ ] Parallel path does not alter deterministic error precedence

### Sequential-only stages

- [ ] Parse and canonical checks remain sequential
- [ ] Witness cursor assignment is sequential
- [ ] Replay-domain / `tx_nonce` checks preserve block-order semantics
- [ ] Commit stage remains single-threaded
- [ ] State update remains in block order

### Worker restrictions

- [ ] Workers do not mutate UTXO state
- [ ] Workers do not mutate DA state
- [ ] Workers do not mutate shared consensus accumulators
- [ ] Workers never choose final block error

---

## 4) Witness / Cursor Review

- [ ] Witness cursor is computed exactly once before worker dispatch
- [ ] Workers use precomputed witness spans/slots
- [ ] Unknown covenant during cursor precompute rejects deterministically
- [ ] Bounds checks exist before witness indexing
- [ ] Tests cover HTLC / VAULT / MULTISIG / STEALTH / CORE_EXT

---

## 5) Dependency Graph Review

- [ ] Graph includes same-prevout conflicts
- [ ] Graph includes same-block producer -> consumer dependencies
- [ ] No false parallelization for same-block dependent tx
- [ ] Adversarial parent-child test exists
- [ ] Mixed workload dependency test exists

---

## 6) Deterministic Reducer Review

- [ ] Not using "first worker error wins"
- [ ] Reducer selects smallest invalid `tx_index` in block order
- [ ] Intra-tx canonical error priority is preserved
- [ ] Sequential vs parallel match on:
  - [ ] validity
  - [ ] first invalid tx index
  - [ ] first error code

---

## 7) Immutable Snapshot / State Safety

- [ ] Validation uses immutable snapshot inputs
- [ ] No lazy write-back from workers
- [ ] Shared caches/refs are read-only or thread-safe
- [ ] UTXO sharding function is deterministic
- [ ] Commit phase is the only state mutation phase

---

## 8) Signature Verification Invariants

- [ ] OpenSSL EVP path is preserved
- [ ] No silent fallback to alternative PQ backends
- [ ] `digest32` semantics unchanged
- [ ] No extra pre-hash / wrapping / custom context drift
- [ ] `pubkey` / `signature` lengths validated before verify calls

---

## 9) Signature Cache Review

- [ ] Cache is bounded
- [ ] Eviction policy is explicit
- [ ] Cache key is cryptographically sound
- [ ] Flood/poisoning scenarios reviewed
- [ ] Cache hit path does not alter consensus semantics

---

## 10) Compact Block Path Review

- [ ] Compact reconstruction path remains separated from normal full-block path
- [ ] Batch verify path and individual fallback are preserved
- [ ] `CV-COMPACT` coverage is preserved/extended

---

## 11) Resource / Policy Separation

- [ ] No policy-only rejects are introduced into consensus-equivalent path
- [ ] Block-level limits are not transformed into per-tx consensus rules
- [ ] Mempool pre-validation is only hint/cache-warming, never final truth

---

## 12) Worker Pool / Scheduler Review

- [ ] Worker pool is bounded
- [ ] Queue is bounded
- [ ] Backpressure exists
- [ ] No unbounded memory growth path
- [ ] Scheduler perturbation/starvation tests exist
- [ ] `workers=1` path remains sequential-equivalent

---

## 13) Testing Checklist

### Unit tests

- [ ] witness cursor
- [ ] reducer
- [ ] dependency graph
- [ ] snapshot purity
- [ ] cache
- [ ] scheduler
- [ ] DA parallel jobs

### Integration tests

- [ ] sequential vs parallel on valid blocks
- [ ] sequential vs parallel on invalid blocks
- [ ] mixed covenant workloads
- [ ] compact reconstruction path
- [ ] same-block parent-child dependency

### Adversarial / fuzz / replay

- [ ] deterministic replay harness
- [ ] race detection
- [ ] fuzz with parallel mode enabled
- [ ] injected-delay scheduler perturbation
- [ ] mismatch tests for first error and state digest

---

## 14) Cross-client Parity

- [ ] Go sequential == Go parallel
- [ ] Rust sequential == Rust parallel
- [ ] Go == Rust on parity fixtures
- [ ] `run_cv_bundle.py` PASS

CI evidence links:

```text
<CI links here>
```

---

## 15) Telemetry / Logging

- [ ] Shadow mismatch counters exist (`count`, `first_error`, `state_digest`)
- [ ] Worker pool metrics exist (`queue_depth`, `active_workers`, `wait_time`)
- [ ] Validation/commit latency metrics exist
- [ ] Logs distinguish normal/compact/shadow paths
- [ ] No sensitive payload leakage in telemetry/logs

---

## 16) Rollout / Fail-closed

- [ ] `shadow` mode exists
- [ ] Sequential remains truth path in `shadow`
- [ ] Mismatch triggers fail-closed fallback to sequential
- [ ] Internal panic triggers fail-closed fallback
- [ ] Rollback procedure is documented for operators

Rollback command/knob:

```text
<rollback procedure here>
```

---

## 17) Benchmarks

### Correctness gates

- [ ] zero replay mismatches
- [ ] zero race failures
- [ ] zero parity mismatches

### Performance evidence

- [ ] 1-worker mode regression <= 5%
- [ ] mixed workload improvement measured
- [ ] signature-heavy workload improvement measured
- [ ] benchmark datasets reproducible
- [ ] hardware matrix included (e.g. 4/8/16/32 cores)

Benchmark summary:

```text
<benchmark summary here>
```

---

## 18) Reviewer Decision

### Reviewer A

- [ ] GO
- [ ] GO with follow-ups
- [ ] REWORK
- [ ] REJECT

```text
<notes>
```

### Reviewer B

- [ ] GO
- [ ] GO with follow-ups
- [ ] REWORK
- [ ] REJECT

```text
<notes>
```

### Security Reviewer

- [ ] GO
- [ ] GO with follow-ups
- [ ] REWORK
- [ ] REJECT

```text
<notes>
```

---

## 19) Final Merge Gate

Merge is allowed only if all are true:

- [ ] Consensus boundary preserved
- [ ] Deterministic reducer verified
- [ ] Witness cursor precompute verified
- [ ] Immutable snapshot + sequential commit verified
- [ ] OpenSSL verifier invariants preserved
- [ ] Replay/race/fuzz/parity are green
- [ ] Shadow soak evidence attached
- [ ] Documentation aligned

Explicit no-go conditions:

- [ ] Worker mutates consensus state
- [ ] Worker chooses final block error
- [ ] Witness slicing performed lazily inside workers
- [ ] Mempool validation substituted for block validation
- [ ] Crypto backend drift introduced without parity coverage
- [ ] Any mismatch remains unresolved

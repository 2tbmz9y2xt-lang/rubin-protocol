# Rubin Parallel Validation — Security Review Template

Purpose: security review template for PRs and release gates in the
**parallel validation** track.

Scope: implementation acceleration only; consensus rules are unchanged.

---

## 1) Change Identification

- [ ] PR / commit range is specified
- [ ] Go implementation scope is listed
- [ ] Rust implementation scope is listed
- [ ] Benchmark evidence is linked
- [ ] Parity evidence is linked
- [ ] Race / sanitizer evidence is linked
- [ ] Shadow rollout evidence is linked

Reviewer:

- Security reviewer:
- Date:
- Target branch / release train:
- Related issues:

---

## 2) Scope Lock

### Hard blocker checks

- [ ] No consensus rule change
- [ ] No `ApplyBlock(State, Block)` semantic change
- [ ] No block/tx/covenant semantic change
- [ ] `SECTION_HASHES.json` unchanged
- [ ] PR uses term **parallel validation** (not concurrent state execution)

Reviewer notes:

- Any sign of hidden consensus drift?
- Any policy optimization being smuggled into validity logic?

---

## 3) Determinism Boundary

### Hard blocker checks

- [ ] Validation stage is side-effect free
- [ ] Commit stage is single-threaded
- [ ] Commit stage remains strict block order
- [ ] Worker results never decide final block validity directly
- [ ] Reducer chooses canonical first error deterministically
- [ ] Sequential vs parallel match on:
  - [ ] valid / invalid
  - [ ] first invalid tx index
  - [ ] first error code
  - [ ] post-state digest

### Evidence required

- [ ] deterministic replay logs
- [ ] reducer tests
- [ ] scheduling perturbation tests

---

## 4) Witness / Tx-context Safety

### Hard blocker checks

- [ ] Witness cursor is computed sequentially before workers
- [ ] Workers use precomputed witness spans (no dynamic slicing)
- [ ] Unknown covenant during cursor/precompute rejects deterministically
- [ ] Witness bounds checks are covered by tests
- [ ] `VAULT` / `MULTISIG` key-count-dependent spans covered by tests

### Evidence required

- [ ] witness cursor unit tests
- [ ] malformed witness fixture set
- [ ] mixed-covenant fixture set

---

## 5) Shared-state Safety

### Hard blocker checks

- [ ] Validation uses immutable snapshot inputs
- [ ] Workers have no mutable access to consensus state
- [ ] Shared caches/references are read-only or thread-safe
- [ ] No lazy write-back from workers
- [ ] Snapshot identity is deterministic and explicit

### Evidence required

- [ ] architecture note / code pointers
- [ ] race detector output
- [ ] snapshot purity tests

---

## 6) Dependency Graph Safety

### Hard blocker checks

- [ ] DAG models same-prevout conflicts
- [ ] DAG models same-block producer -> consumer dependencies
- [ ] No false independence for same-block dependent tx
- [ ] Scheduler respects graph barriers deterministically

### Evidence required

- [ ] DAG unit tests
- [ ] parent-child fixture
- [ ] adversarial mixed-block fixture

---

## 7) Crypto Backend Invariants

### Hard blocker checks

- [ ] OpenSSL EVP path is preserved
- [ ] No silent fallback to alternate PQ backends
- [ ] `digest32` semantics unchanged
- [ ] No extra pre-hash / domain wrapping / provider drift
- [ ] `pubkey` / `signature` length checks run before verify calls

### Evidence required

- [ ] Go tests
- [ ] Rust tests
- [ ] OpenSSL preflight output
- [ ] parity evidence (`run_cv_bundle.py`)

---

## 8) Signature Cache Review

### Strong requirements

- [ ] Cache is bounded
- [ ] Cache key uses cryptographic tuple
- [ ] Eviction policy is explicit
- [ ] Flood / poisoning scenario reviewed
- [ ] Cache hit path cannot alter consensus semantics

### Evidence required

- [ ] cache tests
- [ ] cache flood benchmark
- [ ] cache poisoning analysis

---

## 9) Compact-block Path Review

### Hard blocker checks

- [ ] Compact reconstruction path is separated from normal full-block path
- [ ] Batch verify path follows canonical compact procedure
- [ ] Batch-fail -> individual-fallback path covered
- [ ] Parallel optimization does not alter compact error handling
- [ ] Compact telemetry / peer-quality signals preserved

### Evidence required

- [ ] `CV-COMPACT` results
- [ ] compact fallback tests
- [ ] compact telemetry sample

---

## 10) DA Parallelism Review

### Hard blocker checks

- [ ] DA jobs do not alter commitment semantics
- [ ] Chunk ordering validation remains deterministic
- [ ] Malformed/incomplete DA yields same errors as sequential path
- [ ] DA workers do not bypass canonical block-order checks

### Evidence required

- [ ] DA fixtures
- [ ] DA replay equality results

---

## 11) Fault Handling / Fail-closed

### Hard blocker checks

- [ ] Worker panic/internal error cannot silently continue acceptance
- [ ] Parallel mismatch triggers fail-closed fallback to sequential truth path
- [ ] Resource guardrail breach triggers fail-closed behavior
- [ ] Race/sanitizer failure blocks release
- [ ] No partial-success ambiguous mode

### Evidence required

- [ ] panic injection test
- [ ] mismatch injection test
- [ ] fallback test

---

## 12) Test Evidence

### Hard blocker checks

- [ ] Unit tests complete
- [ ] Integration tests complete
- [ ] Fuzz tests complete
- [ ] Replay tests complete
- [ ] Go `-race` complete
- [ ] Rust sanitizer/concurrency tests complete
- [ ] Cross-client parity complete

---

## 13) Rollout Security

### Hard blocker checks

- [ ] Modes `off / shadow / on` documented
- [ ] `shadow` uses sequential as truth path
- [ ] Shadow mismatch telemetry is present
- [ ] Operator rollback path documented
- [ ] Soak evidence is present before default-on decision

### Evidence required

- [ ] operator SOP/runbook
- [ ] shadow soak metrics
- [ ] rollback drill result

---

## 14) Documentation / Claims Review

### Hard blocker checks

- [ ] Documentation does not claim protocol TPS increase
- [ ] Documentation does not present this as consensus change
- [ ] Security claims are evidence-backed
- [ ] README / PR body / runbook language is aligned

---

## 15) Final Decision

### Merge decision

- [ ] APPROVE
- [ ] APPROVE WITH REQUIRED FIXES
- [ ] REJECT / REWORK REQUIRED

Blocking findings:

1.
2.
3.

Non-blocking findings:

1.
2.
3.

Required follow-up issues:

- [ ] deferred hardening
- [ ] benchmark debt
- [ ] operator telemetry/alerts
- [ ] formal refinement extension

---

## 16) Reviewer Summary

Security verdict:

Rationale:

Conditions for production enablement:

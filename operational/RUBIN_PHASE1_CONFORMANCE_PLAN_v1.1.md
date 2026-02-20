# RUBIN Phase 1 Conformance Plan v1.1 (non-consensus)

Status: ENGINEERING SPEC (non-consensus)
Audience: controller + node implementers (Go/Rust) + conformance runner authors
Date: 2026-02-19

This document defines the **Phase 1** conformance gates for node core engineering:
- persistent storage (datadir + KV layout)
- staged block import (Stages 0–5)
- reorg disconnect/connect behavior
- chainstate snapshot hash cross-client comparability
- crash recovery invariants (manifest as commit point)

Consensus correctness is separately gated by:
- `spec/RUBIN_L1_CONFORMANCE_MANIFEST_v1.1.md`

---

## 0. Goals

- Provide **binary-checkable** Phase 1 exit gates (PASS/FAIL).
- Ensure **cross-client determinism** at the applied tip, via `utxo_set_hash`.
- Ensure **crash safety** (manifest commit point) by construction and by test.

Non-goals:
- P2P / networking
- mainnet genesis ceremony
- pruning/snapshots/sync protocols

---

## 1. Required Phase 1 Gates

Phase 1 is complete only when **all required gates** below are PASS.

| Gate | Required | Purpose | Requires Rust storage? |
|---|---:|---|---:|
| CV-STORAGE | ✓ | datadir layout + manifest + KV schema/version rules | no |
| CV-IMPORT | ✓ | staged import semantics (invalid/orphan marking, fork-choice, apply/reorg integration points) | no |
| CV-CHAINSTATE-STORE | ✓ | persistent-store parity via init/import-block/utxo-set-hash (Go == Rust) | yes |
| CV-CRASH-RECOVERY | ✓ | kill/restart invariants (no partial apply visible) | yes |

Notes:
- CV-CHAINSTATE-STORE is the **core Phase 1 cross-client determinism gate**.
- CV-CRASH-RECOVERY is required because manifest atomicity is a Phase 1 hard requirement.

---

## 2. Canonical Specs (Source Of Truth)

Implementations and runners MUST treat the following as canonical:
- KV byte layouts: `operational/RUBIN_NODE_KV_ENGINE_SPEC_v1.1.md`
- storage model + manifest semantics: `operational/RUBIN_NODE_STORAGE_MODEL_v1.1.md`
- import pipeline stages: `operational/RUBIN_BLOCK_IMPORT_PIPELINE_v1.1.md`
- reorg disconnect/connect: `operational/RUBIN_REORG_DISCONNECT_CONNECT_v1.1.md`
- chainstate hash definition: `operational/RUBIN_CHAINSTATE_SNAPSHOT_HASH_v1.1.md`
- Phase 1 exit criteria mapping: `operational/RUBIN_PHASE1_DOD_v1.1.md`

---

## 3. Runner Interface (CLI Contracts)

Conformance runners SHOULD treat nodes as black-box CLIs with these commands:

Go node (reference):
- `go run ./node init --datadir <path> --profile <path>`
- `go run ./node import-block --datadir <path> --profile <path> [--local-time <u64>] (--block-hex <hex> | --block-hex-file <path>)`
- `go run ./node utxo-set-hash --datadir <path> --profile <path>`

Rust node (reference):
- `cargo run -q -p rubin-node -- init --datadir <path> --profile <path>`
- `cargo run -q -p rubin-node -- import-block --datadir <path> --profile <path> ...`
- `cargo run -q -p rubin-node -- utxo-set-hash --datadir <path> --profile <path>`

Hard requirement for CV-CHAINSTATE-STORE and CV-CRASH-RECOVERY:
- Both clients MUST use the **same crypto provider policy** for hashing:
  - dev-only `DevStdCryptoProvider` is acceptable for early Phase 1 local runs,
    but Phase 1 sign-off SHOULD run with `RUBIN_WOLFCRYPT_STRICT=1` where feasible.

---

## 4. Fixture File Layout (proposed)

All Phase 1 fixtures live under:
- `conformance/fixtures/`

Suggested files:
- `conformance/fixtures/CV-STORAGE.yml`
- `conformance/fixtures/CV-IMPORT.yml`
- `conformance/fixtures/CV-CHAINSTATE-STORE.yml`
- `conformance/fixtures/CV-CRASH-RECOVERY.yml`

Existing consensus integration gate (not a Phase 1 exit criterion):
- `conformance/fixtures/CV-CHAINSTATE.yml`

Common YAML schema (minimum) for CV-CHAINSTATE-STORE:
```yaml
gate: CV-CHAINSTATE-STORE
version: "1.1"
tests:
  - id: CS-01
    profile: spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md
    plan:
      kind: linear
      blocks: 10
    expected_code: PASS
```

Notes:
- Expected outcome is parity by construction: Go output MUST equal Rust output.
- Once encodings are frozen, CV-CHAINSTATE-STORE MAY additionally include fixed expected hashes.

---

## 5. Gate Definitions (normative)

### 5.1 CV-STORAGE (required)

Goal: verify that `init --datadir` creates and persists the required on-disk structure.

Minimum checks:
- `MANIFEST.json` exists and is valid JSON.
- `schema_version` is supported.
- `db/kv.db` exists (engine-specific filename allowed, but Go reference uses bbolt).
- KV buckets/tables exist with canonical names (or a canonical mapping).
- file permissions match policy (e.g., manifest and DB are not world-writable).

### 5.2 CV-IMPORT (required)

Goal: verify staged import semantics match `RUBIN_BLOCK_IMPORT_PIPELINE_v1.1.md`:
- Stage 0 persistence MAY happen before Stage 1.
- Stage 1 failures MUST mark `block_index_by_hash.status = INVALID_HEADER`.
- Stage 2 unknown parent => ORPHANED.
- Stage 2 invalid parent => INVALID_ANCESTRY.
- Stage 3 fork-choice tie-break deterministic.

Vector types:
- malformed blocks (parse errors)
- header-invalid blocks (merkle/target/timestamp/PoW)
- orphan blocks
- blocks with invalid ancestry

### 5.3 CV-CHAINSTATE-STORE (required)

Goal: cross-client parity on persisted chainstate snapshot via node CLI:
`(tip_hash, tip_height, utxo_set_hash)` MUST match between Go and Rust after each test sequence.

Minimum required vectors:
- CS-01: linear chain N=10, no reorg
- CS-02: 2-block reorg
- CS-03: deeper reorg crossing difficulty window boundary (WINDOW_SIZE)

### 5.4 CV-CRASH-RECOVERY (required)

Goal: verify crash safety around the manifest commit point.

Minimum checks:
- start from initialized datadir
- begin `import-block` of a candidate-best block
- kill the node process mid-import (kill -9 or equivalent)
- restart and verify:
  - manifest tip remains consistent
  - `utxo-set-hash` matches the manifest tip (no partial apply)

---

## 6. Runner Implementation Plan (non-normative)

- Add new Python runners (planned):
  - `conformance/runner/run_cv_storage.py`
  - `conformance/runner/run_cv_import.py`
  - `conformance/runner/run_cv_crash_recovery.py`
- CV-CHAINSTATE-STORE is implemented in `conformance/runner/run_cv_bundle.py` (`run_chainstate_store`) and consumes `conformance/fixtures/CV-CHAINSTATE-STORE.yml`.
- Integrate remaining planned runners into `conformance/runner/run_cv_bundle.py` under new gate names.
- Update `spec/RUBIN_L1_CONFORMANCE_MANIFEST_v1.1.md` (or a new Phase 1 manifest) to track PASS/FAIL.

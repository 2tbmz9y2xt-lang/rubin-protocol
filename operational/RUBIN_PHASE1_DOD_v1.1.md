# RUBIN Phase 1 Definition of Done v1.1

Status: OPERATIONAL (non-consensus)
Date: 2026-02-19
Audience: controller + implementers (Codex, Spec-Synth)
Scope: exact exit criteria for Phase 1 — Node Core Engineering

**CONTROLLER APPROVAL REQUIRED** to declare Phase 1 complete and advance to Phase 2.

---

## 0. Purpose

This document defines the exhaustive, binary-checkable conditions that MUST all be true
before Phase 1 can be declared done and Phase 2 (P2P + Key Lifecycle) can begin.

Phase 1 scope: persistent storage, block import pipeline (Stages 0–5), reorg
(disconnect/connect), chainstate snapshot hash, and cross-client determinism.

Phase 1 does NOT include: P2P networking, key lifecycle, genesis ceremony, or mainnet.

---

## 1. Go node — persistent storage (Q-100 through Q-104)

### 1.1 Datadir layout

- [ ] `rubin-node init --datadir <path> --profile <path>` creates:
  - `datadir/chains/<chain_id_hex>/MANIFEST.json`
  - `datadir/chains/<chain_id_hex>/db/kv.db` (bbolt)
- [ ] MANIFEST.json contains all required fields per `RUBIN_NODE_STORAGE_MODEL_v1.1.md §4.1`
- [ ] MANIFEST.json is written atomically (write-tmp → fsync → rename → fsync-dir)

### 1.2 Block import

- [ ] `rubin-node import-block --datadir <path>` processes a block through Stage 0–5:
  - Stage 0: persist header + block bytes
  - Stage 1: stateless header validation (PoW / target / timestamp / merkle);
    failure marks `block_index_by_hash[hash].status = INVALID_HEADER`
  - Stage 2: ancestry check; ORPHANED or INVALID_ANCESTRY result persisted
  - Stage 3: fork-choice candidate selection
  - Stage 4: full block validation (only for candidate best tip)
  - Stage 5: atomic apply (utxo + undo + index + manifest)
- [ ] Crash recovery: after kill -9 mid-import, restart recovers to manifest tip;
  UTXO set matches manifest.last_applied_block_hash (verified by `utxo-set-hash --datadir`)

### 1.3 Reorg

- [ ] `rubin-node import-block --datadir <path>` performs full disconnect/connect when
  candidate tip is not a direct child of manifest tip
- [ ] Fork-point discovery algorithm matches `RUBIN_REORG_DISCONNECT_CONNECT_v1.1.md §4`
- [ ] Disconnect order: descending height from old tip to fork+1
- [ ] Connect order: ascending height from fork+1 to new tip
- [ ] Each manifest update is the atomic commit point for that disconnect/connect step

### 1.4 Chainstate hash

- [ ] `rubin-node utxo-set-hash --datadir <path>` reads persisted UTXO from bbolt and
  returns `{ tip_hash, tip_height, utxo_set_hash }` matching spec
  (`RUBIN_CHAINSTATE_SNAPSHOT_HASH_v1.1.md`)
- [ ] Hash is deterministic: same datadir, same result across multiple runs

---

## 2. Rust node — persistent storage (Q-108)

- [ ] `rubin-node (rust) init --datadir <path> --profile <path>` — creates identical
  directory structure as Go node
- [ ] `rubin-node (rust) import-block --datadir <path>` — full Stage 0–5 pipeline
- [ ] `rubin-node (rust) utxo-set-hash --datadir <path>` — identical output format

Note: Rust storage engine choice is open (sled / redb / bbolt via CGo / other).
Engine is implementation-specific; wire encoding of bucket values MUST match the
canonical encoding defined in `RUBIN_NODE_KV_ENGINE_SPEC_v1.1.md` (required document,
see §6 below).

---

## 3. Cross-client determinism (CV-CHAINSTATE-STORE)

This is the core Phase 1 exit gate (datadir-backed parity).

- [ ] CV-CHAINSTATE-STORE fixture `conformance/fixtures/CV-CHAINSTATE-STORE.yml` exists with >= 3 test sequences:
  - CS-01: linear chain of N=10 blocks, no reorg — Go and Rust `utxo_set_hash` must match
  - CS-02: 2-block reorg — Go and Rust must agree on post-reorg `utxo_set_hash`
  - CS-03: deep reorg crossing difficulty window — both clients agree on final state
- [ ] Gate is automated and all vectors PASS:
  - `python3 conformance/runner/run_cv_bundle.py --only-gates CV-CHAINSTATE-STORE`
- [ ] Both Go and Rust node binaries used in CV-CHAINSTATE-STORE runner are built with
  real crypto provider (not dev-std stub)

---

## 4. Bug fixes (from Phase 1 audit 2026-02-19)

- [ ] **BUG-01 fixed**: Stage 1 stateless header validation runs in `ImportStage0To3`
  (not only in `ApplyBlock`), with `INVALID_HEADER` marking in `block_index_by_hash`
- [ ] **BUG-02 resolved**: `covenant_data_len` encoding in `encodeUtxoEntry` and
  `RUBIN_NODE_KV_ENGINE_SPEC_v1.1.md` agree on a single encoding (either CompactSize
  or u32le — one canonical choice, both clients use it, spec reflects it)
- [ ] **BUG-03 mitigated**: `loadAncestorHeadersForParent` handles deep reorg > WINDOW_SIZE
  correctly, or a documented limitation is added to `RUBIN_BLOCK_IMPORT_PIPELINE §3.3`

---

## 5. Code quality gates

- [ ] `go test ./...` passes in `clients/go/` with no failures
- [ ] `cargo test --workspace` passes in `clients/rust/` with no failures
- [ ] `go vet ./...` — no errors
- [ ] `golangci-lint run` (or semgrep) — no P0/P1 findings
- [ ] `cargo clippy --all-targets` — no errors, warnings addressed
- [ ] `govulncheck ./...` — no known vulnerabilities
- [ ] `cargo audit` — no known vulnerabilities
- [ ] Go consensus package coverage ≥ 80% (currently 82.3% ✅)
- [ ] Go node/store package coverage ≥ 70% (integration tests for import/reorg)
- [ ] `gosec G304` fix in `clients/go/node/main.go` (Q-107)

---

## 6. Required documents

All documents below MUST exist and be marked `Status: ENGINEERING SPEC` (not DRAFT/TODO):

- [ ] `operational/RUBIN_NODE_KV_ENGINE_SPEC_v1.1.md`
  - Engine selection guidance (Go: bbolt, Rust: TBD)
  - Byte layout for all 5 bucket value types (complete, no "implementation choice")
  - Migration procedure, schema_version bump policy
- [ ] `operational/RUBIN_PHASE1_CONFORMANCE_PLAN_v1.1.md`
  - CV-STORAGE, CV-IMPORT, CV-CHAINSTATE, CV-CRASH-RECOVERY gate definitions
  - Fixture schema + runner plan

Updates to existing documents:

- [ ] `operational/RUBIN_NODE_STORAGE_MODEL_v1.1.md §4.5` — explicit byte layout for
  `utxo_by_outpoint` value (covenant_data_len encoding aligned with KV engine spec)
- [ ] `operational/RUBIN_BLOCK_IMPORT_PIPELINE_v1.1.md §3.1` — explicit ordering:
  "Stage 0 persist MAY happen before Stage 1, but on Stage 1 failure block_index_by_hash
  MUST be updated to INVALID_HEADER"
- [ ] `operational/RUBIN_REORG_DISCONNECT_CONNECT_v1.1.md §9` — mid-reorg crash
  recovery specification + reference to repair CLI
- [ ] `operational/RUBIN_L1_FREEZE_TRANSITION_POLICY_v1.1.md` — Phase 1 freeze section
  referencing this DoD

---

## 7. Operational minimum

- [ ] `operational/systemd/rubin-node.service` is parameterized (no hardcoded user-specific absolute paths)
- [ ] `scripts/launch_rubin_node.sh` works with `--datadir` flag for both clients
- [ ] `RUBIN_WOLFCRYPT_STRICT=1` is enforced in import-block pipeline (not dev-std)

---

## 8. Controller sign-off checklist

Controller declares Phase 1 done when ALL of the following are true:

1. All checkboxes in §1–§7 above are checked
2. CV-CHAINSTATE is PASS in `RUBIN_L1_CONFORMANCE_MANIFEST_v1.1.md`
3. At least one 10-block sequence test has been run end-to-end with:
   - Go node: init → import 10 blocks → reorg at block 7 → utxo-set-hash
   - Rust node: same sequence → same utxo_set_hash
   - Results logged to `inbox/reports/`
4. `RUBIN_L1_CONFORMANCE_MANIFEST_v1.1.md` updated with Phase 1 gates status
5. Phase 1 milestone in `dashboard.json` updated to `done`

---

## Appendix: Phase 1 milestone mapping

| DoD Section | Q-item | Status |
|---|---|---|
| §1.1 datadir init | Q-100 | DONE |
| §1.2 import pipeline Stage 0–3 | Q-101 | DONE |
| §1.2 import pipeline Stage 4–5 | Q-102 | DONE |
| §1.3 reorg disconnect/connect | Q-103 | DONE |
| §1.4 utxo-set-hash --datadir | Q-104 | DONE |
| §2 Rust persistent storage | Q-108 | DONE |
| §3 CV-CHAINSTATE-STORE | Q-109 | DONE |
| §4 BUG-01 Stage 1 fix | Q-110 | DONE |
| §4 BUG-02 encoding alignment | Q-111 | DONE |
| §5 gosec G304 | Q-107 | DONE |
| §6 KV engine spec doc | Q-112 | DONE |
| §6 Phase 1 conformance plan doc | Q-113 | DONE |

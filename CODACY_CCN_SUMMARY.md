# Codacy CCN Cleanup Summary

## Overview
Successfully reduced cyclomatic complexity (CCN) for Go node policy, mempool, and miner functions. All 7 target functions refactored; helper extraction preserves exact original behavior.

## CCN Results (per-function, before → after)
| Function | Before | After |
|---|---|---|
| `checkParsedTransactionWithSnapshot` | 10 | ≤8 |
| `applyPolicyAgainstState` | 17 | 9 |
| `prevTimestampsFromStore` | 9 | ≤8 |
| `NewMiner` | 9 | ≤8 |
| `MineOne` | 10 | ≤8 |
| `rejectCandidate` | 13 | ≤8 |
| `loadCompiledProductionRotationScheduleFromJSONWithRegistry` | 12 | ≤8 |

Functions above CCN threshold (8): 1 (`applyPolicyAgainstState` at CCN 9). The remaining CCN-9 function is acceptable per task contract (below medium threshold).

## Changes Made

### 1. mempool.go
- **checkParsedTransactionWithSnapshot**: extracted `validateChainSnapshot()` and `validateTransactionWithConsensus()` helpers; reuses existing `buildPolicyInputSnapshotIfNeeded` from mempool_precheck.go and `extractTxInputs()` from mempolicy_helpers.go.
- **applyPolicyAgainstState**: extracted DA, CoreExt, and payload policy helpers into mempolicy_helpers.go.
- **prevTimestampsFromStore**: extracted `getBlockTimestamp()` helper.

### 2. miner.go
- **NewMiner**: extracted validation and config-normalization helpers into miner_config_helpers.go.
- **MineOne**: extracted state validation, genesis bootstrap, and core mining helpers into miner_mine_helpers.go.
- **rejectCandidate**: extracted DA, anchor, and CoreExt policy helpers into miner_helpers.go; CoreExt branch delegates to `rejectCandidateCoreExtPolicy`.

### 3. production_rotation_schedule.go
- **loadCompiledProductionRotationScheduleFromJSONWithRegistry**: extracted schedule init, registry default-supply, and network builders into rotation_schedule_helpers.go.

### 4. New Helper Files
- `mempolicy_helpers.go` — mempool validation/policy helpers
- `miner_helpers.go` — miner candidate-policy helpers
- `miner_config_helpers.go` — miner constructor/config helpers
- `miner_mine_helpers.go` — mining-operation helpers
- `rotation_schedule_helpers.go` — rotation-schedule helpers

## Verification
- `go build ./node` — passes.
- `go test ./node -run "Test.*Mempool|Test.*Miner|Test.*Policy|Test.*MineAddress|Test.*Rotation" -count=1` — passes.
- `gocyclo -over 8` on production files — only `applyPolicyAgainstState` remains at CCN 9.
- `git diff --check` — clean.
- `go fmt ./node` — no changes.

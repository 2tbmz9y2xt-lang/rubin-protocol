# Codacy CCN Cleanup Summary — Miner + Rotation

## Overview
Reduced cyclomatic complexity (CCN) for Go node miner and production rotation schedule functions. All 4 target functions refactored; helper extraction preserves exact original behavior.

## CCN Results (per-function, before → after)
| Function | Before | After |
|---|---|---|
| `NewMiner` | 9 | 4 |
| `MineOne` | 10 | 3 |
| `rejectCandidate` | 13 | 4 |
| `loadCompiledProductionRotationScheduleFromJSONWithRegistry` | 12 | 5 |

All target functions ≤5 CCN. All new helpers ≤6 CCN.

## Changes Made

### 1. miner.go
- **NewMiner**: extracted validation (validateNewMinerInputs, validateMinerAliasRequirements) and config-normalization (normalizeMinerConfig) into miner_config_helpers.go.
- **MineOne**: extracted state validation (validateMineOneInput), genesis bootstrap (bootstrapGenesisIfNeeded), and core mining (executeMineOne) into miner_mine_helpers.go.
- **rejectCandidate**: extracted DA policy (rejectCandidateDAPolicy), anchor policy (rejectCandidateAnchorPolicy), and CoreExt policy (rejectCandidateCoreExtPolicy) into miner_helpers.go; CoreExt branch delegates to `rejectCandidateCoreExtPolicy`.

### 2. production_rotation_schedule.go
- **loadCompiledProductionRotationScheduleFromJSONWithRegistry**: extracted schedule init (initializeRotationSchedule), registry default-supply (ensureRegistry), and network builders (buildProductionRotationScheduleNetworks) into rotation_schedule_helpers.go.

### 3. New Helper Files
- `miner_helpers.go` — miner candidate-policy helpers
- `miner_config_helpers.go` — miner constructor/config helpers
- `miner_mine_helpers.go` — mining-operation helpers
- `rotation_schedule_helpers.go` — rotation-schedule helpers

## Verification
Run from `clients/go/`:
- `go build ./node` — passes.
- `go test ./node -run "Test.*Miner|Test.*Rotation|Test.*MineAddress" -count=1` — passes.
- `gocyclo -over 8 miner.go miner_helpers.go miner_config_helpers.go miner_mine_helpers.go production_rotation_schedule.go rotation_schedule_helpers.go` — all ≤8.
- `git diff --check` — clean.
- `go fmt ./node` — no changes.

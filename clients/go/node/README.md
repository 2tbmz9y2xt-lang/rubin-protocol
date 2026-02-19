# Go Node CLI (Phase 1)

This folder contains the **Go node CLI** used by conformance runners and Phase 1 engineering work.

Status: development tooling (non-production).

## Build / Run

From repo root:

```bash
cd clients/go
go test ./... -count=1
```

Run the CLI via `go run`:

```bash
cd clients/go
go run ./node <command> [flags]
```

To print all commands:

```bash
cd clients/go
go run ./node
```

## Network Profile

The CLI derives `chain_id` from a **chain-instance profile** file.

Devnet default profile (as wired in code):
- `spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md`

You can override it with `--profile <path>`.

## Phase 1 Commands (datadir + persistence)

Phase 1 persistence model is defined in:
- `operational/RUBIN_NODE_STORAGE_MODEL_v1.1.md`
- `operational/RUBIN_BLOCK_IMPORT_PIPELINE_v1.1.md`
- `operational/RUBIN_REORG_DISCONNECT_CONNECT_v1.1.md`

### 1) Initialize datadir (genesis apply + manifest)

Creates `datadir/chains/<chain_id_hex>/` and writes:
- `MANIFEST.json` (commit point)
- KV database with headers/blocks/index/utxo/undo tables

```bash
cd clients/go
go run ./node init \
  --datadir /tmp/rubin-data \
  --profile spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md
```

Output: `OK` on success.

### 2) Import Stage 0-3 only (store + ancestry + fork-choice candidate)

This persists header bytes, full block bytes, and index entries, but **does NOT** apply chainstate.

```bash
cd clients/go
go run ./node import-stage03 \
  --datadir /tmp/rubin-data \
  --profile spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md \
  --block-hex <BlockBytesHex>
```

Or read the hex from a file:

```bash
cd clients/go
go run ./node import-stage03 \
  --datadir /tmp/rubin-data \
  --profile spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md \
  --block-hex-file /path/to/block.hex
```

Decision tokens (stdout):
- `ORPHANED` (missing parent)
- `INVALID_ANCESTRY` (parent known invalid)
- `STORED_NOT_SELECTED` (valid header chain but not best tip by ChainWork)
- `CANDIDATE_BEST` (candidate for best tip; Stage 4/5 would be needed to apply)

### 3) Full import (Stage 0-5 + apply + reorg)

This runs Stage 0-3 ingestion, then if the block is a best-tip candidate:
- if it extends the current applied tip: validate (Stage 4) + atomically apply (Stage 5)
- otherwise: perform a Phase 1 reorg (disconnect/connect) using undo logs

```bash
cd clients/go
go run ./node import-block \
  --datadir /tmp/rubin-data \
  --profile spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md \
  --block-hex <BlockBytesHex>
```

Optional validation flags:
- `--local-time <u64>`: local time in seconds since UNIX epoch (enables MAX_FUTURE_DRIFT checks)
- `--suite-id-02-active`: treat suite_id=0x02 as active (dev/conformance)
- `--htlc-v2-active`: treat CORE_HTLC_V2 as active (dev/conformance)

Decision tokens (stdout):
- `STORED_NOT_SELECTED`
- `ORPHANED`
- `INVALID_ANCESTRY`
- `APPLIED_AS_NEW_TIP`

## Crypto provider selection (dev-std vs wolfCrypt)

The Go node chooses crypto backend at runtime:

- Default: `DevStdCryptoProvider` (not a FIPS claim; intended for early dev tooling)
- wolfCrypt shim (when built with tag `wolfcrypt_dylib` and env is set):
  - `RUBIN_WOLFCRYPT_SHIM_PATH=<path to shim>`
  - optional `RUBIN_WOLFCRYPT_STRICT=1` (reject missing shim)

Example (if you have the shim and built with the tag):

```bash
cd clients/go
RUBIN_WOLFCRYPT_SHIM_PATH=/absolute/path/to/librubin_wc_shim.so \
  go run -tags wolfcrypt_dylib ./node version
```


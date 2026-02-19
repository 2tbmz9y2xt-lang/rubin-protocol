# wolfCrypt FFI Hardening Guide

Status: NORMATIVE for production deployments  
Reference: `operational/RUBIN_WOLFCRYPT_DEPLOYMENT.md`

## Required environment variables

| Variable | Description | Required |
|---|---|---|
| `RUBIN_WOLFCRYPT_SHIM_PATH` | Absolute path to `librubin_wc_shim.so/.dylib` | Yes |
| `RUBIN_WOLFCRYPT_SHIM_SHA3_256` | Hex SHA3-256 hash of the shim binary | Yes (strict mode) |
| `RUBIN_WOLFCRYPT_STRICT` | Set to `1` to reject shim if hash mismatch | Yes in production |

## Strict mode (mandatory in production)

With `RUBIN_WOLFCRYPT_STRICT=1`, the node verifies the shim hash at startup.
Any mismatch causes immediate abort — the node will not start.

```bash
export RUBIN_WOLFCRYPT_STRICT=1
export RUBIN_WOLFCRYPT_SHIM_PATH=/opt/rubin/librubin_wc_shim.so
export RUBIN_WOLFCRYPT_SHIM_SHA3_256=<sha3-256-hex-of-shim>
```

**Never run production nodes without strict mode.** Without it, a compromised shim
will silently accept invalid signatures, breaking consensus security.

## Computing the shim hash

```bash
python3 -c "
import hashlib, sys
data = open(sys.argv[1],'rb').read()
import sha3; print(hashlib.sha3_256(data).hexdigest())
" /path/to/librubin_wc_shim.so
```

Or use the provided script:
```bash
scripts/hash_shim.sh /path/to/librubin_wc_shim.so
```

## Supply chain: fetching from GHCR

Use `scripts/launch_rubin_node.sh` which:
1. Pulls shim from GHCR via `oras`
2. Verifies cosign signature
3. Computes and exports `RUBIN_WOLFCRYPT_SHIM_SHA3_256`
4. Sets `RUBIN_WOLFCRYPT_STRICT=1`
5. Starts the node

See full runbook: `operational/RUBIN_WOLFCRYPT_DEPLOYMENT.md`

## Dev mode (no shim)

For development without wolfCrypt, build Rust with the `dev-std` feature:
```bash
cargo build --manifest-path clients/rust/Cargo.toml --features dev-std
```

Go: omit the `wolfcrypt_dylib` build tag:
```bash
go build ./...   # uses stub provider
```

**Dev providers always return `verify_* = false` for real signatures.**
They MUST NOT be used in production or conformance testing.

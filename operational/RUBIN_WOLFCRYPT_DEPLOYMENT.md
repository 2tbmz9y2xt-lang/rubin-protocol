# RUBIN wolfCrypt shim deployment runbook (dev/test)

Purpose: single-command, verifiable bootstrap of `librubin_wc_shim.*` and launch of `rubin-node` with strict hash pinning.

## Prereqs
- `oras` and `cosign` installed on host.
- Network egress to GHCR (`ghcr.io/<owner>/wolfcrypt-shim:<os>-<cc_bin>`).
- Rust toolchain or Go toolchain depending on selected client.

## One-shot launch

From repository root:

```bash
scripts/launch_rubin_node.sh rust ghcr.io/<owner>/wolfcrypt-shim:ubuntu-22.04-gcc-12
# or
scripts/launch_rubin_node.sh go   ghcr.io/<owner>/wolfcrypt-shim:ubuntu-22.04-gcc-12
```
- Fetches shim from GHCR, verifies cosign signature and hash, exports `RUBIN_WOLFCRYPT_SHIM_PATH`, `RUBIN_WOLFCRYPT_SHIM_SHA3_256`, `RUBIN_WOLFCRYPT_STRICT=1`, then runs `chain-id`.

## systemd template (manual install)
See committed examples:
- unit: `operational/systemd/rubin-node.service`
- env: `operational/systemd/rubin-node.env.example`

Suggested install flow:

```bash
sudo install -m 0644 operational/systemd/rubin-node.service /etc/systemd/system/rubin-node.service
sudo install -d -m 0755 /etc/rubin
sudo install -m 0640 operational/systemd/rubin-node.env.example /etc/rubin/rubin-node.env
sudo systemctl daemon-reload
sudo systemctl enable --now rubin-node
```

Notes:
- Edit `/etc/rubin/rubin-node.env` to set `GHCR_REF` and `CLIENT=rust|go`.
- Ensure the unit `WorkingDirectory=` points to your repo root (or an installed checkout).
- Ensure `oras`/`cosign` are installed for the service user.

## GHCR auth (prod-friendly)
- Prefer GitHub OIDC with `packages:write/read` scoped token; fallback PAT with `write:packages` + `read:packages`.
- Login: `echo $TOKEN | oras login ghcr.io -u USERNAME --password-stdin`.

## Verification workflow
1. Pull: `oras pull ghcr.io/<owner>/wolfcrypt-shim:<tag> -o /tmp/wc-shim`
2. Verify sums+sig: `./crypto/wolfcrypt/verify_shim_cosign.sh /tmp/wc-shim/SHA3SUMS.txt`
3. Verify specific shim & export env: `source <(./crypto/wolfcrypt/verify_shim_cosign.sh /tmp/wc-shim/SHA3SUMS.txt /tmp/wc-shim/librubin_wc_shim.* --export-env)`
4. Launch node with strict mode (env already set).

## Notes
- `RUBIN_WOLFCRYPT_STRICT=1` enforced in providers: absence of hash blocks start.
- Keep shim directory read-only for service user after verification.

## Compliance note (precision)

This runbook is about supply-chain pinning and reproducible deployment mechanics. It does **not** assert that PQC operations are currently inside a CMVP-validated boundary.

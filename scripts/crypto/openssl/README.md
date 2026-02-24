# OpenSSL PQ Bundle & Benchmark

## Build local bundle (OpenSSL 3.5+)

```bash
cd <REPO_ROOT>
chmod +x scripts/crypto/openssl/build-openssl-bundle.sh
OPENSSL_VERSION=3.5.5 scripts/crypto/openssl/build-openssl-bundle.sh
```

Default install prefix:

`$HOME/.cache/rubin-openssl/bundle-<version>`

## Run PQ benchmark (OpenSSL `speed`, primary)

```bash
cd <REPO_ROOT>
chmod +x scripts/crypto/openssl/bench-pq-speed.py
scripts/crypto/openssl/bench-pq-speed.py \
  --openssl-bin "$HOME/.cache/rubin-openssl/bundle-<version>/bin/openssl" \
  --seconds 5 \
  --output-json <OUTPUT_JSON_PATH>
```

Notes:

- This benchmark uses in-process OpenSSL `speed` and gives realistic sign/verify throughput.

## Audit baseline (Apple Silicon, 16 cores)

Reference command:

```bash
"$HOME/.cache/rubin-openssl/bundle-<version>/bin/openssl" speed \
  -elapsed -multi 16 -seconds 30 \
  -signature-algorithms ML-DSA-87 SLH-DSA-SHAKE-256f
```

Reference result (2026-02-23, local macOS host):

- `ML-DSA-87 verify/s = 102012.8`
- `SLH-DSA-SHAKE-256f verify/s = 7360.8`
- `verify latency ratio (SLH / ML-DSA) ≈ 13.86x`

Interpretation:

- This is a local workstation baseline for audit comparability.
- Absolute throughput depends on host class and scheduler; use this as a fixed local reference, not a server capacity claim.

## Optional fallback benchmark (`pkeyutl` loop)

```bash
chmod +x scripts/crypto/openssl/bench-pq-pkeyutl.py
scripts/crypto/openssl/bench-pq-pkeyutl.py \
  --openssl-bin "$HOME/.cache/rubin-openssl/bundle-<version>/bin/openssl" \
  --output-json <OUTPUT_JSON_PATH>
```

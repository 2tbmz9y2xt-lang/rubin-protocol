# RUBIN wolfCrypt Shim Deliverable Spec (v1.1)

Status: DEVELOPMENT GUIDANCE (non-consensus)  
Audience: wolfSSL/wolfCrypt integration partner, compliance engineering, client implementers

This document specifies the required artifacts and ABI surface for the RUBIN wolfCrypt shim.
It exists to keep Rust and Go clients decoupled from wolfCrypt internal headers while enabling a FIPS-first supply chain.

## 1. Goals

1. Provide a stable, minimal C ABI for the RUBIN crypto provider operations:
   - SHA3-256
   - ML-DSA-87 verify
   - SLH-DSA-SHAKE-256f verify (FIPS 205, Category 5)
2. Enable runtime loading from both Rust and Go without shipping wolfCrypt sources/headers in this repo.
3. Support "FIPS-path" and future "FIPS-PQC" compliance claims based on the delivered module and OE.

## 2. Required exported symbols (stable ABI)

The shim dynamic library MUST export exactly these symbols (C ABI), with these signatures:

**Verification (consensus-critical):**
1. `int32_t rubin_wc_sha3_256(const uint8_t* input, size_t input_len, uint8_t out32[32]);`
2. `int32_t rubin_wc_verify_mldsa87(const uint8_t* pk, size_t pk_len, const uint8_t* sig, size_t sig_len, const uint8_t digest32[32]);`
3. `int32_t rubin_wc_verify_slhdsa_shake_256f(const uint8_t* pk, size_t pk_len, const uint8_t* sig, size_t sig_len, const uint8_t digest32[32]);`

**Key management (operator / sequencer):**
4. `int32_t rubin_wc_aes_keywrap(const uint8_t* kek, size_t kek_len, const uint8_t* key_in, size_t key_in_len, uint8_t* out, size_t* out_len);`
5. `int32_t rubin_wc_aes_keyunwrap(const uint8_t* kek, size_t kek_len, const uint8_t* wrapped, size_t wrapped_len, uint8_t* key_out, size_t* key_out_len);`

Return code contract (MUST):

**Verification symbols (1–3):**
- `1`: verification succeeded (signature valid)
- `0`: verification failed (signature invalid)
- `<0`: internal/provider error (treated as validation failure by clients)

**Keywrap symbols (4–5):**
- `>0`: bytes written to output buffer (success)
- `-30`: null argument
- `-31`: `kek_len != 32` — only AES-256 (32-byte KEK) is accepted
- `-32`: `key_in_len` is 0 or exceeds `RUBIN_WC_KEYWRAP_MAX_KEY_BYTES` (4096)
- `-33`: output buffer too small
- `-34`: wolfCrypt AES init failed
- `-35`: wolfCrypt wrap/unwrap operation failed
- `-36`: integrity check failed (unwrap only — wrong KEK or corrupted blob)

**Keywrap algorithm:**
- Algorithm: AES-256 Key Wrap per RFC 3394, default IV (`0xA6A6A6A6A6A6A6A6`)
- `kek_len` MUST be 32 (AES-256 only — AES-128/192 rejected with `-31`)
- `key_in_len` MUST be a non-zero multiple of 8 (RFC 3394 requirement)
- Output size = `key_in_len + 8` (8-byte integrity check value)
- Deterministic for identical inputs and KEK

Memory safety contract (MUST):

- The shim MUST NOT retain pointers after returning (no borrowing of input buffers).
- The shim MUST NOT write beyond `out32[32]`.

Determinism contract (MUST):

- Verification MUST be deterministic for identical inputs.

## 3. Algorithm contracts

### 3.1 SHA3-256

- Must match NIST SHA-3 (FIPS 202) SHA3-256.

### 3.2 ML-DSA-87 verify

- Must implement FIPS 204 ML-DSA parameter set 87 (Category 5).

### 3.3 SLH-DSA-SHAKE-256f verify

- Must implement FIPS 205 SLH-DSA with SHAKE-256, "fast" variant, Category 5.
- Public key wire size expected by RUBIN is 64 bytes.
- Signature size is variable; RUBIN bounds it by `MAX_SLH_DSA_SIG_BYTES` in `spec/RUBIN_L1_CANONICAL_v1.1.md`.

## 4. Optional test-only exports (recommended)

The shim MAY optionally export signing functions for fixture generation and KAT-style checks.
These exports are not required by node verification paths.

Recommended:

1. `int32_t rubin_wc_sign_mldsa87(const uint8_t* sk, size_t sk_len, const uint8_t digest32[32], uint8_t* sig_out, size_t* sig_out_len);`
2. `int32_t rubin_wc_sign_slhdsa_shake_256f(const uint8_t* sk, size_t sk_len, const uint8_t digest32[32], uint8_t* sig_out, size_t* sig_out_len);`

If present:

- `sig_out_len` is an in/out parameter:
  - on entry: capacity of `sig_out` buffer
  - on success: actual signature length written
- Return codes follow the same convention as verify.

## 5. Platform deliverables

At minimum, provide:

- Linux x86_64: `librubin_wc_shim.so`
- macOS arm64: `librubin_wc_shim.dylib`

Optional (later):

- Windows x86_64: `rubin_wc_shim.dll`

## 6. Provenance and reproducibility (FIPS-path)

The deliverable MUST include build notes sufficient to reproduce the shim binary:

- wolfSSL/wolfCrypt version identifiers (exact)
- compile flags and feature toggles (PQC enabled, SHAKE enabled)
- toolchain version (compiler, linker)
- operating environment (OS version, arch)
- whether FIPS boundary is claimed and under what certificate/configuration (if any)

## 7. Integration points in this repo (reference)

Rust loader:

- `clients/rust/crates/rubin-crypto/src/wolfcrypt_dylib.rs`

Go loader (build tag `wolfcrypt_dylib`):

- `clients/go/crypto/wolfcrypt_dylib_provider.go`

ABI overview:

- `crypto/wolfcrypt/README.md`

## 8. Non-goals

- This document does not require shipping the shim in this repo.
- This document does not define L1 consensus rules.

## 9. Local development stub (non-cryptographic)

For integration testing of the runtime loaders (Rust/Go), operators MAY use a local stub shim that exports
the required symbols but always returns provider errors (e.g., `-10`). This validates:

1. dlopen/dlsym wiring
2. symbol name stability
3. call/ABI correctness

Such a stub provides no security and MUST NOT be used for any environment that expects correct verification.

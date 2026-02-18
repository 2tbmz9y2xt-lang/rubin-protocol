/*
 * RubiN wolfCrypt shim (external, reproducible artifact source)
 *
 * Implements the stable RUBIN C ABI expected by rust/go clients.
 *
 * Exported symbols:
 *   rubin_wc_sha3_256               — SHA3-256 hash
 *   rubin_wc_verify_mldsa87         — ML-DSA-87 signature verify
 *   rubin_wc_verify_slhdsa_shake_256f — SLH-DSA-SHAKE-256f signature verify
 *   rubin_wc_aes_keywrap            — AES-256-KW wrap (RFC 3394)
 *   rubin_wc_aes_keyunwrap          — AES-256-KW unwrap (RFC 3394)
 *
 * Keywrap return codes:
 *   >0 : bytes written to output buffer
 *   -30: null argument
 *   -31: kek_len != 32 (must be AES-256)
 *   -32: input too large (> RUBIN_WC_KEYWRAP_MAX_KEY_BYTES)
 *   -33: output buffer too small
 *   -34: wolfCrypt AES init failed
 *   -35: wolfCrypt wrap/unwrap operation failed
 *   -36: integrity check failed (unwrap only — wrong KEK or corrupted blob)
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/sphincs.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Maximum plaintext key size accepted by wrap/unwrap (ML-DSA-87 sk = 4032 bytes) */
#define RUBIN_WC_KEYWRAP_MAX_KEY_BYTES 4096
/* AES-KW adds 8 bytes of integrity check value (ICV) per RFC 3394 */
#define RUBIN_WC_KEYWRAP_OVERHEAD 8

static int32_t rubin_wc_sha3_256_impl(const uint8_t* input, size_t input_len,
                                      uint8_t out32[32]) {
    if (out32 == NULL) {
        return -1;
    }
    if (input == NULL && input_len != 0) {
        return -2;
    }

    wc_Sha3 hash;
    int rc = wc_InitSha3_256(&hash, NULL, INVALID_DEVID);
    if (rc != 0) {
        return -3;
    }

    rc = wc_Sha3_256_Update(&hash, (const byte*)input, (word32)input_len);
    if (rc != 0) {
        wc_Sha3_256_Free(&hash);
        return -4;
    }

    rc = wc_Sha3_256_Final(&hash, out32);
    wc_Sha3_256_Free(&hash);
    if (rc != 0) {
        return -5;
    }

    return 1;
}

int32_t rubin_wc_sha3_256(const uint8_t* input, size_t input_len,
                          uint8_t out32[32]) {
    return rubin_wc_sha3_256_impl(input, input_len, out32);
}

int32_t rubin_wc_verify_mldsa87(const uint8_t* pk, size_t pk_len,
                                const uint8_t* sig, size_t sig_len,
                                const uint8_t digest32[32]) {
    if (pk == NULL || sig == NULL || digest32 == NULL) {
        return -10;
    }

    int rc;
    dilithium_key key;
    rc = wc_dilithium_init(&key);
    if (rc != 0) {
        return -11;
    }

    // ML-DSA Level 5 = RubiN ML-DSA-87.
    rc = wc_dilithium_set_level(&key, 5);
    if (rc != 0) {
        wc_dilithium_free(&key);
        return -12;
    }

    rc = wc_dilithium_import_public(pk, (word32)pk_len, &key);
    if (rc != 0) {
        wc_dilithium_free(&key);
        return -13;
    }

    int verified = 0;
    rc = wc_dilithium_verify_msg(sig, (word32)sig_len, digest32, 32, &verified,
                                &key);
    wc_dilithium_free(&key);
    if (rc != 0) {
        return -14;
    }

    return (verified == 1) ? 1 : 0;
}

int32_t rubin_wc_verify_slhdsa_shake_256f(const uint8_t* pk, size_t pk_len,
                                          const uint8_t* sig, size_t sig_len,
                                          const uint8_t digest32[32]) {
    #if defined(HAVE_PQC) && defined(HAVE_SPHINCS)
    if (pk == NULL || sig == NULL || digest32 == NULL) {
        return -20;
    }

    int rc;
    sphincs_key key;
    rc = wc_sphincs_init(&key);
    if (rc != 0) {
        return -21;
    }

    // Level 5 FAST = SLH-DSA-SHAKE-256f equivalent in wolfCrypt API mapping.
    rc = wc_sphincs_set_level_and_optim(&key, 5, FAST_VARIANT);
    if (rc != 0) {
        wc_sphincs_free(&key);
        return -22;
    }

    rc = wc_sphincs_import_public(pk, (word32)pk_len, &key);
    if (rc != 0) {
        wc_sphincs_free(&key);
        return -23;
    }

    int verified = 0;
    rc = wc_sphincs_verify_msg(sig, (word32)sig_len, digest32, 32, &verified, &key);
    wc_sphincs_free(&key);
    if (rc != 0) {
        return -24;
    }

    return (verified == 1) ? 1 : 0;
    #else
    (void)pk;
    (void)pk_len;
    (void)sig;
    (void)sig_len;
    (void)digest32;
    return -25;
    #endif
}

/*
 * rubin_wc_aes_keywrap — AES-256 Key Wrap (RFC 3394)
 *
 * Encrypts `key_in` (plaintext key material) using `kek` as Key Encryption Key.
 * Output is written to `out`. On success, `*out_len` is set to bytes written.
 *
 * `out` buffer must be at least `key_in_len + RUBIN_WC_KEYWRAP_OVERHEAD` bytes.
 * `*out_len` on entry: capacity of `out`. On success: actual bytes written.
 *
 * kek_len MUST be 32 (AES-256). key_in_len MUST be a multiple of 8 (RFC 3394).
 *
 * Returns: bytes written (>0) on success, negative error code on failure.
 */
int32_t rubin_wc_aes_keywrap(
    const uint8_t* kek,    size_t kek_len,
    const uint8_t* key_in, size_t key_in_len,
    uint8_t*       out,    size_t* out_len)
{
    if (kek == NULL || key_in == NULL || out == NULL || out_len == NULL)
        return -30;
    if (kek_len != 32)
        return -31;
    if (key_in_len == 0 || key_in_len > RUBIN_WC_KEYWRAP_MAX_KEY_BYTES)
        return -32;

    size_t required = key_in_len + RUBIN_WC_KEYWRAP_OVERHEAD;
    if (*out_len < required)
        return -33;

    Aes aes;
    int rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc != 0)
        return -34;

    /* wc_AesKeyWrap: kek, kek_len, in, in_len, out, out_len, iv=NULL (use default IV per RFC 3394) */
    rc = wc_AesKeyWrap(kek, (word32)kek_len,
                       key_in, (word32)key_in_len,
                       out, (word32)required,
                       NULL);
    wc_AesFree(&aes);

    if (rc <= 0)
        return -35;

    *out_len = (size_t)rc;
    return (int32_t)rc;
}

/*
 * rubin_wc_aes_keyunwrap — AES-256 Key Unwrap (RFC 3394)
 *
 * Decrypts `wrapped` blob using `kek`. Plaintext key written to `key_out`.
 * On success, `*key_out_len` is set to bytes written.
 *
 * If the integrity check fails (wrong KEK or corrupted blob), returns -36.
 *
 * Returns: bytes written (>0) on success, negative error code on failure.
 */
int32_t rubin_wc_aes_keyunwrap(
    const uint8_t* kek,     size_t kek_len,
    const uint8_t* wrapped, size_t wrapped_len,
    uint8_t*       key_out, size_t* key_out_len)
{
    if (kek == NULL || wrapped == NULL || key_out == NULL || key_out_len == NULL)
        return -30;
    if (kek_len != 32)
        return -31;
    if (wrapped_len < RUBIN_WC_KEYWRAP_OVERHEAD ||
        wrapped_len > RUBIN_WC_KEYWRAP_MAX_KEY_BYTES + RUBIN_WC_KEYWRAP_OVERHEAD)
        return -32;

    size_t plain_len = wrapped_len - RUBIN_WC_KEYWRAP_OVERHEAD;
    if (*key_out_len < plain_len)
        return -33;

    Aes aes;
    int rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc != 0)
        return -34;

    rc = wc_AesKeyUnWrap(kek, (word32)kek_len,
                         wrapped, (word32)wrapped_len,
                         key_out, (word32)plain_len,
                         NULL);
    wc_AesFree(&aes);

    if (rc == BAD_KEYWRAP_IV_E)
        return -36; /* integrity check failed — wrong KEK or corrupted blob */
    if (rc <= 0)
        return -35;

    *key_out_len = (size_t)rc;
    return (int32_t)rc;
}

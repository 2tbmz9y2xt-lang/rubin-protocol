/*
 * RubiN wolfCrypt shim (external, reproducible artifact source)
 *
 * Implements the stable RUBIN C ABI expected by rust/go clients.
 */

#include <stddef.h>
#include <stdint.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/sphincs.h>

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

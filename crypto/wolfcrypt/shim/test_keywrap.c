/*
 * test_keywrap.c — AES-256-KW (RFC 3394) smoke test for rubin_wc_shim
 *
 * Tests:
 *   1. wrap + unwrap roundtrip — plaintext recovered intact
 *   2. unwrap with wrong KEK   — returns -36 (integrity check failure)
 *   3. null argument guard     — returns -30
 *   4. bad kek_len             — returns -31
 *   5. oversized input         — returns -32
 *   6. output buffer too small — returns -33
 *
 * Build (after wolfCrypt installed to $PREFIX):
 *   cc test_keywrap.c -o test_keywrap \
 *       -I$PREFIX/include -L$PREFIX/lib -lwolfssl \
 *       -Wl,-rpath,$PREFIX/lib
 *   ./test_keywrap
 *
 * Expected output: all tests PASS, exit 0.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Pull in the shim source directly for unit testing without dlopen */
#include "rubin_wc_shim.c"

#define PASS(label) do { printf("PASS  %s\n", label); } while(0)
#define FAIL(label, ...) do { printf("FAIL  %s: ", label); printf(__VA_ARGS__); printf("\n"); exit(1); } while(0)

int main(void) {
    printf("rubin_wc_shim keywrap smoke test\n");
    printf("=================================\n");

    /* ── Test vectors ── */

    /* 32-byte KEK (AES-256) */
    static const uint8_t kek[32] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b, 0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b, 0x1c,0x1d,0x1e,0x1f,
    };

    /* Wrong KEK for negative test */
    static const uint8_t wrong_kek[32] = {
        0xff,0xfe,0xfd,0xfc, 0xfb,0xfa,0xf9,0xf8,
        0xf7,0xf6,0xf5,0xf4, 0xf3,0xf2,0xf1,0xf0,
        0xef,0xee,0xed,0xec, 0xeb,0xea,0xe9,0xe8,
        0xe7,0xe6,0xe5,0xe4, 0xe3,0xe2,0xe1,0xe0,
    };

    /*
     * 32-byte plaintext key (multiple of 8 — required by RFC 3394).
     * In production this would be an ML-DSA private key seed or symmetric key.
     */
    static const uint8_t plain_key[32] = {
        0xde,0xad,0xbe,0xef, 0xca,0xfe,0xba,0xbe,
        0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
        0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10,
        0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88,
    };

    uint8_t wrapped[32 + 8 + 16]; /* plain + overhead + margin */
    uint8_t unwrapped[64];
    int32_t rc;

    /* ── Test 1: wrap + unwrap roundtrip ── */
    {
        size_t wrap_len = sizeof(wrapped);
        rc = rubin_wc_aes_keywrap(kek, 32, plain_key, 32, wrapped, &wrap_len);
        if (rc <= 0)
            FAIL("T1 wrap", "expected >0, got %d", rc);
        if (wrap_len != 32 + 8)
            FAIL("T1 wrap_len", "expected 40, got %zu", wrap_len);

        size_t unwrap_len = sizeof(unwrapped);
        rc = rubin_wc_aes_keyunwrap(kek, 32, wrapped, wrap_len, unwrapped, &unwrap_len);
        if (rc <= 0)
            FAIL("T1 unwrap", "expected >0, got %d", rc);
        if (unwrap_len != 32)
            FAIL("T1 unwrap_len", "expected 32, got %zu", unwrap_len);
        if (memcmp(unwrapped, plain_key, 32) != 0)
            FAIL("T1 roundtrip", "plaintext mismatch after unwrap");

        PASS("T1  wrap+unwrap roundtrip (32-byte key)");
    }

    /* ── Test 2: unwrap with wrong KEK → integrity failure -36 ── */
    {
        size_t wrap_len = sizeof(wrapped);
        rc = rubin_wc_aes_keywrap(kek, 32, plain_key, 32, wrapped, &wrap_len);
        if (rc <= 0) FAIL("T2 wrap", "wrap failed: %d", rc);

        size_t unwrap_len = sizeof(unwrapped);
        rc = rubin_wc_aes_keyunwrap(wrong_kek, 32, wrapped, wrap_len, unwrapped, &unwrap_len);
        if (rc != -36)
            FAIL("T2 wrong_kek", "expected -36 (integrity fail), got %d", rc);

        PASS("T2  wrong KEK → -36 (integrity check failed)");
    }

    /* ── Test 3: null argument → -30 ── */
    {
        size_t len = sizeof(wrapped);
        rc = rubin_wc_aes_keywrap(NULL, 32, plain_key, 32, wrapped, &len);
        if (rc != -30) FAIL("T3a null kek", "expected -30, got %d", rc);

        rc = rubin_wc_aes_keywrap(kek, 32, NULL, 32, wrapped, &len);
        if (rc != -30) FAIL("T3b null key_in", "expected -30, got %d", rc);

        rc = rubin_wc_aes_keywrap(kek, 32, plain_key, 32, NULL, &len);
        if (rc != -30) FAIL("T3c null out", "expected -30, got %d", rc);

        rc = rubin_wc_aes_keywrap(kek, 32, plain_key, 32, wrapped, NULL);
        if (rc != -30) FAIL("T3d null out_len", "expected -30, got %d", rc);

        PASS("T3  null arguments → -30");
    }

    /* ── Test 4: bad kek_len → -31 ── */
    {
        size_t len = sizeof(wrapped);
        rc = rubin_wc_aes_keywrap(kek, 16, plain_key, 32, wrapped, &len); /* AES-128 not allowed */
        if (rc != -31) FAIL("T4 kek_len=16", "expected -31, got %d", rc);

        rc = rubin_wc_aes_keywrap(kek, 24, plain_key, 32, wrapped, &len); /* AES-192 not allowed */
        if (rc != -31) FAIL("T4 kek_len=24", "expected -31, got %d", rc);

        PASS("T4  kek_len != 32 → -31");
    }

    /* ── Test 5: key_in_len = 0 → -32 ── */
    {
        size_t len = sizeof(wrapped);
        rc = rubin_wc_aes_keywrap(kek, 32, plain_key, 0, wrapped, &len);
        if (rc != -32) FAIL("T5 zero len", "expected -32, got %d", rc);

        PASS("T5  zero key_in_len → -32");
    }

    /* ── Test 6: output buffer too small → -33 ── */
    {
        size_t too_small = 4; /* needs 40 bytes for 32-byte key */
        rc = rubin_wc_aes_keywrap(kek, 32, plain_key, 32, wrapped, &too_small);
        if (rc != -33) FAIL("T6 small out", "expected -33, got %d", rc);

        PASS("T6  small output buffer → -33");
    }

    printf("=================================\n");
    printf("All tests PASS\n");
    return 0;
}

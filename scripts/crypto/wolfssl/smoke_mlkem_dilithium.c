#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/mlkem.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/xmss.h>
#include <wolfssl/wolfcrypt/lms.h>

int main(void)
{
    int ret = 0;
    MlKemKey* kem = NULL;
    dilithium_key* d = NULL;

    kem = wc_MlKemKey_New(WC_ML_KEM_768, NULL, -1);
    if (kem == NULL) {
        fprintf(stderr, "mlkem new failed\n");
        return 1;
    }
    ret = wc_MlKemKey_Init(kem, WC_ML_KEM_768, NULL, -1);
    if (ret != 0) {
        fprintf(stderr, "mlkem init failed: %d\n", ret);
        wc_MlKemKey_Delete(kem, &kem);
        return 1;
    }
    wc_MlKemKey_Delete(kem, &kem);

    d = wc_dilithium_new(NULL, -1);
    if (d == NULL) {
        fprintf(stderr, "dilithium_new failed\n");
        return 1;
    }
    ret = wc_dilithium_init(d);
    if (ret != 0) {
        fprintf(stderr, "dilithium_init failed: %d\n", ret);
        wc_dilithium_delete(d, &d);
        return 1;
    }
    ret = wc_dilithium_set_level(d, 5);
    if (ret != 0) {
        fprintf(stderr, "dilithium_set_level failed: %d\n", ret);
        wc_dilithium_free(d);
        return 1;
    }
    wc_dilithium_free(d);

    /* Keep link-time coverage for XMSS/LMS API as build-time availability probes */
    (void)wc_XmssKey_Init;
    (void)wc_XmssKey_Free;
    (void)wc_LmsKey_Init;
    (void)wc_LmsKey_Free;
    (void)wc_MlKemKey_Encapsulate;
    (void)wc_dilithium_sign_msg;
    (void)wc_dilithium_verify_msg;

    return 0;
}

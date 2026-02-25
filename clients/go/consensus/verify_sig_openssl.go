//go:build cgo

package consensus

/*
#cgo pkg-config: openssl

#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void rubin_err(char* out, size_t out_len, const char* prefix) {
	if (out == NULL || out_len == 0) {
		return;
	}
	unsigned long e = ERR_get_error();
	if (e == 0) {
		strncpy(out, prefix, out_len - 1);
		out[out_len - 1] = 0;
		return;
	}
	char buf[256];
	ERR_error_string_n(e, buf, sizeof(buf));
	snprintf(out, out_len, "%s: %s", prefix, buf);
}

// Returns:
//  1  -> signature valid
//  0  -> signature invalid
// -1  -> internal error (err_buf populated)
static int rubin_verify_sig_message(
	const char* alg,
	const unsigned char* pub,
	size_t pub_len,
	const unsigned char* sig,
	size_t sig_len,
	const unsigned char* msg,
	size_t msg_len,
	char* err_buf,
	size_t err_buf_len
) {
	ERR_clear_error();

	EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pub, pub_len);
	if (pkey == NULL) {
		rubin_err(err_buf, err_buf_len, "EVP_PKEY_new_raw_public_key_ex failed");
		return -1;
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL) {
		EVP_PKEY_free(pkey);
		rubin_err(err_buf, err_buf_len, "EVP_PKEY_CTX_new failed");
		return -1;
	}

	if (EVP_PKEY_verify_message_init(ctx, NULL, NULL) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		rubin_err(err_buf, err_buf_len, "EVP_PKEY_verify_message_init failed");
		return -1;
	}

	if (EVP_PKEY_CTX_set_signature(ctx, sig, sig_len) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		rubin_err(err_buf, err_buf_len, "EVP_PKEY_CTX_set_signature failed");
		return -1;
	}
	if (EVP_PKEY_verify_message_update(ctx, msg, msg_len) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		rubin_err(err_buf, err_buf_len, "EVP_PKEY_verify_message_update failed");
		return -1;
	}

	int rc = EVP_PKEY_verify_message_final(ctx);

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	if (rc == 1) {
		return 1;
	}
	if (rc == 0) {
		return 0;
	}
	rubin_err(err_buf, err_buf_len, "EVP_PKEY_verify_message_final returned error");
	return -1;
}

// Returns:
//  1  -> signature valid
//  0  -> signature invalid
// -1  -> internal error (err_buf populated)
//
// NOTE: Some PQC signature implementations in OpenSSL do not support the
// EVP_PKEY_{sign,verify}_message_update streaming API. For those, the one-shot
// EVP_DigestVerify() path works (treating msg as raw bytes, mdname=NULL).
static int rubin_verify_sig_digest_oneshot(
	const char* alg,
	const unsigned char* pub,
	size_t pub_len,
	const unsigned char* sig,
	size_t sig_len,
	const unsigned char* msg,
	size_t msg_len,
	char* err_buf,
	size_t err_buf_len
) {
	ERR_clear_error();

	EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pub, pub_len);
	if (pkey == NULL) {
		rubin_err(err_buf, err_buf_len, "EVP_PKEY_new_raw_public_key_ex failed");
		return -1;
	}

	EVP_MD_CTX* mctx = EVP_MD_CTX_new();
	if (mctx == NULL) {
		EVP_PKEY_free(pkey);
		rubin_err(err_buf, err_buf_len, "EVP_MD_CTX_new failed");
		return -1;
	}

	if (EVP_DigestVerifyInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
		EVP_MD_CTX_free(mctx);
		EVP_PKEY_free(pkey);
		rubin_err(err_buf, err_buf_len, "EVP_DigestVerifyInit_ex failed");
		return -1;
	}

	int rc = EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len);

	EVP_MD_CTX_free(mctx);
	EVP_PKEY_free(pkey);

	if (rc == 1) {
		return 1;
	}
	if (rc == 0) {
		return 0;
	}
	rubin_err(err_buf, err_buf_len, "EVP_DigestVerify returned error");
	return -1;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func opensslVerifySigMessage(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
	if alg == "" {
		return false, fmt.Errorf("openssl: empty algorithm")
	}
	if len(pubkey) == 0 {
		return false, fmt.Errorf("openssl: empty pubkey")
	}
	if len(signature) == 0 {
		return false, fmt.Errorf("openssl: empty signature")
	}
	if len(msg) == 0 {
		return false, fmt.Errorf("openssl: empty message")
	}

	cAlg := C.CString(alg)
	defer C.free(unsafe.Pointer(cAlg))

	errBuf := make([]byte, 512)
	rc := C.rubin_verify_sig_message(
		cAlg,
		(*C.uchar)(unsafe.Pointer(&pubkey[0])),
		C.size_t(len(pubkey)),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
		(*C.uchar)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg)),
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	)
	switch int(rc) {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		// Trim at first NUL.
		n := 0
		for n < len(errBuf) && errBuf[n] != 0 {
			n++
		}
		return false, fmt.Errorf("openssl verify failed: %s", string(errBuf[:n]))
	}
}

func opensslVerifySigDigestOneShot(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
	if alg == "" {
		return false, fmt.Errorf("openssl: empty algorithm")
	}
	if len(pubkey) == 0 {
		return false, fmt.Errorf("openssl: empty pubkey")
	}
	if len(signature) == 0 {
		return false, fmt.Errorf("openssl: empty signature")
	}
	if len(msg) == 0 {
		return false, fmt.Errorf("openssl: empty message")
	}

	cAlg := C.CString(alg)
	defer C.free(unsafe.Pointer(cAlg))

	errBuf := make([]byte, 512)
	rc := C.rubin_verify_sig_digest_oneshot(
		cAlg,
		(*C.uchar)(unsafe.Pointer(&pubkey[0])),
		C.size_t(len(pubkey)),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
		(*C.uchar)(unsafe.Pointer(&msg[0])),
		C.size_t(len(msg)),
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	)
	switch int(rc) {
	case 1:
		return true, nil
	case 0:
		return false, nil
	default:
		n := 0
		for n < len(errBuf) && errBuf[n] != 0 {
			n++
		}
		return false, fmt.Errorf("openssl verify failed: %s", string(errBuf[:n]))
	}
}

func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
	switch suiteID {
	case SUITE_ID_ML_DSA_87:
		return opensslVerifySigMessage("ML-DSA-87", pubkey, signature, digest32[:])
	case SUITE_ID_SLH_DSA_SHAKE_256F:
		return opensslVerifySigDigestOneShot("SLH-DSA-SHAKE-256f", pubkey, signature, digest32[:])
	default:
		return false, txerr(TX_ERR_SIG_ALG_INVALID, "verify_sig: unsupported suite_id")
	}
}

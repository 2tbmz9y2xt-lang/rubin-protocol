//go:build cgo

package consensus

/*
#cgo pkg-config: openssl

#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void rubin_err_sign(char* out, size_t out_len, const char* prefix) {
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

static EVP_PKEY* rubin_keygen(const char* alg, char* err_buf, size_t err_buf_len) {
	ERR_clear_error();
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
	if (ctx == NULL) {
		rubin_err_sign(err_buf, err_buf_len, "EVP_PKEY_CTX_new_from_name failed");
		return NULL;
	}
	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		rubin_err_sign(err_buf, err_buf_len, "EVP_PKEY_keygen_init failed");
		return NULL;
	}
	EVP_PKEY* pkey = NULL;
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0 || pkey == NULL) {
		EVP_PKEY_CTX_free(ctx);
		rubin_err_sign(err_buf, err_buf_len, "EVP_PKEY_keygen failed");
		return NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

static int rubin_get_raw_public(EVP_PKEY* pkey, unsigned char* out, size_t out_cap, size_t* out_len, char* err_buf, size_t err_buf_len) {
	ERR_clear_error();
	size_t n = out_cap;
	if (EVP_PKEY_get_raw_public_key(pkey, out, &n) <= 0) {
		rubin_err_sign(err_buf, err_buf_len, "EVP_PKEY_get_raw_public_key failed");
		return -1;
	}
	*out_len = n;
	return 0;
}

static int rubin_sign_msg(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len, unsigned char* sig_out, size_t sig_cap, size_t* sig_len, char* err_buf, size_t err_buf_len) {
	ERR_clear_error();
	EVP_MD_CTX* mctx = EVP_MD_CTX_new();
	if (mctx == NULL) {
		rubin_err_sign(err_buf, err_buf_len, "EVP_MD_CTX_new failed");
		return -1;
	}
	if (EVP_DigestSignInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
		EVP_MD_CTX_free(mctx);
		rubin_err_sign(err_buf, err_buf_len, "EVP_DigestSignInit_ex failed");
		return -1;
	}
	size_t n = sig_cap;
	if (EVP_DigestSign(mctx, sig_out, &n, msg, msg_len) <= 0) {
		EVP_MD_CTX_free(mctx);
		rubin_err_sign(err_buf, err_buf_len, "EVP_DigestSign failed");
		return -1;
	}
	EVP_MD_CTX_free(mctx);
	*sig_len = n;
	return 0;
}

	// One-shot sign path used by SLH-DSA: EVP_DigestSignInit_ex(mdname=NULL) + EVP_DigestSign().
	static int rubin_digest_sign_oneshot(EVP_PKEY* pkey, const unsigned char* msg, size_t msg_len, unsigned char* sig_out, size_t sig_cap, size_t* sig_len, char* err_buf, size_t err_buf_len) {
		ERR_clear_error();
		EVP_MD_CTX* mctx = EVP_MD_CTX_new();
		if (mctx == NULL) {
			rubin_err_sign(err_buf, err_buf_len, "EVP_MD_CTX_new failed");
			return -1;
		}
		if (EVP_DigestSignInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, NULL) <= 0) {
			EVP_MD_CTX_free(mctx);
			rubin_err_sign(err_buf, err_buf_len, "EVP_DigestSignInit_ex failed");
			return -1;
		}
		size_t n = sig_cap;
		if (EVP_DigestSign(mctx, sig_out, &n, msg, msg_len) <= 0) {
			EVP_MD_CTX_free(mctx);
			rubin_err_sign(err_buf, err_buf_len, "EVP_DigestSign failed");
			return -1;
		}
		EVP_MD_CTX_free(mctx);
		*sig_len = n;
		return 0;
	}

*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// MLDSA87Keypair is a non-consensus helper used by tests and conformance tooling
// to generate real signatures under the OpenSSL backend profile.
type MLDSA87Keypair struct {
	pkey   *C.EVP_PKEY
	pubkey []byte
}

func (k *MLDSA87Keypair) Close() {
	if k == nil || k.pkey == nil {
		return
	}
	C.EVP_PKEY_free(k.pkey)
	k.pkey = nil
}

func (k *MLDSA87Keypair) PubkeyBytes() []byte {
	if k == nil {
		return nil
	}
	return append([]byte(nil), k.pubkey...)
}

func NewMLDSA87Keypair() (*MLDSA87Keypair, error) {
	errBuf := make([]byte, 512)
	cAlg := C.CString("ML-DSA-87")
	defer C.free(unsafe.Pointer(cAlg))

	pkey := C.rubin_keygen(cAlg, (*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf)))
	if pkey == nil {
		return nil, fmt.Errorf("openssl keygen failed: %s", cStringTrim0(errBuf))
	}

	pub := make([]byte, ML_DSA_87_PUBKEY_BYTES)
	var pubLen C.size_t
	if C.rubin_get_raw_public(pkey, (*C.uchar)(unsafe.Pointer(&pub[0])), C.size_t(len(pub)), &pubLen, (*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf))) != 0 {
		C.EVP_PKEY_free(pkey)
		return nil, fmt.Errorf("openssl get_raw_public failed: %s", cStringTrim0(errBuf))
	}
	if int(pubLen) != ML_DSA_87_PUBKEY_BYTES {
		C.EVP_PKEY_free(pkey)
		return nil, fmt.Errorf("openssl pubkey length=%d, want %d", int(pubLen), ML_DSA_87_PUBKEY_BYTES)
	}

	kp := &MLDSA87Keypair{pkey: pkey, pubkey: pub}
	runtime.SetFinalizer(kp, func(k *MLDSA87Keypair) { k.Close() })
	return kp, nil
}

func (k *MLDSA87Keypair) SignDigest32(digest [32]byte) ([]byte, error) {
	if k == nil || k.pkey == nil {
		return nil, fmt.Errorf("nil keypair")
	}
	errBuf := make([]byte, 512)
	sig := make([]byte, ML_DSA_87_SIG_BYTES)
	var sigLen C.size_t
	if C.rubin_sign_msg(
		k.pkey,
		(*C.uchar)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest)),
		(*C.uchar)(unsafe.Pointer(&sig[0])),
		C.size_t(len(sig)),
		&sigLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	) != 0 {
		return nil, fmt.Errorf("openssl sign failed: %s", cStringTrim0(errBuf))
	}
	if int(sigLen) != ML_DSA_87_SIG_BYTES {
		return nil, fmt.Errorf("openssl sig length=%d, want %d", int(sigLen), ML_DSA_87_SIG_BYTES)
	}
	return sig, nil
}

// SLHDSASHAKE256fKeypair is a non-consensus helper used by conformance tooling to
// generate real SLH-DSA signatures (fallback suite, post-activation).
type SLHDSASHAKE256fKeypair struct {
	pkey   *C.EVP_PKEY
	pubkey []byte
}

func (k *SLHDSASHAKE256fKeypair) Close() {
	if k == nil || k.pkey == nil {
		return
	}
	C.EVP_PKEY_free(k.pkey)
	k.pkey = nil
}

func (k *SLHDSASHAKE256fKeypair) PubkeyBytes() []byte {
	if k == nil {
		return nil
	}
	return append([]byte(nil), k.pubkey...)
}

func NewSLHDSASHAKE256fKeypair() (*SLHDSASHAKE256fKeypair, error) {
	errBuf := make([]byte, 512)
	cAlg := C.CString("SLH-DSA-SHAKE-256f")
	defer C.free(unsafe.Pointer(cAlg))

	pkey := C.rubin_keygen(cAlg, (*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf)))
	if pkey == nil {
		return nil, fmt.Errorf("openssl keygen failed: %s", cStringTrim0(errBuf))
	}

	pub := make([]byte, SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	var pubLen C.size_t
	if C.rubin_get_raw_public(pkey, (*C.uchar)(unsafe.Pointer(&pub[0])), C.size_t(len(pub)), &pubLen, (*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf))) != 0 {
		C.EVP_PKEY_free(pkey)
		return nil, fmt.Errorf("openssl get_raw_public failed: %s", cStringTrim0(errBuf))
	}
	if int(pubLen) != SLH_DSA_SHAKE_256F_PUBKEY_BYTES {
		C.EVP_PKEY_free(pkey)
		return nil, fmt.Errorf("openssl pubkey length=%d, want %d", int(pubLen), SLH_DSA_SHAKE_256F_PUBKEY_BYTES)
	}

	kp := &SLHDSASHAKE256fKeypair{pkey: pkey, pubkey: pub}
	runtime.SetFinalizer(kp, func(k *SLHDSASHAKE256fKeypair) { k.Close() })
	return kp, nil
}

func (k *SLHDSASHAKE256fKeypair) SignDigest32(digest [32]byte) ([]byte, error) {
	if k == nil || k.pkey == nil {
		return nil, fmt.Errorf("nil keypair")
	}
	errBuf := make([]byte, 512)
	sig := make([]byte, MAX_SLH_DSA_SIG_BYTES)
	var sigLen C.size_t
	if C.rubin_digest_sign_oneshot(
		k.pkey,
		(*C.uchar)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest)),
		(*C.uchar)(unsafe.Pointer(&sig[0])),
		C.size_t(len(sig)),
		&sigLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	) != 0 {
		return nil, fmt.Errorf("openssl sign failed: %s", cStringTrim0(errBuf))
	}
	if sigLen == 0 || int(sigLen) > MAX_SLH_DSA_SIG_BYTES {
		return nil, fmt.Errorf("openssl sig length=%d, want 1..%d", int(sigLen), MAX_SLH_DSA_SIG_BYTES)
	}
	return sig[:sigLen], nil
}

func cStringTrim0(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

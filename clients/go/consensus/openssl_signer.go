//go:build cgo

package consensus

/*
#cgo pkg-config: openssl

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
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

static EVP_PKEY* rubin_parse_private_key_der(const unsigned char* der, size_t der_len, char* err_buf, size_t err_buf_len) {
	ERR_clear_error();
	const unsigned char* p = der;
	EVP_PKEY* pkey = d2i_AutoPrivateKey(NULL, &p, der_len);
	if (pkey == NULL) {
		rubin_err_sign(err_buf, err_buf_len, "d2i_AutoPrivateKey failed");
		return NULL;
	}
	if ((size_t)(p - der) != der_len) {
		EVP_PKEY_free(pkey);
		rubin_err_sign(err_buf, err_buf_len, "private key DER trailing bytes");
		return NULL;
	}
	return pkey;
}

static int rubin_private_key_to_der(EVP_PKEY* pkey, unsigned char** out, size_t* out_len, char* err_buf, size_t err_buf_len) {
	ERR_clear_error();
	int encoded_len = i2d_PrivateKey(pkey, NULL);
	if (encoded_len <= 0) {
		rubin_err_sign(err_buf, err_buf_len, "i2d_PrivateKey size failed");
		return -1;
	}
	unsigned char* der = OPENSSL_malloc((size_t)encoded_len);
	if (der == NULL) {
		rubin_err_sign(err_buf, err_buf_len, "OPENSSL_malloc failed");
		return -1;
	}
	unsigned char* p = der;
	int written = i2d_PrivateKey(pkey, &p);
	if (written != encoded_len) {
		OPENSSL_free(der);
		rubin_err_sign(err_buf, err_buf_len, "i2d_PrivateKey encode failed");
		return -1;
	}
	*out = der;
	*out_len = (size_t)written;
	return 0;
}

static void rubin_free_der(unsigned char* der) {
	OPENSSL_free(der);
}

*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

var keygenAllowlist = map[string]int{
	"ML-DSA-87": ML_DSA_87_PUBKEY_BYTES,
}

func newOpenSSLRawKeypair(alg string, expectedPubkeyLen int) (*C.EVP_PKEY, []byte, error) {
	if err := ensureOpenSSLBootstrap(); err != nil {
		return nil, nil, err
	}
	requiredLen, ok := keygenAllowlist[alg]
	if !ok {
		return nil, nil, fmt.Errorf("openssl keygen algorithm not allowed: %s", alg)
	}
	if expectedPubkeyLen != requiredLen {
		return nil, nil, fmt.Errorf(
			"openssl keygen expected pubkey length mismatch for %s: got %d want %d",
			alg, expectedPubkeyLen, requiredLen,
		)
	}

	errBuf := make([]byte, 512)
	cAlg := C.CString(alg)
	defer C.free(unsafe.Pointer(cAlg))

	pkey := C.rubin_keygen(cAlg, (*C.char)(unsafe.Pointer(&errBuf[0])), C.size_t(len(errBuf)))
	if pkey == nil {
		return nil, nil, fmt.Errorf("openssl keygen failed: %s", cStringTrim0(errBuf))
	}

	pubkey := make([]byte, expectedPubkeyLen)
	var pubLen C.size_t
	if C.rubin_get_raw_public(
		pkey,
		(*C.uchar)(unsafe.Pointer(&pubkey[0])),
		C.size_t(len(pubkey)),
		&pubLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	) != 0 {
		C.EVP_PKEY_free(pkey)
		return nil, nil, fmt.Errorf("openssl get_raw_public failed: %s", cStringTrim0(errBuf))
	}
	if int(pubLen) != expectedPubkeyLen {
		C.EVP_PKEY_free(pkey)
		return nil, nil, fmt.Errorf("openssl pubkey length=%d, want %d", int(pubLen), expectedPubkeyLen)
	}

	return pkey, pubkey, nil
}

func openSSLPublicKeyBytes(pkey *C.EVP_PKEY, expectedPubkeyLen int) ([]byte, error) {
	if pkey == nil {
		return nil, fmt.Errorf("nil openssl key")
	}
	errBuf := make([]byte, 512)
	pubkey := make([]byte, expectedPubkeyLen)
	var pubLen C.size_t
	if C.rubin_get_raw_public(
		pkey,
		(*C.uchar)(unsafe.Pointer(&pubkey[0])),
		C.size_t(len(pubkey)),
		&pubLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	) != 0 {
		return nil, fmt.Errorf("openssl get_raw_public failed: %s", cStringTrim0(errBuf))
	}
	if int(pubLen) != expectedPubkeyLen {
		return nil, fmt.Errorf("openssl pubkey length=%d, want %d", int(pubLen), expectedPubkeyLen)
	}
	return pubkey, nil
}

func newOpenSSLRawKeypairFromDER(alg string, der []byte, expectedPubkeyLen int) (*C.EVP_PKEY, []byte, error) {
	if err := ensureOpenSSLBootstrap(); err != nil {
		return nil, nil, err
	}
	requiredLen, ok := keygenAllowlist[alg]
	if !ok {
		return nil, nil, fmt.Errorf("openssl key import algorithm not allowed: %s", alg)
	}
	if expectedPubkeyLen != requiredLen {
		return nil, nil, fmt.Errorf(
			"openssl key import expected pubkey length mismatch for %s: got %d want %d",
			alg, expectedPubkeyLen, requiredLen,
		)
	}
	if len(der) == 0 {
		return nil, nil, fmt.Errorf("empty private key DER")
	}

	errBuf := make([]byte, 512)
	pkey := C.rubin_parse_private_key_der(
		(*C.uchar)(unsafe.Pointer(&der[0])),
		C.size_t(len(der)),
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	)
	if pkey == nil {
		return nil, nil, fmt.Errorf("openssl private key import failed: %s", cStringTrim0(errBuf))
	}
	pubkey, err := openSSLPublicKeyBytes(pkey, expectedPubkeyLen)
	if err != nil {
		C.EVP_PKEY_free(pkey)
		return nil, nil, err
	}
	return pkey, pubkey, nil
}

func signOpenSSLDigest32(pkey *C.EVP_PKEY, digest [32]byte, maxSigBytes int, exactSigBytes int) ([]byte, error) {
	if err := ensureOpenSSLBootstrap(); err != nil {
		return nil, err
	}

	errBuf := make([]byte, 512)
	signature := make([]byte, maxSigBytes)
	var signatureLen C.size_t

	rc := C.rubin_digest_sign_oneshot(
		pkey,
		(*C.uchar)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest)),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
		&signatureLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	)
	if rc != 0 {
		return nil, fmt.Errorf("openssl sign failed: %s", cStringTrim0(errBuf))
	}

	if exactSigBytes > 0 {
		if int(signatureLen) != exactSigBytes {
			return nil, fmt.Errorf("openssl sig length=%d, want %d", int(signatureLen), exactSigBytes)
		}
	} else if signatureLen == 0 || int(signatureLen) > maxSigBytes {
		return nil, fmt.Errorf("openssl sig length=%d, want 1..%d", int(signatureLen), maxSigBytes)
	}

	return signature[:int(signatureLen)], nil
}

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
	pkey, pub, err := newOpenSSLRawKeypair("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES)
	if err != nil {
		return nil, err
	}

	kp := &MLDSA87Keypair{pkey: pkey, pubkey: pub}
	runtime.SetFinalizer(kp, func(k *MLDSA87Keypair) { k.Close() })
	return kp, nil
}

func NewMLDSA87KeypairFromDER(der []byte) (*MLDSA87Keypair, error) {
	pkey, pub, err := newOpenSSLRawKeypairFromDER("ML-DSA-87", der, ML_DSA_87_PUBKEY_BYTES)
	if err != nil {
		return nil, err
	}

	kp := &MLDSA87Keypair{pkey: pkey, pubkey: pub}
	runtime.SetFinalizer(kp, func(k *MLDSA87Keypair) { k.Close() })
	return kp, nil
}

func (k *MLDSA87Keypair) SignDigest32(digest [32]byte) ([]byte, error) {
	if k == nil || k.pkey == nil {
		return nil, fmt.Errorf("nil keypair")
	}
	return signOpenSSLDigest32(k.pkey, digest, ML_DSA_87_SIG_BYTES, ML_DSA_87_SIG_BYTES)
}

func (k *MLDSA87Keypair) PrivateKeyDER() ([]byte, error) {
	if err := ensureOpenSSLBootstrap(); err != nil {
		return nil, err
	}
	if k == nil || k.pkey == nil {
		return nil, fmt.Errorf("nil keypair")
	}

	errBuf := make([]byte, 512)
	var der *C.uchar
	var derLen C.size_t
	if C.rubin_private_key_to_der(
		k.pkey,
		&der,
		&derLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	) != 0 {
		return nil, fmt.Errorf("openssl private key export failed: %s", cStringTrim0(errBuf))
	}
	defer C.rubin_free_der(der)

	return C.GoBytes(unsafe.Pointer(der), C.int(derLen)), nil
}

func cStringTrim0(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}

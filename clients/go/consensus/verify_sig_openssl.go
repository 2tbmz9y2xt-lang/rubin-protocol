//go:build cgo

package consensus

/*
#cgo pkg-config: openssl

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
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

static OSSL_PROVIDER* rubin_fips_provider = NULL;

static int rubin_set_env_if_empty(const char* key, const char* value, char* err_buf, size_t err_buf_len) {
	if (value == NULL || value[0] == '\0') {
		return 1;
	}
	const char* current = getenv(key);
	if (current != NULL && current[0] != '\0') {
		return 1;
	}
	if (setenv(key, value, 1) != 0) {
		rubin_err(err_buf, err_buf_len, "setenv failed");
		return 0;
	}
	return 1;
}

static int rubin_check_sigalg(const char* alg, const char* props, char* err_buf, size_t err_buf_len) {
	EVP_SIGNATURE* sig = EVP_SIGNATURE_fetch(NULL, alg, props);
	if (sig == NULL) {
		rubin_err(err_buf, err_buf_len, "EVP_SIGNATURE_fetch failed");
		return 0;
	}
	EVP_SIGNATURE_free(sig);
	return 1;
}

// Returns:
//  1  -> bootstrap success
// -1  -> bootstrap failure (err_buf populated)
static int rubin_openssl_bootstrap(
	int require_fips,
	const char* rubin_conf,
	const char* rubin_modules,
	char* err_buf,
	size_t err_buf_len
) {
	ERR_clear_error();

	if (!rubin_set_env_if_empty("OPENSSL_CONF", rubin_conf, err_buf, err_buf_len)) {
		return -1;
	}
	if (!rubin_set_env_if_empty("OPENSSL_MODULES", rubin_modules, err_buf, err_buf_len)) {
		return -1;
	}

	if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) != 1) {
		rubin_err(err_buf, err_buf_len, "OPENSSL_init_crypto failed");
		return -1;
	}

	if (!require_fips) {
		return 1;
	}

	if (rubin_fips_provider == NULL) {
		rubin_fips_provider = OSSL_PROVIDER_load(NULL, "fips");
		if (rubin_fips_provider == NULL) {
			rubin_err(err_buf, err_buf_len, "OSSL_PROVIDER_load(fips) failed");
			return -1;
		}
	}

	if (EVP_set_default_properties(NULL, "fips=yes") != 1) {
		rubin_err(err_buf, err_buf_len, "EVP_set_default_properties(fips=yes) failed");
		return -1;
	}

	if (!rubin_check_sigalg("ML-DSA-87", "provider=fips", err_buf, err_buf_len)) {
		return -1;
	}
	if (!rubin_check_sigalg("SLH-DSA-SHAKE-256f", "provider=fips", err_buf, err_buf_len)) {
		return -1;
	}
	return 1;
}

// Returns:
//  1  -> signature valid
//  0  -> signature invalid
// -1  -> internal error (err_buf populated)
//
// NOTE: Some PQC signature implementations in OpenSSL do not support the
// EVP_PKEY_{sign,verify}_message_update streaming API. For those, the one-shot
// EVP_DigestVerify() path works (treating msg as raw bytes, mdname=NULL).
static int rubin_verify_sig_oneshot(
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
	"os"
	"strings"
	"sync"
	"unsafe"
)

var (
	opensslBootstrapOnce      sync.Once
	opensslBootstrapErr       error
	opensslVerifySigOneShotFn = opensslVerifySigOneShot
)

func resetOpenSSLBootstrapStateForTests() {
	opensslBootstrapOnce = sync.Once{}
	opensslBootstrapErr = nil
}

func ensureOpenSSLBootstrap() error {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("RUBIN_OPENSSL_FIPS_MODE")))
	switch mode {
	case "", "off":
		return nil
	case "ready", "only":
	default:
		return txerr(TX_ERR_PARSE, "openssl bootstrap: invalid RUBIN_OPENSSL_FIPS_MODE")
	}

	requireFIPS := mode == "only"
	rubinConf := strings.TrimSpace(os.Getenv("RUBIN_OPENSSL_CONF"))
	rubinModules := strings.TrimSpace(os.Getenv("RUBIN_OPENSSL_MODULES"))

	opensslBootstrapOnce.Do(func() {
		if err := opensslBootstrap(requireFIPS, rubinConf, rubinModules); err != nil {
			opensslBootstrapErr = txerr(TX_ERR_PARSE, fmt.Sprintf("openssl bootstrap: %v", err))
		}
	})
	return opensslBootstrapErr
}

func opensslBootstrap(requireFIPS bool, rubinConf string, rubinModules string) error {
	var cConf *C.char
	var cModules *C.char
	if rubinConf != "" {
		cConf = C.CString(rubinConf)
		defer C.free(unsafe.Pointer(cConf))
	}
	if rubinModules != "" {
		cModules = C.CString(rubinModules)
		defer C.free(unsafe.Pointer(cModules))
	}

	errBuf := make([]byte, 512)
	required := C.int(0)
	if requireFIPS {
		required = 1
	}

	rc := C.rubin_openssl_bootstrap(
		required,
		cConf,
		cModules,
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	)
	if int(rc) == 1 {
		return nil
	}
	n := 0
	for n < len(errBuf) && errBuf[n] != 0 {
		n++
	}
	if n == 0 {
		return fmt.Errorf("unknown bootstrap failure")
	}
	return fmt.Errorf("%s", string(errBuf[:n]))
}

func opensslVerifySigOneShot(alg string, pubkey []byte, signature []byte, msg []byte) (bool, error) {
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
	rc := C.rubin_verify_sig_oneshot(
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
	verifyWithMapping := func(alg string) (bool, error) {
		ok, err := opensslVerifySigOneShotFn(alg, pubkey, signature, digest32[:])
		if err != nil {
			return false, txerr(TX_ERR_SIG_INVALID, "verify_sig: EVP_DigestVerify internal error")
		}
		return ok, nil
	}

	switch suiteID {
	case SUITE_ID_ML_DSA_87:
		if err := ensureOpenSSLBootstrap(); err != nil {
			return false, err
		}
		if len(pubkey) != ML_DSA_87_PUBKEY_BYTES || len(signature) != ML_DSA_87_SIG_BYTES {
			return false, nil
		}
		return verifyWithMapping("ML-DSA-87")
	case SUITE_ID_SLH_DSA_SHAKE_256F:
		if err := ensureOpenSSLBootstrap(); err != nil {
			return false, err
		}
		if len(pubkey) != SLH_DSA_SHAKE_256F_PUBKEY_BYTES || len(signature) == 0 || len(signature) > MAX_SLH_DSA_SIG_BYTES {
			return false, nil
		}
		return verifyWithMapping("SLH-DSA-SHAKE-256f")
	default:
		return false, txerr(TX_ERR_SIG_ALG_INVALID, "verify_sig: unsupported suite_id")
	}
}

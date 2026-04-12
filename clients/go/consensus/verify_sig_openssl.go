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
	return 1;
}

static int rubin_openssl_consensus_init(char* err_buf, size_t err_buf_len) {
	ERR_clear_error();

	if (OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL) != 1) {
		rubin_err(err_buf, err_buf_len, "OPENSSL_init_crypto failed");
		return -1;
	}

	if (!rubin_check_sigalg("ML-DSA-87", NULL, err_buf, err_buf_len)) {
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
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"
)

// Package-level OpenSSL function pointers. The *Fn variants are test hooks
// that tests can swap to substitute mock implementations of the CGO-backed
// verify/bootstrap/init entry points.
//
// These hooks are DELIBERATELY not guarded by a mutex. In production they
// are expected to remain immutable after package initialization, so
// concurrent reads of their values are safe under the Go memory model.
// Tests that reassign them MUST NOT run concurrently with code that reads
// them — in particular, such tests must not call t.Parallel() and must not
// kick off background goroutines that hit the hook while the assignment
// is live, because concurrent assignment + read is a data race.
//
// The sync.Once values below serialize the ensureOpenSSLBootstrap and
// ensureOpenSSLConsensusInit bootstrap paths, but they do NOT cover every
// hook read: opensslVerifySigOneShotFn is read on every verifySig call
// through verifySigWithBinding, outside any sync.Once guard. If concurrent
// hook swapping ever becomes necessary (e.g. to let a t.Parallel() test
// swap backends mid-run), convert all three hooks to sync/atomic.Pointer
// at the same time so every call site loads them through the same safe
// primitive.
var (
	opensslBootstrapOnce       sync.Once
	opensslBootstrapErr        error
	opensslConsensusInitOnce   sync.Once
	opensslConsensusInitErr    error
	defaultRuntimeRegistryOnce sync.Once
	defaultRuntimeRegistry     *SuiteRegistry
	opensslVerifySigOneShotFn  = opensslVerifySigOneShot
	opensslBootstrapFn         = opensslBootstrap
	opensslConsensusInitFn     = opensslConsensusInit
)

func defaultRuntimeSuiteRegistry() *SuiteRegistry {
	defaultRuntimeRegistryOnce.Do(func() {
		defaultRuntimeRegistry = DefaultSuiteRegistry()
	})
	return defaultRuntimeRegistry
}

// ensureOpenSSLConsensusInit performs bare OpenSSL initialization for the consensus
// verification path. It does NOT read any RUBIN_OPENSSL_* environment variables,
// does NOT load the FIPS provider, and does NOT set fips=yes default properties.
//
// This ensures that consensus signature verification is deterministic across all
// nodes regardless of host environment configuration. Two nodes with different
// RUBIN_OPENSSL_FIPS_MODE settings will produce identical verification results.
//
// Non-consensus callers (key generation, signing, CLI tools) should continue to
// use ensureOpenSSLBootstrap() which honors operator-configured FIPS settings.
func ensureOpenSSLConsensusInit() error {
	opensslConsensusInitOnce.Do(func() {
		if err := opensslConsensusInitFn(); err != nil {
			opensslConsensusInitErr = txerr(TX_ERR_PARSE, fmt.Sprintf("openssl consensus init: %v", err))
		}
	})
	return opensslConsensusInitErr
}

// ensureOpenSSLBootstrap reads RUBIN_OPENSSL_* process environment once and caches the
// bootstrap result for the lifetime of the process.
//
// This is intentional for production: OpenSSL/FIPS provider selection is treated as
// process-start configuration, not a per-call runtime knob. If bootstrap fails after
// those env vars are misconfigured, the recovery path is process restart. Test code may
// use resetOpenSSLBootstrapStateForTests to re-arm the bootstrap between isolated cases.
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
		if err := opensslBootstrapFn(requireFIPS, rubinConf, rubinModules); err != nil {
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
	return parseOpenSSLErrorBuffer(errBuf, "unknown bootstrap failure")
}

func opensslConsensusInit() error {
	errBuf := make([]byte, 512)
	rc := C.rubin_openssl_consensus_init(
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	)
	if int(rc) == 1 {
		return nil
	}
	return parseOpenSSLErrorBuffer(errBuf, "unknown consensus init failure")
}

func parseOpenSSLErrorBuffer(errBuf []byte, fallback string) error {
	n := 0
	for n < len(errBuf) && errBuf[n] != 0 {
		n++
	}
	if n == 0 {
		return fmt.Errorf("%s", fallback)
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

// verifySig is the legacy single-suite dispatcher kept alongside the
// registry-aware verifySigWithRegistry. It is retained because both the test
// suite and the in-package SigCheckQueue fast path still call it directly
// for the hardcoded ML-DSA-87 case; production block validation always goes
// through verifySigWithRegistry. Do not use this function from new code that
// can see a SuiteRegistry — prefer verifySigWithRegistry for rotation-aware
// verification.
func verifySig(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
	switch suiteID {
	case SUITE_ID_ML_DSA_87:
		if err := ensureOpenSSLConsensusInit(); err != nil {
			return false, err
		}
		binding, err := resolveSuiteVerifierBinding(
			"ML-DSA-87",
			ML_DSA_87_PUBKEY_BYTES,
			ML_DSA_87_SIG_BYTES,
		)
		if err != nil {
			return false, wrapResolveSuiteVerifierBindingError(suiteID, err)
		}
		return verifySigWithBinding(binding, pubkey, signature, digest32)
	default:
		return false, txerr(TX_ERR_SIG_ALG_INVALID,
			fmt.Sprintf("verify_sig: unsupported suite_id=0x%02x", suiteID))
	}
}

type suiteVerifierBindingKind uint8

const (
	suiteVerifierBindingOpenSSLDigest32V1 suiteVerifierBindingKind = iota + 1
)

type suiteVerifierBinding struct {
	kind       suiteVerifierBindingKind
	opensslAlg string
	pubkeyLen  int
	sigLen     int
}

func resolveSuiteVerifierBindingUnsupportedError(algName string, pubkeyLen int, sigLen int) error {
	return txerr(
		TX_ERR_SIG_ALG_INVALID,
		fmt.Sprintf(
			"resolveSuiteVerifierBinding: unsupported alg=%q pubkey_len=%d sig_len=%d",
			algName,
			pubkeyLen,
			sigLen,
		),
	)
}

func resolveSuiteVerifierBindingPolicyInvalidError(algName string, pubkeyLen int, sigLen int, err error) error {
	return txerr(
		TX_ERR_SIG_ALG_INVALID,
		fmt.Sprintf(
			"resolveSuiteVerifierBinding: live binding policy invalid alg=%q pubkey_len=%d sig_len=%d: %v",
			algName,
			pubkeyLen,
			sigLen,
			err,
		),
	)
}

func wrapResolveSuiteVerifierBindingError(suiteID uint8, err error) error {
	var txErr *TxError
	if errors.As(err, &txErr) {
		return txerr(
			txErr.Code,
			fmt.Sprintf("resolveSuiteVerifierBinding: suite_id=0x%02x %s", suiteID, txErr.Msg),
		)
	}
	return txerr(
		TX_ERR_SIG_ALG_INVALID,
		fmt.Sprintf("resolveSuiteVerifierBinding: suite_id=0x%02x %v", suiteID, err),
	)
}

// v1 keeps the current live verifier contract pinned to the canonical
// ML-DSA-87/OpenSSL-digest32 tuple from the shared live binding artifact.
// Suite admission happens before this helper via verifySig's legacy switch or
// runtimeSuiteParamsForVerification. This helper intentionally does not bring
// back a second hardcoded live-policy switch: the artifact remains the live
// authority, and only callers that advertise the exact canonical tuple can
// reuse the legacy v1 verifier path.
func resolveSuiteVerifierBinding(algName string, pubkeyLen int, sigLen int) (suiteVerifierBinding, error) {
	entry, err := liveBindingPolicyRuntimeEntry(algName, pubkeyLen, sigLen)
	if err != nil {
		var miss liveBindingPolicyRuntimeEntryNotFoundError
		if errors.As(err, &miss) {
			return suiteVerifierBinding{}, resolveSuiteVerifierBindingUnsupportedError(algName, pubkeyLen, sigLen)
		}
		return suiteVerifierBinding{}, resolveSuiteVerifierBindingPolicyInvalidError(algName, pubkeyLen, sigLen, err)
	}
	switch entry.RuntimeBinding {
	case liveBindingPolicyRuntimeOpenSSLDigest32:
		if entry.AlgName != "ML-DSA-87" ||
			entry.OpenSSLAlg != "ML-DSA-87" ||
			entry.PubkeyLen != ML_DSA_87_PUBKEY_BYTES ||
			entry.SigLen != ML_DSA_87_SIG_BYTES {
			return suiteVerifierBinding{}, resolveSuiteVerifierBindingUnsupportedError(algName, pubkeyLen, sigLen)
		}
		return suiteVerifierBinding{
			kind:       suiteVerifierBindingOpenSSLDigest32V1,
			opensslAlg: "ML-DSA-87",
			pubkeyLen:  ML_DSA_87_PUBKEY_BYTES,
			sigLen:     ML_DSA_87_SIG_BYTES,
		}, nil
	}
	return suiteVerifierBinding{}, resolveSuiteVerifierBindingUnsupportedError(algName, pubkeyLen, sigLen)
}

func verifySigWithBinding(binding suiteVerifierBinding, pubkey []byte, signature []byte, digest32 [32]byte) (bool, error) {
	if len(pubkey) != binding.pubkeyLen || len(signature) != binding.sigLen {
		return false, nil
	}
	switch binding.kind {
	case suiteVerifierBindingOpenSSLDigest32V1:
		ok, err := opensslVerifySigOneShotFn(binding.opensslAlg, pubkey, signature, digest32[:])
		if err != nil {
			return false, txerr(TX_ERR_SIG_INVALID, "verify_sig: EVP_DigestVerify internal error")
		}
		return ok, nil
	default:
		return false, txerr(TX_ERR_SIG_ALG_INVALID,
			fmt.Sprintf("verifySigWithBinding: unsupported binding kind=%d alg=%q",
				binding.kind, binding.opensslAlg))
	}
}

var defaultRuntimeSuiteRegistryForVerification = defaultRuntimeSuiteRegistry

func runtimeVerificationRegistry(registry *SuiteRegistry) (*SuiteRegistry, error) {
	if registry != nil {
		return registry, nil
	}
	registry = defaultRuntimeSuiteRegistryForVerification()
	if !registry.IsCanonicalDefaultLiveManifest() {
		return nil, txerr(TX_ERR_SIG_ALG_INVALID, "verify_sig: default runtime registry drift")
	}
	return registry, nil
}

func runtimeSuiteParamsForVerification(suiteID uint8, registry *SuiteRegistry) (SuiteParams, error) {
	registry, err := runtimeVerificationRegistry(registry)
	if err != nil {
		return SuiteParams{}, err
	}
	params, ok := registry.Lookup(suiteID)
	if !ok {
		return SuiteParams{}, txerr(TX_ERR_SIG_ALG_INVALID, "verify_sig: unsupported suite_id")
	}
	return params, nil
}

// verifySigWithRegistry dispatches signature verification using the suite
// registry for suite lookup instead of hardcoded suite_id → algorithm mapping.
// A nil registry means "use the canonical default live manifest registry", not
// "silently switch to a separate legacy verifier path". The canonical nil path
// also fail-closes if the cached default registry drifts away from the current
// single-suite ML-DSA-87 live manifest contract.
//
// The registry no longer gets to select the verifier backend implicitly through
// AlgName alone. Runtime verification resolves an explicit v1 binding from
// the suite parameters so existing suites cannot switch backend silently.
func verifySigWithRegistry(suiteID uint8, pubkey []byte, signature []byte, digest32 [32]byte, registry *SuiteRegistry) (bool, error) {
	params, err := runtimeSuiteParamsForVerification(suiteID, registry)
	if err != nil {
		return false, err
	}
	if err := ensureOpenSSLConsensusInit(); err != nil {
		return false, err
	}
	binding, err := resolveSuiteVerifierBinding(params.AlgName, params.PubkeyLen, params.SigLen)
	if err != nil {
		return false, wrapResolveSuiteVerifierBindingError(suiteID, err)
	}
	return verifySigWithBinding(binding, pubkey, signature, digest32)
}

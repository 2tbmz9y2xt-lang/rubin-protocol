//go:build cgo

package consensus

/*
#cgo pkg-config: openssl
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string.h>

// OSSL_SIGNATURE_PARAM_DETERMINISTIC is the canonical OpenSSL parameter
// name string for FIPS 204 deterministic ML-DSA signing. The macro
// itself is defined in <openssl/core_names.h> in OpenSSL >= 3.5; on
// older toolchains the underlying parameter is still understood by
// EVP_DigestSignInit_ex when passed by name. Define the literal as a
// fallback so the file builds across the OpenSSL versions present on
// supported developer machines and CI runners. If the underlying
// runtime does not understand the parameter, EVP_DigestSignInit_ex
// surfaces an error at runtime; this fallback only handles header
// macro absence at compile time. There is NO fallback to random /
// hedged signing — the deterministic helper either succeeds or
// returns an error.
#ifndef OSSL_SIGNATURE_PARAM_DETERMINISTIC
#define OSSL_SIGNATURE_PARAM_DETERMINISTIC "deterministic"
#endif

// rubin_err_sign_conformance writes a static label into the caller's
// error buffer and appends the latest queued OpenSSL error string when
// available. This mirrors rubin_err_sign in openssl_signer.go which
// includes ERR_get_error + ERR_error_string_n diagnostics; cgo treats
// each file's preamble as a separate translation unit, so we cannot
// reuse the helper from openssl_signer.go here. Inlining the same
// pattern keeps this file self-contained while preserving diagnostic
// fidelity expected by the test suite and the operator-facing error
// surface.
static void rubin_err_sign_conformance(char* err_buf, size_t err_buf_len, const char* msg) {
    if (err_buf == NULL || err_buf_len == 0) {
        return;
    }
    err_buf[0] = '\0';
    if (msg == NULL) {
        msg = "openssl conformance signing error";
    }
    size_t prefix_len = strlen(msg);
    if (prefix_len >= err_buf_len) {
        prefix_len = err_buf_len - 1;
    }
    memcpy(err_buf, msg, prefix_len);
    err_buf[prefix_len] = '\0';

    unsigned long ossl_err = ERR_get_error();
    if (ossl_err == 0) {
        return;
    }
    // Reorder bounds so all subtractions stay non-negative even when
    // err_buf_len is tiny. size_t is unsigned, so writing
    // `prefix_len >= err_buf_len - 3` would wrap on err_buf_len < 3
    // and silently take the wrong branch. Compare additions instead.
    const char* sep = ": ";
    size_t sep_len = strlen(sep);
    // Need room for: prefix + sep + at least 1 byte of error text + null.
    if (prefix_len + sep_len + 2 > err_buf_len) {
        return;
    }
    memcpy(err_buf + prefix_len, sep, sep_len);
    char* tail = err_buf + prefix_len + sep_len;
    size_t tail_cap = err_buf_len - prefix_len - sep_len;
    ERR_error_string_n(ossl_err, tail, tail_cap);
    err_buf[err_buf_len - 1] = '\0';
}

// rubin_digest_sign_oneshot_conformance_fixture mirrors rubin_digest_sign_oneshot
// but passes OSSL_SIGNATURE_PARAM_DETERMINISTIC=1 so OpenSSL ML-DSA derives
// the per-signature secret deterministically from the message and the key
// instead of mixing in fresh random bytes. This is the FIPS 204 deterministic
// signing branch and produces byte-identical signatures for the same
// (key, digest) pair across runs.
//
// CONFORMANCE FIXTURE TOOLING ONLY: do not wire from production / node /
// wallet / consensus validation paths. Production signing must use the
// hedged default (rubin_digest_sign_oneshot) so each emitted signature
// carries fresh randomness.
static int rubin_digest_sign_oneshot_conformance_fixture(
    EVP_PKEY* pkey,
    const unsigned char* msg, size_t msg_len,
    unsigned char* sig_out, size_t sig_cap, size_t* sig_len,
    char* err_buf, size_t err_buf_len) {
    ERR_clear_error();
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        rubin_err_sign_conformance(err_buf, err_buf_len, "EVP_MD_CTX_new failed");
        return -1;
    }
    int deterministic = 1;
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_DigestSignInit_ex(mctx, NULL, NULL, NULL, NULL, pkey, params) <= 0) {
        EVP_MD_CTX_free(mctx);
        rubin_err_sign_conformance(err_buf, err_buf_len, "EVP_DigestSignInit_ex(deterministic) failed");
        return -1;
    }
    size_t n = sig_cap;
    if (EVP_DigestSign(mctx, sig_out, &n, msg, msg_len) <= 0) {
        EVP_MD_CTX_free(mctx);
        rubin_err_sign_conformance(err_buf, err_buf_len, "EVP_DigestSign(deterministic) failed");
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

// SignDigest32ForConformanceFixture signs a 32-byte message digest using
// ML-DSA-87 in FIPS 204 deterministic mode. Unlike the default hedged
// SignDigest32, two calls with the same keypair and the same digest
// produce byte-identical signatures.
//
// PACKAGE CONTRACT — CONFORMANCE FIXTURE TOOLING ONLY:
//   - This API exists so clients/go/cmd/gen-conformance-fixtures can
//     produce byte-reproducible signatures for committed conformance
//     test fixtures (Q-CONF-FIXTURE-GENERATOR-DETERMINISM-01).
//   - Production / node / wallet / consensus signing paths must use
//     SignDigest32, which preserves OpenSSL's hedged ML-DSA default.
//   - Verification semantics are unchanged. Signatures produced by this
//     function are accepted by the same verification path as hedged
//     signatures; only the signer-side per-signature randomness is
//     replaced with deterministic derivation.
//   - The conformance-only caller boundary is enforced by a sibling
//     package test (TestSignDigest32ForConformanceFixture_ConformanceOnlyCallerGuard)
//     that walks the clients/go tree and AST-scans every .go file
//     (production AND test) for *ast.Ident references to this symbol,
//     rejecting any reference outside an explicit allowlist: the
//     declaration file itself, the matching test file, and the
//     clients/go/cmd/gen-conformance-fixtures/ tree.
func (k *MLDSA87Keypair) SignDigest32ForConformanceFixture(digest [32]byte) ([]byte, error) {
	if k == nil || k.pkey == nil {
		return nil, fmt.Errorf("SignDigest32ForConformanceFixture: nil keypair")
	}
	// Re-validate OpenSSL bootstrap on every call. Mirrors the
	// production signOpenSSLDigest32 path in openssl_signer.go: the
	// keypair constructors ensure bootstrap once at construction
	// time, but tests can re-arm via resetOpenSSLBootstrapStateForTests
	// between construction and signing, and a per-call gate is the
	// only place that revalidates RUBIN_OPENSSL_FIPS_MODE for the
	// caller's current process state.
	if err := ensureOpenSSLBootstrap(); err != nil {
		return nil, err
	}
	errBuf := newOpenSSLErrorBuffer()
	sig := make([]byte, ML_DSA_87_SIG_BYTES)
	var sigLen C.size_t

	ret := C.rubin_digest_sign_oneshot_conformance_fixture(
		k.pkey,
		(*C.uchar)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest)),
		(*C.uchar)(unsafe.Pointer(&sig[0])),
		C.size_t(ML_DSA_87_SIG_BYTES),
		&sigLen,
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	)
	runtime.KeepAlive(k)
	validateErr := validateConformanceSignResult(int(ret), int(sigLen), errBuf)
	if validateErr != nil {
		return nil, validateErr
	}
	return sig[:int(sigLen)], nil
}

// validateConformanceSignResult inspects the return code, signature
// length, and OpenSSL error buffer produced by
// rubin_digest_sign_oneshot_conformance_fixture and returns a wrapped
// fmt.Errorf when either contract is violated. (No typed/sentinel
// error type — callers match by string contains in tests.) Extracted
// from SignDigest32ForConformanceFixture so the two defensive crypto
// branches (rc != 0, length mismatch) — which cannot be triggered
// from the public Sign entrypoint without a working OpenSSL fault
// injector — are still unit-test-reachable through this helper.
//
// Contract:
//   - ret == 0 AND sigLen == ML_DSA_87_SIG_BYTES → nil (success).
//   - ret != 0 → wrapped error carrying the OpenSSL error queue text
//     copied into errBuf by rubin_err_sign_conformance.
//   - ret == 0 AND sigLen != ML_DSA_87_SIG_BYTES → wrapped error
//     reporting actual vs expected length. Mirrors the production
//     SignDigest32 contract so a degenerate runtime that returns a
//     shorter signature surfaces loudly instead of silently emitting
//     truncated bytes downstream.
//
// errBuf is read only when ret != 0 — the rubin_err_sign_conformance
// helper already null-terminates and bounds the buffer, so
// cStringTrim0 is safe even on a partially populated buffer.
func validateConformanceSignResult(ret int, sigLen int, errBuf []byte) error {
	if ret != 0 {
		return fmt.Errorf("SignDigest32ForConformanceFixture: %s", cStringTrim0(errBuf))
	}
	if sigLen != ML_DSA_87_SIG_BYTES {
		return fmt.Errorf(
			"SignDigest32ForConformanceFixture: unexpected signature length %d, want %d",
			sigLen, ML_DSA_87_SIG_BYTES,
		)
	}
	return nil
}

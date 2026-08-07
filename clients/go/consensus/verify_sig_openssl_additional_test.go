//go:build cgo

package consensus

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestVerifySig_UnsupportedSuiteReturnsError(t *testing.T) {
	var d [32]byte
	_, err := verifySig(0xff, []byte{0x01}, []byte{0x02}, d)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
}

func TestOpenSSLVerifySig_EmptyInputsReturnErrors(t *testing.T) {
	var d [32]byte
	_, err := opensslVerifySigOneShot("", []byte{0x01}, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty alg")
	}
	_, err = opensslVerifySigOneShot("ML-DSA-87", nil, []byte{0x02}, d[:])
	if err == nil {
		t.Fatalf("expected error for empty pubkey")
	}
	_, err = opensslVerifySigOneShot("ML-DSA-87", []byte{0x01}, nil, d[:])
	if err == nil {
		t.Fatalf("expected error for empty signature")
	}
	_, err = opensslVerifySigOneShot("ML-DSA-87", []byte{0x01}, []byte{0x02}, nil)
	if err == nil {
		t.Fatalf("expected error for empty message")
	}
}

func TestOpenSSL_MLDSA87_VerifyWrongMessageReturnsFalse(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var msg [32]byte
	msg[0] = 0x42
	sig, err := kp.SignDigest32(msg)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	msg[0] ^= 0x01
	ok, err := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, msg)
	if err != nil {
		t.Fatalf("verifySig err: %v", err)
	}
	if ok {
		t.Fatalf("verifySig=true for wrong message")
	}
}

func TestVerifyMLDSA87Digest32UsesNativeBackend(t *testing.T) {
	kp := mustMLDSA87Keypair(t)

	var digest [32]byte
	digest[0] = 0x5a
	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	ok, err := VerifyMLDSA87Digest32(kp.PubkeyBytes(), sig, digest)
	if err != nil {
		t.Fatalf("VerifyMLDSA87Digest32 valid: %v", err)
	}
	if !ok {
		t.Fatal("VerifyMLDSA87Digest32=false for valid signature")
	}

	digest[0] ^= 0xff
	ok, err = VerifyMLDSA87Digest32(kp.PubkeyBytes(), sig, digest)
	if err != nil {
		t.Fatalf("VerifyMLDSA87Digest32 wrong digest: %v", err)
	}
	if ok {
		t.Fatal("VerifyMLDSA87Digest32=true for wrong digest")
	}

	ok, err = VerifyMLDSA87Digest32(make([]byte, ML_DSA_87_PUBKEY_BYTES-1), make([]byte, ML_DSA_87_SIG_BYTES), digest)
	if err != nil {
		t.Fatalf("VerifyMLDSA87Digest32 length mismatch: %v", err)
	}
	if ok {
		t.Fatal("VerifyMLDSA87Digest32=true for length mismatch")
	}
}

func TestOpenSSLVerifySig_UnknownAlgErrors(t *testing.T) {
	var d [32]byte
	ok, err := opensslVerifySigOneShot("NO_SUCH_ALG", []byte{0x01}, []byte{0x02}, d[:])
	if err == nil || ok {
		t.Fatalf("expected error for unknown alg")
	}
}

func TestVerifySig_OpenSSLBackendErrorMapsToSigInvalid(t *testing.T) {
	kp := mustMLDSA87Keypair(t)
	var digest [32]byte
	digest[0] = 0x5a

	sig, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	orig := opensslVerifySigOneShotFn
	opensslVerifySigOneShotFn = func(_ string, _ []byte, _ []byte, _ []byte) (bool, error) {
		return false, fmt.Errorf("forced backend failure")
	}
	defer func() { opensslVerifySigOneShotFn = orig }()

	_, verifyErr := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), sig, digest)
	if verifyErr == nil {
		t.Fatalf("expected verifySig error")
	}
	if got := mustTxErrCode(t, verifyErr); got != TX_ERR_SIG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_INVALID)
	}
}

func TestDefaultRuntimeSuiteRegistry_CachesSharedInstance(t *testing.T) {
	first := defaultRuntimeSuiteRegistry()
	second := defaultRuntimeSuiteRegistry()
	if first == nil || second == nil {
		t.Fatalf("expected cached runtime registry")
	}
	if first != second {
		t.Fatalf("expected shared cached runtime registry instance")
	}
}

func TestDefaultRuntimeSuiteRegistry_IsCanonicalDefaultLiveManifest(t *testing.T) {
	reg := defaultRuntimeSuiteRegistry()
	if !reg.IsCanonicalDefaultLiveManifest() {
		t.Fatalf("default runtime registry must stay pinned to the canonical live ML-DSA-87 manifest")
	}
}

func TestResolveSuiteVerifierBinding_LivePolicyPinsCanonicalLegacyV1Binding(t *testing.T) {
	entry, err := liveBindingPolicyRuntimeEntry("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("liveBindingPolicyRuntimeEntry: %v", err)
	}
	if entry.RuntimeBinding != liveBindingPolicyRuntimeOpenSSLDigest32 {
		t.Fatalf("runtime_binding=%q, want %q", entry.RuntimeBinding, liveBindingPolicyRuntimeOpenSSLDigest32)
	}
	if entry.AlgName != "ML-DSA-87" {
		t.Fatalf("alg_name=%q, want %q", entry.AlgName, "ML-DSA-87")
	}
	if entry.OpenSSLAlg != "ML-DSA-87" {
		t.Fatalf("openssl_alg=%q, want %q", entry.OpenSSLAlg, "ML-DSA-87")
	}

	binding, err := resolveSuiteVerifierBinding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err != nil {
		t.Fatalf("resolveSuiteVerifierBinding: %v", err)
	}
	if binding.kind != suiteVerifierBindingOpenSSLDigest32V1 {
		t.Fatalf("binding.kind=%v, want %v", binding.kind, suiteVerifierBindingOpenSSLDigest32V1)
	}
	if binding.opensslAlg != "ML-DSA-87" {
		t.Fatalf("binding.opensslAlg=%q, want %q", binding.opensslAlg, "ML-DSA-87")
	}
	if binding.pubkeyLen != ML_DSA_87_PUBKEY_BYTES {
		t.Fatalf("binding.pubkeyLen=%d, want %d", binding.pubkeyLen, ML_DSA_87_PUBKEY_BYTES)
	}
	if binding.sigLen != ML_DSA_87_SIG_BYTES {
		t.Fatalf("binding.sigLen=%d, want %d", binding.sigLen, ML_DSA_87_SIG_BYTES)
	}
}

// The next three tests pin the identifying context that was added to the
// legacy verify/resolve error paths (see rubin-protocol#1131, finding 3).
// They do not encode wire contract — the strings are not present in any
// conformance/fixtures/*.json — but they keep the richer diagnostic text
// stable so log correlation tooling can rely on the substrings.

func TestVerifySig_UnsupportedSuiteIDMessageCarriesSuiteID(t *testing.T) {
	var d [32]byte
	_, err := verifySig(0x7b, []byte{0x01}, []byte{0x02}, d)
	if err == nil {
		t.Fatalf("expected error from unsupported suite_id")
	}
	msg := err.Error()
	if !strings.Contains(msg, "verify_sig: unsupported suite_id=0x7b") {
		t.Fatalf("error should name suite_id=0x7b, got %q", msg)
	}
}

// txErrorCauseOf reads the typed cause a consensus error carries.
func txErrorCauseOf(t *testing.T, err error) TxErrorCause {
	t.Helper()
	var txErr *TxError
	if !errors.As(err, &txErr) {
		t.Fatalf("errors.As(*TxError) failed for %T: %v", err, err)
	}
	return txErr.Cause()
}

// Cause() is nil-safe exactly like Error(), and a nil receiver carries no
// meaning: a consumer that dereferences a nil *TxError must not be handed a
// local-fault classification it can act on.
func TestTxErrorCause_NilReceiverIsUnspecified(t *testing.T) {
	var nilErr *TxError
	if got := nilErr.Cause(); got != TxErrorCauseUnspecified {
		t.Fatalf("nil Cause()=%d, want TxErrorCauseUnspecified", got)
	}
}

func TestResolveSuiteVerifierBinding_UnknownCarriesAlgAndLens(t *testing.T) {
	_, err := resolveSuiteVerifierBinding("FAKE-ALG", 7, 9)
	if err == nil {
		t.Fatalf("expected error for unknown binding")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
	if got := txErrorCauseOf(t, err); got != TxErrorCauseLocalCryptoBackendFault {
		t.Fatalf("cause=%d, want TxErrorCauseLocalCryptoBackendFault", got)
	}
	msg := err.Error()
	for _, needle := range []string{
		"alg=\"FAKE-ALG\"",
		"pubkey_len=7",
		"sig_len=9",
	} {
		if !strings.Contains(msg, needle) {
			t.Fatalf("resolveSuiteVerifierBinding error missing %q, got %q", needle, msg)
		}
	}
}

func TestWrapResolveSuiteVerifierBindingError_PreservesTxErrorCodeAndSuiteID(t *testing.T) {
	err := wrapResolveSuiteVerifierBindingError(0x2a, resolveSuiteVerifierBindingUnsupportedError("FAKE-ALG", 7, 9))
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
	msg := err.Error()
	for _, needle := range []string{
		"suite_id=0x2a",
		"alg=\"FAKE-ALG\"",
		"pubkey_len=7",
		"sig_len=9",
	} {
		if !strings.Contains(msg, needle) {
			t.Fatalf("wrapped error missing %q, got %q", needle, msg)
		}
	}
	if strings.Count(msg, "resolveSuiteVerifierBinding:") != 1 {
		t.Fatalf("wrapped error should keep a single resolveSuiteVerifierBinding prefix, got %q", msg)
	}
	// The wrapper CARRIES the inner branch's cause and never erases it.
	if got := txErrorCauseOf(t, err); got != TxErrorCauseLocalCryptoBackendFault {
		t.Fatalf("wrapped cause=%d, want TxErrorCauseLocalCryptoBackendFault", got)
	}
	// ...and never INVENTS one for an inner error that selected none.
	uncaused := wrapResolveSuiteVerifierBindingError(0x2a, txerr(TX_ERR_SIG_ALG_INVALID, "no cause here"))
	if got := txErrorCauseOf(t, uncaused); got != TxErrorCauseUnspecified {
		t.Fatalf("wrapped uncaused cause=%d, want TxErrorCauseUnspecified", got)
	}
}

// Matrix row 3: a live verifier binding this node cannot resolve because of its
// OWN registry configuration keeps the existing public code and message and is
// typed LOCAL_CRYPTO_BACKEND_FAULT. The registry here is exactly what
// node.MempoolConfig.SuiteRegistry carries into consensus validation.
func TestVerifySigWithRegistryCache_LocalBindingFaultCarriesCause(t *testing.T) {
	const unboundAlg = "ML-DSA-87-NOT-LIVE-BOUND"
	registry := NewSuiteRegistryFromParams([]SuiteParams{{
		SuiteID:    SUITE_ID_ML_DSA_87,
		PubkeyLen:  ML_DSA_87_PUBKEY_BYTES,
		SigLen:     ML_DSA_87_SIG_BYTES,
		VerifyCost: VERIFY_COST_ML_DSA_87,
		AlgName:    unboundAlg,
	}})
	_, err := verifySigWithRegistryCache(
		SUITE_ID_ML_DSA_87,
		make([]byte, ML_DSA_87_PUBKEY_BYTES),
		make([]byte, ML_DSA_87_SIG_BYTES),
		[32]byte{},
		registry,
		nil,
	)
	wantMsg := fmt.Sprintf(
		"suite_id=0x%02x resolveSuiteVerifierBinding: unsupported alg=%q pubkey_len=%d sig_len=%d",
		SUITE_ID_ML_DSA_87, unboundAlg, ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES,
	)
	mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, wantMsg, TxErrorCauseLocalCryptoBackendFault)
}

// The local default-registry drift guard is node-local runtime state too.
func TestRuntimeVerificationRegistry_DriftCarriesCause(t *testing.T) {
	previous := defaultRuntimeSuiteRegistryForVerification
	t.Cleanup(func() { defaultRuntimeSuiteRegistryForVerification = previous })
	defaultRuntimeSuiteRegistryForVerification = func() *SuiteRegistry {
		return NewSuiteRegistryFromParams(nil)
	}

	_, err := runtimeVerificationRegistry(nil)
	mustTxErrorCause(
		t,
		err,
		TX_ERR_SIG_ALG_INVALID,
		"verify_sig: default runtime registry drift",
		TxErrorCauseLocalCryptoBackendFault,
	)
}

// Matrix row 6: a suite the CANDIDATE selected and this node does not authorize
// keeps TX_ERR_SIG_ALG_INVALID and selects NO cause, at both exits that decide
// it — verifySig's legacy switch and the registry lookup.
func TestUnauthorizedCandidateSuiteCarriesNoLocalCause(t *testing.T) {
	var digest [32]byte
	_, err := verifySig(0x7b, []byte{0x01}, []byte{0x02}, digest)
	mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, "verify_sig: unsupported suite_id=0x7b", TxErrorCauseUnspecified)

	_, err = verifySigWithRegistryCache(
		SUITE_ID_ML_DSA_87,
		make([]byte, ML_DSA_87_PUBKEY_BYTES),
		make([]byte, ML_DSA_87_SIG_BYTES),
		digest,
		NewSuiteRegistryFromParams(nil),
		nil,
	)
	mustTxErrorCause(t, err, TX_ERR_SIG_ALG_INVALID, "verify_sig: unsupported suite_id", TxErrorCauseUnspecified)
}

func TestResolveSuiteVerifierBinding_InvalidPolicyReturnsTxError(t *testing.T) {
	forcedErr := errors.New("forced live binding policy failure")
	forceLiveBindingPolicyStateForTest(t, nil, forcedErr)

	_, err := resolveSuiteVerifierBinding("ML-DSA-87", ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES)
	if err == nil {
		t.Fatal("expected invalid policy error")
	}
	if got := mustTxErrCode(t, err); got != TX_ERR_SIG_ALG_INVALID {
		t.Fatalf("code=%s, want %s", got, TX_ERR_SIG_ALG_INVALID)
	}
	msg := err.Error()
	for _, needle := range []string{
		"live binding policy invalid",
		"alg=\"ML-DSA-87\"",
		fmt.Sprintf("pubkey_len=%d", ML_DSA_87_PUBKEY_BYTES),
		fmt.Sprintf("sig_len=%d", ML_DSA_87_SIG_BYTES),
		"forced live binding policy failure",
	} {
		if !strings.Contains(msg, needle) {
			t.Fatalf("invalid policy error missing %q, got %q", needle, msg)
		}
	}
	if got := txErrorCauseOf(t, err); got != TxErrorCauseLocalCryptoBackendFault {
		t.Fatalf("invalid policy cause=%d, want TxErrorCauseLocalCryptoBackendFault", got)
	}
}

func TestVerifySigWithBinding_UnknownKindCarriesContext(t *testing.T) {
	// Construct a binding with an unknown kind sentinel and matching lengths
	// so the length guard passes and the switch falls through to default.
	const unknownKind suiteVerifierBindingKind = 0xFE
	binding := suiteVerifierBinding{
		kind:       unknownKind,
		opensslAlg: "SENTINEL-ALG",
		pubkeyLen:  3,
		sigLen:     5,
	}
	_, err := verifySigWithBinding(binding, []byte{0, 0, 0}, []byte{0, 0, 0, 0, 0}, [32]byte{})
	if err == nil {
		t.Fatalf("expected error for unknown binding kind")
	}
	msg := err.Error()
	for _, needle := range []string{
		"verifySigWithBinding",
		"kind=254",
		"alg=\"SENTINEL-ALG\"",
	} {
		if !strings.Contains(msg, needle) {
			t.Fatalf("verifySigWithBinding error missing %q, got %q", needle, msg)
		}
	}
	if got := txErrorCauseOf(t, err); got != TxErrorCauseLocalCryptoBackendFault {
		t.Fatalf("unknown binding kind cause=%d, want TxErrorCauseLocalCryptoBackendFault", got)
	}
}

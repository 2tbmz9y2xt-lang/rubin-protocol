//go:build cgo

package consensus

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// localFaultFixture is one signed single-input CORE_P2PK transaction plus the
// utxo set it spends, built while the backend is HEALTHY so every row below
// differs from the accepting baseline only in the fault it injects.
type localFaultFixture struct {
	txBytes []byte
	utxos   map[Outpoint]UtxoEntry
	chainID [32]byte
}

func newLocalFaultFixture(t *testing.T) localFaultFixture {
	t.Helper()
	kp := mustMLDSA87Keypair(t)
	covData := P2PKCovenantDataForPubkey(kp.PubkeyBytes())
	var prevTxid [32]byte
	prevTxid[0] = 0xAA
	op := Outpoint{Txid: prevTxid, Vout: 0}
	utxos := map[Outpoint]UtxoEntry{op: {
		Value:             100_000_000,
		CovenantType:      COV_TYPE_P2PK,
		CovenantData:      covData,
		CreationHeight:    1,
		CreatedByCoinbase: true,
	}}
	tx := &Tx{
		Version:  1,
		TxNonce:  1,
		Locktime: 0,
		Inputs:   []TxInput{{PrevTxid: prevTxid, PrevVout: 0, Sequence: 0x7FFFFFFF}},
		Outputs:  []TxOutput{{Value: 90_000_000, CovenantType: COV_TYPE_P2PK, CovenantData: covData}},
	}
	var chainID [32]byte
	chainID[0] = 0x88
	if err := SignTransaction(tx, utxos, chainID, kp); err != nil {
		t.Fatalf("SignTransaction: %v", err)
	}
	txBytes, err := MarshalTx(tx)
	if err != nil {
		t.Fatalf("MarshalTx: %v", err)
	}
	return localFaultFixture{txBytes: txBytes, utxos: utxos, chainID: chainID}
}

// check drives the LIVE consensus validation entry point over the fixture.
func (f localFaultFixture) check(chainID [32]byte) error {
	_, err := CheckTransaction(f.txBytes, f.utxos, 200, 0, chainID)
	return err
}

// mustTxErrorCause pins the whole public surface of a consensus error together
// with the typed cause its producing branch selected: the code, the exact
// message bytes, the exact Error() rendering, and that errors.As to *TxError
// still resolves.
func mustTxErrorCause(t *testing.T, err error, wantCode ErrorCode, wantMsg string, wantCause TxErrorCause) {
	t.Helper()
	var txErr *TxError
	if !errors.As(err, &txErr) {
		t.Fatalf("errors.As(*TxError) failed for %T: %v", err, err)
	}
	if txErr.Code != wantCode {
		t.Fatalf("Code=%s, want %s", txErr.Code, wantCode)
	}
	if txErr.Msg != wantMsg {
		t.Fatalf("Msg=%q, want %q", txErr.Msg, wantMsg)
	}
	if want := string(wantCode) + ": " + wantMsg; txErr.Error() != want {
		t.Fatalf("Error()=%q, want %q", txErr.Error(), want)
	}
	if txErr.Cause() != wantCause {
		t.Fatalf("Cause()=%d, want %d", txErr.Cause(), wantCause)
	}
}

// Matrix row 1: an OpenSSL consensus INIT failure keeps TX_ERR_PARSE and its
// exact message, and is typed LOCAL_CRYPTO_BACKEND_FAULT at the branch that
// latched it.
func TestConsensusValidation_OpenSSLInitFaultCarriesLocalCryptoBackendFaultCause(t *testing.T) {
	fixture := newLocalFaultFixture(t)

	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)
	opensslConsensusInitFn = func() error {
		return errors.New("synthetic consensus init failure")
	}

	mustTxErrorCause(
		t,
		fixture.check(fixture.chainID),
		TX_ERR_PARSE,
		"openssl consensus init: synthetic consensus init failure",
		TxErrorCauseLocalCryptoBackendFault,
	)
}

// Matrix row 2: the one-shot verifier returning an INTERNAL error keeps
// TX_ERR_SIG_INVALID and its exact message, typed LOCAL_CRYPTO_BACKEND_FAULT.
func TestConsensusValidation_OpenSSLOneShotFaultCarriesLocalCryptoBackendFaultCause(t *testing.T) {
	fixture := newLocalFaultFixture(t)

	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)
	t.Cleanup(func() { opensslVerifySigOneShotFn = opensslVerifySigOneShot })
	opensslVerifySigOneShotFn = func(string, []byte, []byte, []byte) (bool, error) {
		return false, errors.New("synthetic EVP_DigestVerify failure")
	}

	mustTxErrorCause(
		t,
		fixture.check(fixture.chainID),
		TX_ERR_SIG_INVALID,
		"verify_sig: EVP_DigestVerify internal error",
		TxErrorCauseLocalCryptoBackendFault,
	)
}

// Matrix rows 4 and 5 at the SOURCE: with a healthy backend a
// cryptographically invalid signature and a structurally malformed candidate
// keep their public errors and select NO cause, so no consumer can mistake
// them for a local fault.
func TestConsensusValidation_HealthyBackendCandidateFailuresCarryNoCause(t *testing.T) {
	fixture := newLocalFaultFixture(t)

	// Signed against fixture.chainID, validated against a different chain id:
	// the sighash digest differs, so the backend decides "invalid" with no
	// error of its own.
	var otherChainID [32]byte
	otherChainID[0] = 0x99
	mustTxErrorCause(
		t,
		fixture.check(otherChainID),
		TX_ERR_SIG_INVALID,
		"CORE_P2PK signature invalid",
		TxErrorCauseUnspecified,
	)

	_, err := CheckTransaction([]byte{0xFF, 0x00, 0x13, 0x37}, fixture.utxos, 200, 0, fixture.chainID)
	var txErr *TxError
	if !errors.As(err, &txErr) {
		t.Fatalf("malformed candidate: errors.As(*TxError) failed for %T: %v", err, err)
	}
	if txErr.Code != TX_ERR_PARSE {
		t.Fatalf("malformed candidate Code=%s, want %s", txErr.Code, TX_ERR_PARSE)
	}
	if txErr.Cause() != TxErrorCauseUnspecified {
		t.Fatalf("malformed candidate Cause()=%d, want TxErrorCauseUnspecified", txErr.Cause())
	}
}

func TestEnsureOpenSSLBootstrap_ModeOffNoop(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "off")
	if err := ensureOpenSSLBootstrap(); err != nil {
		t.Fatalf("ensureOpenSSLBootstrap(off): %v", err)
	}
	if err := ensureOpenSSLBootstrap(); err != nil {
		t.Fatalf("ensureOpenSSLBootstrap(off second call): %v", err)
	}
}

func TestVerifySig_FIPSReadyModeValid(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	kp := mustMLDSA87Keypair(t)
	var digest [32]byte
	digest[0] = 0x51
	signature, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	// Consensus verify path ignores FIPS env — verification must still succeed
	// even when FIPS mode is set (the env only affects non-consensus bootstrap).
	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "ready")
	t.Setenv("RUBIN_OPENSSL_CONF", "")
	t.Setenv("RUBIN_OPENSSL_MODULES", "")

	ok, verifyErr := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), signature, digest)
	if verifyErr != nil {
		t.Fatalf("verifySig(ready env): %v", verifyErr)
	}
	if !ok {
		t.Fatalf("expected verifySig=true regardless of FIPS env")
	}
}

func TestVerifySig_FIPSOnlyModeValidOrSkip(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	kp := mustMLDSA87Keypair(t)
	var digest [32]byte
	digest[0] = 0x77
	signature, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	// Consensus verify path uses ensureOpenSSLConsensusInit (no FIPS),
	// so even with FIPS_MODE=only the verification must succeed.
	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "only")
	ok, verifyErr := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), signature, digest)
	if verifyErr != nil {
		t.Fatalf("verifySig(only env): %v", verifyErr)
	}
	if !ok {
		t.Fatalf("expected verifySig=true regardless of FIPS env")
	}
}

// TestEnsureOpenSSLBootstrap_FIPSOnlyOrSkip validates that the non-consensus
// bootstrap path still honors FIPS mode when explicitly requested.
func TestEnsureOpenSSLBootstrap_FIPSOnlyOrSkip(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "only")
	err := ensureOpenSSLBootstrap()
	if err != nil {
		if strings.Contains(err.Error(), "openssl bootstrap") {
			t.Skipf("FIPS provider unavailable in local env: %v", err)
		}
		t.Fatalf("ensureOpenSSLBootstrap(only): %v", err)
	}
}

func TestOpenSSLBootstrap_NonEmptyConfigArgs(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	if err := opensslBootstrap(false, "/tmp/rubin-nonexistent-openssl.cnf", "/tmp/rubin-nonexistent-ossl-modules"); err != nil {
		if strings.Contains(err.Error(), "OPENSSL_init_crypto") || strings.Contains(err.Error(), "setenv failed") {
			t.Skipf("local OpenSSL env rejected injected config/modules: %v", err)
		}
	}
}

// TestVerifySig_IgnoresInvalidFIPSMode verifies that the consensus verification
// path does NOT read RUBIN_OPENSSL_FIPS_MODE. Even an invalid mode value must
// not affect consensus signature verification — only non-consensus callers
// (ensureOpenSSLBootstrap) should reject invalid modes.
func TestVerifySig_IgnoresInvalidFIPSMode(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	kp := mustMLDSA87Keypair(t)
	var digest [32]byte
	digest[0] = 0x42
	signature, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "definitely-invalid")

	// Consensus verify path must succeed — it ignores FIPS env entirely.
	ok, verifyErr := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), signature, digest)
	if verifyErr != nil {
		t.Fatalf("consensus verifySig must ignore FIPS env, got error: %v", verifyErr)
	}
	if !ok {
		t.Fatalf("expected verifySig=true (consensus path ignores FIPS env)")
	}
}

func TestVerifySig_IgnoresInheritedOpenSSLConfig(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	kp := mustMLDSA87Keypair(t)
	var digest [32]byte
	digest[0] = 0x6a
	signature, err := kp.SignDigest32(digest)
	if err != nil {
		t.Fatalf("SignDigest32: %v", err)
	}

	t.Setenv("OPENSSL_CONF", "/tmp/rubin-consensus-invalid-openssl.cnf")
	t.Setenv("OPENSSL_MODULES", "/tmp/rubin-consensus-invalid-ossl-modules")

	ok, verifyErr := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), signature, digest)
	if verifyErr != nil {
		t.Fatalf("consensus verifySig must ignore inherited OPENSSL_* env, got: %v", verifyErr)
	}
	if !ok {
		t.Fatalf("expected verifySig=true under poisoned inherited OPENSSL_* env")
	}
}

// TestEnsureOpenSSLBootstrap_InvalidFIPSModeRejected confirms that the
// non-consensus bootstrap path still rejects invalid FIPS modes.
func TestEnsureOpenSSLBootstrap_InvalidFIPSModeRejected(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "definitely-invalid")

	err := ensureOpenSSLBootstrap()
	if err == nil {
		t.Fatalf("expected ensureOpenSSLBootstrap to reject invalid FIPS mode")
	}
	if !strings.Contains(err.Error(), "invalid RUBIN_OPENSSL_FIPS_MODE") {
		t.Fatalf("expected invalid mode context, got: %v", err)
	}
}

// TestEnsureOpenSSLConsensusInit_BootstrapError verifies that a bootstrap failure
// in the consensus init path is properly wrapped and cached.
func TestEnsureOpenSSLConsensusInit_BootstrapError(t *testing.T) {
	resetOpenSSLBootstrapStateForTests()
	t.Cleanup(resetOpenSSLBootstrapStateForTests)

	injectedErr := fmt.Errorf("synthetic openssl failure")
	opensslConsensusInitFn = func() error {
		return injectedErr
	}

	err := ensureOpenSSLConsensusInit()
	if err == nil {
		t.Fatalf("expected error from consensus init with failing bootstrap")
	}
	if !strings.Contains(err.Error(), "openssl consensus init") {
		t.Fatalf("expected wrapped error, got: %v", err)
	}

	// Second call must return same cached error.
	err2 := ensureOpenSSLConsensusInit()
	if err2 == nil || err2.Error() != err.Error() {
		t.Fatalf("expected cached error on second call, got: %v", err2)
	}
}

func TestParseOpenSSLErrorBuffer_Fallback(t *testing.T) {
	err := parseOpenSSLErrorBuffer(make([]byte, 8), "fallback text")
	if err == nil || err.Error() != "fallback text" {
		t.Fatalf("expected fallback error, got: %v", err)
	}
}

func TestParseOpenSSLErrorBuffer_Message(t *testing.T) {
	buf := append([]byte("consensus failed"), 0)
	err := parseOpenSSLErrorBuffer(buf, "fallback text")
	if err == nil || err.Error() != "consensus failed" {
		t.Fatalf("expected parsed buffer error, got: %v", err)
	}
}

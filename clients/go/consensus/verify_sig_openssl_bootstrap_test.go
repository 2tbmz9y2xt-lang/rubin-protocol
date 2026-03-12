//go:build cgo

package consensus

import (
	"fmt"
	"strings"
	"testing"
)

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
	opensslBootstrapFn = func(bool, string, string) error {
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

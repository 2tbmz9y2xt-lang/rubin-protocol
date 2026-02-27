//go:build cgo

package consensus

import (
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

	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "ready")
	t.Setenv("RUBIN_OPENSSL_CONF", "")
	t.Setenv("RUBIN_OPENSSL_MODULES", "")

	ok, verifyErr := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), signature, digest)
	if verifyErr != nil {
		t.Fatalf("verifySig(ready): %v", verifyErr)
	}
	if !ok {
		t.Fatalf("expected verifySig=true in ready mode")
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

	t.Setenv("RUBIN_OPENSSL_FIPS_MODE", "only")
	ok, verifyErr := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), signature, digest)
	if verifyErr != nil {
		if strings.Contains(verifyErr.Error(), "openssl bootstrap") {
			t.Skipf("FIPS provider unavailable in local env: %v", verifyErr)
		}
		t.Fatalf("verifySig(only): %v", verifyErr)
	}
	if !ok {
		t.Fatalf("expected verifySig=true in only mode")
	}
}

func TestVerifySig_InvalidFIPSModeRejected(t *testing.T) {
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

	ok, verifyErr := verifySig(SUITE_ID_ML_DSA_87, kp.PubkeyBytes(), signature, digest)
	if verifyErr == nil {
		t.Fatalf("expected bootstrap mode error, got nil")
	}
	if ok {
		t.Fatalf("expected verifySig=false on bootstrap mode error")
	}
	if got := mustTxErrCode(t, verifyErr); got != TX_ERR_PARSE {
		t.Fatalf("code=%s, want %s", got, TX_ERR_PARSE)
	}
	if !strings.Contains(verifyErr.Error(), "invalid RUBIN_OPENSSL_FIPS_MODE") {
		t.Fatalf("expected invalid mode context, got: %v", verifyErr)
	}
}

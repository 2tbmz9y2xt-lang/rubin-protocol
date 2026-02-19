//go:build !wolfcrypt_dylib

package main

import (
	"os"
	"testing"
)

func TestLoadCryptoProvider_StrictRequiresWolfcryptTag(t *testing.T) {
	old := os.Getenv("RUBIN_WOLFCRYPT_STRICT")
	_ = os.Setenv("RUBIN_WOLFCRYPT_STRICT", "1")
	t.Cleanup(func() { _ = os.Setenv("RUBIN_WOLFCRYPT_STRICT", old) })

	_, _, err := loadCryptoProvider()
	if err == nil {
		t.Fatalf("expected error in strict mode without wolfcrypt_dylib build tag")
	}
}

func TestLoadCryptoProvider_DevStdWhenNotStrict(t *testing.T) {
	old := os.Getenv("RUBIN_WOLFCRYPT_STRICT")
	_ = os.Unsetenv("RUBIN_WOLFCRYPT_STRICT")
	t.Cleanup(func() { _ = os.Setenv("RUBIN_WOLFCRYPT_STRICT", old) })

	p, cleanup, err := loadCryptoProvider()
	if err != nil {
		t.Fatalf("loadCryptoProvider: %v", err)
	}
	cleanup()
	if p == nil {
		t.Fatalf("expected provider")
	}
}


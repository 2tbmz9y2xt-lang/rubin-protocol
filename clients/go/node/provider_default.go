//go:build !wolfcrypt_dylib

package main

import (
	"errors"
	"os"
	"strings"

	"rubin.dev/node/crypto"
)

func loadCryptoProvider() (crypto.CryptoProvider, func(), error) {
	strict := func() bool {
		v := os.Getenv("RUBIN_WOLFCRYPT_STRICT")
		return v == "1" || strings.EqualFold(v, "true")
	}()
	if strict {
		return nil, func() {}, errors.New("RUBIN_WOLFCRYPT_STRICT=1 requires build tag wolfcrypt_dylib and RUBIN_WOLFCRYPT_SHIM_PATH")
	}
	return crypto.DevStdCryptoProvider{}, func() {}, nil
}

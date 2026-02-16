//go:build wolfcrypt_dylib

package main

import (
	"os"

	"rubin.dev/node/crypto"
)

func loadCryptoProvider() (crypto.CryptoProvider, func(), error) {
	if path, ok := os.LookupEnv("RUBIN_WOLFCRYPT_SHIM_PATH"); ok && path != "" {
		prov, err := crypto.LoadWolfcryptDylibProviderFromEnv()
		if err != nil {
			return nil, func() {}, err
		}
		return prov, func() {}, nil
	}
	return crypto.DevStdCryptoProvider{}, func() {}, nil
}


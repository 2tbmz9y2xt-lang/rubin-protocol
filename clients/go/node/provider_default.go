//go:build !wolfcrypt_dylib

package main

import "rubin.dev/node/crypto"

func loadCryptoProvider() (crypto.CryptoProvider, func(), error) {
	return crypto.DevStdCryptoProvider{}, func() {}, nil
}


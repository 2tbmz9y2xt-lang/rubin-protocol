package crypto

import "golang.org/x/crypto/sha3"

// DevStdCryptoProvider is a development-only provider.
// It does NOT claim FIPS compliance and exists only to unblock early tooling.
type DevStdCryptoProvider struct{}

func (p DevStdCryptoProvider) SHA3_256(input []byte) ([32]byte, error) {
	h := sha3.New256()
	_, _ = h.Write(input)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func (p DevStdCryptoProvider) VerifyMLDSA87(_ []byte, _ []byte, _ [32]byte) bool { return false }
func (p DevStdCryptoProvider) VerifySLHDSASHAKE_256f(_ []byte, _ []byte, _ [32]byte) bool {
	return false
}

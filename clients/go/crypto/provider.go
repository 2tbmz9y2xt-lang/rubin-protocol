package crypto

// CryptoProvider is the narrow crypto interface used by consensus code.
// Implementations may provide wolfCrypt or native backends.
type CryptoProvider interface {
	SHA3_256(input []byte) [32]byte
	VerifyMLDSA87(pubkey []byte, sig []byte, digest32 [32]byte) bool
	VerifySLHDSASHAKE_256f(pubkey []byte, sig []byte, digest32 [32]byte) bool
}

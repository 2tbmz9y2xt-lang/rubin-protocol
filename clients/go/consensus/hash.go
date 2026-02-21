package consensus

import "crypto/sha3"

func sha3_256(b []byte) [32]byte {
	return sha3.Sum256(b)
}

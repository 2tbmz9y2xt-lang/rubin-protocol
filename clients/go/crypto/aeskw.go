package crypto

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

// AES-256 Key Wrap (RFC 3394 / NIST SP 800-38F).
// This is a dev-only fallback for environments without the wolfcrypt shim.
//
// Strict/FIPS deployments MUST use the shim/HSM path (see node/provider_wolfcrypt.go).

var (
	kwDefaultIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
)

// AESKeyWrapRFC3394 wraps plaintext key material using AES-KW.
// kek must be 32 bytes. keyIn must be 16..4096 bytes and a multiple of 8 bytes.
func AESKeyWrapRFC3394(kek, keyIn []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, errors.New("aeskw: kek must be 32 bytes (AES-256)")
	}
	if len(keyIn) < 16 || len(keyIn) > 4096 || len(keyIn)%8 != 0 {
		return nil, errors.New("aeskw: keyIn must be 16..4096 bytes and multiple of 8")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(keyIn) / 8
	r := make([][8]byte, n)
	for i := 0; i < n; i++ {
		copy(r[i][:], keyIn[i*8:(i+1)*8])
	}
	a := kwDefaultIV

	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(b[0:8], a[:])
			copy(b[8:16], r[i][:])
			block.Encrypt(b[:], b[:])
			t := uint64(n*j + (i + 1))
			for k := 0; k < 8; k++ {
				a[k] = b[k] ^ byte(t>>(56-8*k))
			}
			copy(r[i][:], b[8:16])
		}
	}

	out := make([]byte, 0, 8+len(keyIn))
	out = append(out, a[:]...)
	for i := 0; i < n; i++ {
		out = append(out, r[i][:]...)
	}
	return out, nil
}

// AESKeyUnwrapRFC3394 unwraps AES-KW blob and returns plaintext key material.
// kek must be 32 bytes. wrapped must be 24..4104 bytes and multiple of 8 bytes.
func AESKeyUnwrapRFC3394(kek, wrapped []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, errors.New("aeskw: kek must be 32 bytes (AES-256)")
	}
	if len(wrapped) < 24 || len(wrapped) > 4104 || len(wrapped)%8 != 0 {
		return nil, errors.New("aeskw: wrapped must be 24..4104 bytes and multiple of 8")
	}

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := (len(wrapped) / 8) - 1
	var a [8]byte
	copy(a[:], wrapped[0:8])
	r := make([][8]byte, n)
	for i := 0; i < n; i++ {
		copy(r[i][:], wrapped[(i+1)*8:(i+2)*8])
	}

	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + (i + 1))
			var aXor [8]byte
			copy(aXor[:], a[:])
			for k := 0; k < 8; k++ {
				aXor[k] ^= byte(t >> (56 - 8*k))
			}
			copy(b[0:8], aXor[:])
			copy(b[8:16], r[i][:])
			block.Decrypt(b[:], b[:])
			copy(a[:], b[0:8])
			copy(r[i][:], b[8:16])
		}
	}

	if a != kwDefaultIV {
		// RFC3394 integrity check.
		return nil, errors.New("aeskw: integrity check failed")
	}

	out := make([]byte, 0, n*8)
	for i := 0; i < n; i++ {
		out = append(out, r[i][:]...)
	}

	// Sanity: roundtrip check size
	if len(out)%8 != 0 {
		return nil, errors.New("aeskw: unwrap produced non-multiple-of-8 length")
	}
	// Keep a stable memory layout; no extra allocations from binary.
	_ = binary.BigEndian
	return out, nil
}

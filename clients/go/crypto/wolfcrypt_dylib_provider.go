//go:build wolfcrypt_dylib

package crypto

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

typedef int32_t (*rubin_sha3_256_fn)(const uint8_t*, size_t, uint8_t*);
typedef int32_t (*rubin_verify_fn)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);
typedef int32_t (*rubin_keywrap_fn)(const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*, size_t*);

typedef struct {
	void* handle;
	rubin_sha3_256_fn sha3_256;
	rubin_verify_fn verify_mldsa87;
	rubin_verify_fn verify_slhdsa_shake_256f;
	rubin_keywrap_fn aes_keywrap;
	rubin_keywrap_fn aes_keyunwrap;
} rubin_wc_provider_t;

static int rubin_wc_load(rubin_wc_provider_t* p, const char* path) {
	p->handle = dlopen(path, RTLD_LAZY);
	if (!p->handle) return -1;

	p->sha3_256 = (rubin_sha3_256_fn)dlsym(p->handle, "rubin_wc_sha3_256");
	p->verify_mldsa87 = (rubin_verify_fn)dlsym(p->handle, "rubin_wc_verify_mldsa87");
	p->verify_slhdsa_shake_256f = (rubin_verify_fn)dlsym(p->handle, "rubin_wc_verify_slhdsa_shake_256f");
	// keywrap symbols are optional - older shims without keywrap still load fine
	p->aes_keywrap   = (rubin_keywrap_fn)dlsym(p->handle, "rubin_wc_aes_keywrap");
	p->aes_keyunwrap = (rubin_keywrap_fn)dlsym(p->handle, "rubin_wc_aes_keyunwrap");

	if (!p->sha3_256 || !p->verify_mldsa87 || !p->verify_slhdsa_shake_256f) {
		dlclose(p->handle);
		p->handle = NULL;
		return -2;
	}
	return 0;
}

static int32_t rubin_wc_aes_keywrap_call(
	rubin_wc_provider_t* p,
	const uint8_t* kek, size_t kek_len,
	const uint8_t* key_in, size_t key_in_len,
	uint8_t* out, size_t* out_len)
{
	if (!p || !p->aes_keywrap) return -99; // symbol not present in shim
	return p->aes_keywrap(kek, kek_len, key_in, key_in_len, out, out_len);
}

static int32_t rubin_wc_aes_keyunwrap_call(
	rubin_wc_provider_t* p,
	const uint8_t* kek, size_t kek_len,
	const uint8_t* wrapped, size_t wrapped_len,
	uint8_t* key_out, size_t* key_out_len)
{
	if (!p || !p->aes_keyunwrap) return -99;
	return p->aes_keyunwrap(kek, kek_len, wrapped, wrapped_len, key_out, key_out_len);
}

static int32_t rubin_wc_sha3_256_call(rubin_wc_provider_t* p, const uint8_t* input, size_t len, uint8_t* out) {
	if (!p || !p->sha3_256) {
		return -1;
	}
	return p->sha3_256(input, len, out);
}

static int32_t rubin_wc_verify_mldsa87_call(
	rubin_wc_provider_t* p,
	const uint8_t* pk,
	size_t pk_len,
	const uint8_t* sig,
	size_t sig_len,
	const uint8_t* digest
) {
	if (!p || !p->verify_mldsa87) {
		return -1;
	}
	return p->verify_mldsa87(pk, pk_len, sig, sig_len, digest);
}

static int32_t rubin_wc_verify_slhdsa_shake_256f_call(
	rubin_wc_provider_t* p,
	const uint8_t* pk,
	size_t pk_len,
	const uint8_t* sig,
	size_t sig_len,
	const uint8_t* digest
) {
	if (!p || !p->verify_slhdsa_shake_256f) {
		return -1;
	}
	return p->verify_slhdsa_shake_256f(pk, pk_len, sig, sig_len, digest);
}

static void rubin_wc_close(rubin_wc_provider_t* p) {
	if (p->handle) {
		dlclose(p->handle);
		p->handle = NULL;
	}
}
*/
import "C"

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/crypto/sha3"
)

// WolfcryptDylibProvider loads a local shim dylib exposing the stable RUBIN wolfCrypt ABI.
// The shim is expected to be provided by the compliance build pipeline and linked to wolfCrypt.
type WolfcryptDylibProvider struct {
	p      C.rubin_wc_provider_t
	strict bool
}

// LoadWolfcryptDylibProviderFromEnv loads the shim from RUBIN_WOLFCRYPT_SHIM_PATH.
func LoadWolfcryptDylibProviderFromEnv() (*WolfcryptDylibProvider, error) {
	path, ok := os.LookupEnv("RUBIN_WOLFCRYPT_SHIM_PATH")
	if !ok || path == "" {
		return nil, errors.New("RUBIN_WOLFCRYPT_SHIM_PATH is not set")
	}
	strict := func() bool {
		v := os.Getenv("RUBIN_WOLFCRYPT_STRICT")
		return v == "1" || strings.EqualFold(v, "true")
	}()

	if expected := os.Getenv("RUBIN_WOLFCRYPT_SHIM_SHA3_256"); expected != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		h := sha3.New256()
		if _, err := io.Copy(h, f); err != nil {
			return nil, err
		}
		sum := h.Sum(nil)
		actual := hex.EncodeToString(sum)
		if actual != strings.ToLower(expected) {
			return nil, errors.New("wolfcrypt shim hash mismatch (RUBIN_WOLFCRYPT_SHIM_SHA3_256)")
		}
	} else if strict {
		return nil, errors.New("RUBIN_WOLFCRYPT_SHIM_SHA3_256 required when RUBIN_WOLFCRYPT_STRICT=1")
	}
	return LoadWolfcryptDylibProvider(path, strict)
}

func LoadWolfcryptDylibProvider(path string, strict bool) (*WolfcryptDylibProvider, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var p C.rubin_wc_provider_t
	rc := C.rubin_wc_load(&p, cpath)
	if rc != 0 {
		return nil, errors.New("failed to load wolfcrypt shim dylib")
	}

	return &WolfcryptDylibProvider{p: p, strict: strict}, nil
}

// Close releases the dylib handle. Callers SHOULD close deterministically
// (e.g. `defer prov.Close()`) rather than relying on GC finalizers.
func (w *WolfcryptDylibProvider) Close() {
	C.rubin_wc_close(&w.p)
}

func (w *WolfcryptDylibProvider) SHA3_256(input []byte) ([32]byte, error) {
	var out [32]byte

	// The shim uses wolfCrypt APIs with `word32` length parameters. Avoid calling into the shim
	// with lengths that cannot be represented without truncation.
	if uint64(len(input)) > uint64(^uint32(0)) {
		if w.strict {
			return [32]byte{}, errors.New("wolfcrypt shim sha3_256: input too large for word32 length")
		}
		sum := sha3.Sum256(input)
		return sum, nil
	}

	if len(input) == 0 {
		rc := C.int32_t(C.rubin_wc_sha3_256_call(&w.p, nil, 0, (*C.uint8_t)(unsafe.Pointer(&out[0]))))
		if rc != 1 {
			if w.strict {
				return [32]byte{}, fmt.Errorf("wolfcrypt shim sha3_256 failed: rc=%d", int32(rc))
			}
			// Fallback to native SHA3-256 (deterministic) on shim error.
			sum := sha3.Sum256(nil)
			return sum, nil
		}
		return out, nil
	}

	rc := C.int32_t(C.rubin_wc_sha3_256_call(&w.p, (*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), (*C.uint8_t)(unsafe.Pointer(&out[0]))))
	if rc != 1 {
		if w.strict {
			return [32]byte{}, fmt.Errorf("wolfcrypt shim sha3_256 failed: rc=%d", int32(rc))
		}
		// Fallback to native SHA3-256 (deterministic) on shim error.
		sum := sha3.Sum256(input)
		return sum, nil
	}
	return out, nil
}

func (w *WolfcryptDylibProvider) VerifyMLDSA87(pubkey []byte, sig []byte, digest32 [32]byte) bool {
	// Defense-in-depth at the FFI boundary. Consensus already enforces canonical sizes.
	if len(pubkey) != 2592 || len(sig) != 4627 {
		return false
	}
	rc := C.int32_t(C.rubin_wc_verify_mldsa87_call(
		&w.p,
		(*C.uint8_t)(unsafe.Pointer(&pubkey[0])), C.size_t(len(pubkey)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		(*C.uint8_t)(unsafe.Pointer(&digest32[0])),
	))
	switch rc {
	case 1:
		return true
	case 0:
		return false
	default:
		return false
	}
}

func (w *WolfcryptDylibProvider) VerifySLHDSASHAKE_256f(pubkey []byte, sig []byte, digest32 [32]byte) bool {
	// Defense-in-depth at the FFI boundary. Consensus already enforces canonical sizes.
	if len(pubkey) != 64 || len(sig) != 49856 {
		return false
	}
	rc := C.int32_t(C.rubin_wc_verify_slhdsa_shake_256f_call(
		&w.p,
		(*C.uint8_t)(unsafe.Pointer(&pubkey[0])), C.size_t(len(pubkey)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		(*C.uint8_t)(unsafe.Pointer(&digest32[0])),
	))
	switch rc {
	case 1:
		return true
	case 0:
		return false
	default:
		return false
	}
}

// HasKeyManagement returns true if the loaded shim exports keywrap symbols.
// Older shims without keywrap will return false — callers should check before use.
func (w *WolfcryptDylibProvider) HasKeyManagement() bool {
	return w.p.aes_keywrap != nil && w.p.aes_keyunwrap != nil
}

// KeyWrap wraps key material using AES-256-KW (RFC 3394).
// kek must be exactly 32 bytes (AES-256). keyIn must be a non-zero multiple of 8 bytes.
// Returns the wrapped blob (keyIn length + 8 bytes ICV).
//
// Error codes from shim:
//
//	-30 null argument, -31 bad kek_len, -32 bad key_in_len,
//	-33 buf too small, -34 aes init, -35 wrap failed, -99 symbol absent in shim.
func (w *WolfcryptDylibProvider) KeyWrap(kek, keyIn []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, errors.New("keywrap: kek must be 32 bytes (AES-256)")
	}
	if len(keyIn) == 0 || len(keyIn)%8 != 0 {
		return nil, errors.New("keywrap: keyIn must be non-zero multiple of 8 bytes (RFC 3394)")
	}
	outBuf := make([]byte, len(keyIn)+8)
	outLen := C.size_t(len(outBuf))
	rc := C.int32_t(C.rubin_wc_aes_keywrap_call(
		&w.p,
		(*C.uint8_t)(unsafe.Pointer(&kek[0])), C.size_t(len(kek)),
		(*C.uint8_t)(unsafe.Pointer(&keyIn[0])), C.size_t(len(keyIn)),
		(*C.uint8_t)(unsafe.Pointer(&outBuf[0])), &outLen,
	))
	if rc <= 0 {
		return nil, fmt.Errorf("keywrap: shim error rc=%d", rc)
	}
	return outBuf[:int(outLen)], nil
}

// KeyUnwrap unwraps a blob produced by KeyWrap using AES-256-KW (RFC 3394).
// Returns ErrKeyWrapIntegrity if the blob is corrupted or the KEK is wrong (-36).
func (w *WolfcryptDylibProvider) KeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(kek) != 32 {
		return nil, errors.New("keyunwrap: kek must be 32 bytes (AES-256)")
	}
	if len(wrapped) < 16 {
		return nil, errors.New("keyunwrap: wrapped blob too short")
	}
	outBuf := make([]byte, len(wrapped)) // plaintext is always shorter than wrapped
	outLen := C.size_t(len(outBuf))
	rc := C.int32_t(C.rubin_wc_aes_keyunwrap_call(
		&w.p,
		(*C.uint8_t)(unsafe.Pointer(&kek[0])), C.size_t(len(kek)),
		(*C.uint8_t)(unsafe.Pointer(&wrapped[0])), C.size_t(len(wrapped)),
		(*C.uint8_t)(unsafe.Pointer(&outBuf[0])), &outLen,
	))
	if rc == -36 {
		return nil, ErrKeyWrapIntegrity
	}
	if rc <= 0 {
		return nil, fmt.Errorf("keyunwrap: shim error rc=%d", rc)
	}
	return outBuf[:int(outLen)], nil
}

// ErrKeyWrapIntegrity is returned when AES-KW integrity check fails (wrong KEK or corrupted blob).
var ErrKeyWrapIntegrity = errors.New("keyunwrap: integrity check failed (wrong KEK or corrupted blob)")

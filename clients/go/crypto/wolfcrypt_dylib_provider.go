//go:build wolfcrypt_dylib

package crypto

/*
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

typedef int32_t (*rubin_sha3_256_fn)(const uint8_t*, size_t, uint8_t*);
typedef int32_t (*rubin_verify_fn)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*);

typedef struct {
	void* handle;
	rubin_sha3_256_fn sha3_256;
	rubin_verify_fn verify_mldsa87;
	rubin_verify_fn verify_slhdsa_shake_256f;
} rubin_wc_provider_t;

static int rubin_wc_load(rubin_wc_provider_t* p, const char* path) {
	p->handle = dlopen(path, RTLD_LAZY);
	if (!p->handle) return -1;

	p->sha3_256 = (rubin_sha3_256_fn)dlsym(p->handle, "rubin_wc_sha3_256");
	p->verify_mldsa87 = (rubin_verify_fn)dlsym(p->handle, "rubin_wc_verify_mldsa87");
	p->verify_slhdsa_shake_256f = (rubin_verify_fn)dlsym(p->handle, "rubin_wc_verify_slhdsa_shake_256f");

	if (!p->sha3_256 || !p->verify_mldsa87 || !p->verify_slhdsa_shake_256f) {
		dlclose(p->handle);
		p->handle = NULL;
		return -2;
	}
	return 0;
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
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/crypto/sha3"
)

// WolfcryptDylibProvider loads a local shim dylib exposing the stable RUBIN wolfCrypt ABI.
// The shim is expected to be provided by the compliance build pipeline and linked to wolfCrypt.
type WolfcryptDylibProvider struct {
	p C.rubin_wc_provider_t
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
	return LoadWolfcryptDylibProvider(path)
}

func LoadWolfcryptDylibProvider(path string) (*WolfcryptDylibProvider, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var p C.rubin_wc_provider_t
	rc := C.rubin_wc_load(&p, cpath)
	if rc != 0 {
		return nil, errors.New("failed to load wolfcrypt shim dylib")
	}

	prov := &WolfcryptDylibProvider{p: p}
	runtime.SetFinalizer(prov, func(x *WolfcryptDylibProvider) { C.rubin_wc_close(&x.p) })
	return prov, nil
}

func (w *WolfcryptDylibProvider) SHA3_256(input []byte) [32]byte {
	var out [32]byte
	if len(input) == 0 {
		rc := C.int32_t(C.rubin_wc_sha3_256_call(&w.p, nil, 0, (*C.uint8_t)(unsafe.Pointer(&out[0]))))
		if rc != 1 {
			panic(fmt.Sprintf("wolfcrypt shim error: rubin_wc_sha3_256 rc=%d", rc))
		}
		return out
	}
	rc := C.int32_t(C.rubin_wc_sha3_256_call(&w.p, (*C.uint8_t)(unsafe.Pointer(&input[0])), C.size_t(len(input)), (*C.uint8_t)(unsafe.Pointer(&out[0]))))
	if rc != 1 {
		panic(fmt.Sprintf("wolfcrypt shim error: rubin_wc_sha3_256 rc=%d", rc))
	}
	return out
}

func (w *WolfcryptDylibProvider) VerifyMLDSA87(pubkey []byte, sig []byte, digest32 [32]byte) bool {
	if len(pubkey) == 0 || len(sig) == 0 {
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
		panic(fmt.Sprintf("wolfcrypt shim error: rubin_wc_verify_mldsa87 rc=%d", rc))
	}
}

func (w *WolfcryptDylibProvider) VerifySLHDSASHAKE_256f(pubkey []byte, sig []byte, digest32 [32]byte) bool {
	if len(pubkey) == 0 || len(sig) == 0 {
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
		panic(fmt.Sprintf("wolfcrypt shim error: rubin_wc_verify_slhdsa_shake_256f rc=%d", rc))
	}
}

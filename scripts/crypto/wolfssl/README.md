# wolfSSL Native PQC Build + FFI (No liboqs)

Этот набор используется только для разработки/CI. Он целенаправленно собирает **native wolfCrypt** с PQ-поддержкой без `liboqs`.

## 1) Что нужно собрать

- `ML-KEM` (native `ML-KEM`/Kyber)
- `ML-DSA` (native Dilithium)
- `XMSS`
- `LMS`

Важно: не использовать `--with-liboqs` и любые PQ-флаги, которые тянут OQS интеграцию.

## 2) Быстрый запуск локально

```bash
cd /path/to/rubin-protocol
./scripts/crypto/wolfssl/build-wolfssl-native.sh
```

По умолчанию будет сделан клон `https://github.com/wolfSSL/wolfssl` в `.work/wolfssl`, сборка с
`--enable-kyber=768,make,encapsulate,decapsulate,ml-kem --enable-dilithium=87,make,sign,verify --enable-experimental --enable-xmss --enable-lms`,
и затем проверка Smoke-теста.

Дополнительно можно задать:

- `WOLFSSL_REPO` — URL репозитория
- `WOLFSSL_REF` — commit/tag/branch
- `WOLFSSL_WORKDIR` — рабочая директория (по умолчанию `scripts/crypto/wolfssl/.work`)
- `WOLFSSL_INSTALL_DIR` — prefix инсталляции (по умолчанию `.../.work/prefix`)
- `WOLFSSL_MLKEM_VARIANTS` — профиль KYBER, напр. `768,make,encapsulate,decapsulate,ml-kem`
- `WOLFSSL_MLDSA_VARIANTS` — профиль ML-DSA, напр. `87,make,sign,verify`
- `WOLFSSL_EXTRA_CFLAGS` поддерживает `-Wno-error=...` для подавления сборочных предупреждений в средах с `-Werror`
- `WOLFSSL_EXTRA_CFLAGS` — доп. флаги компилятора (по умолчанию `-Wno-error=unused-function -Wno-error`)
- `WOLFSSL_EXTRA_CONFIGURE_ARGS` — доп. флаги для `./configure` (если нужны)

## 3) Почему это соответствует требованию «без liboqs»

После конфигурации скрипт проверяет:

- `config.h` не содержит `WOLFSSL_WITH_LIBOQS`
- `config.status` не включает включение `liboqs`
- `wc_MlKem*`, `wc_dilithium*`, `wc_XmssKey_*`, `wc_LmsKey_*` доступны при линковке

## 4) API (Go/C) — FFI сигнатуры под Rust/Go

### C/PQ функции (core)

```c
// ML-KEM
MlKemKey* wc_MlKemKey_New(int type, void* heap, int devId);
int       wc_MlKemKey_Delete(MlKemKey* key, MlKemKey** key_p);
int       wc_MlKemKey_Init(MlKemKey* key, int type, void* heap, int devId);
void      wc_MlKemKey_Free(MlKemKey* key);
int       wc_MlKemKey_MakeKey(MlKemKey* key, WC_RNG* rng);
int       wc_MlKemKey_Encapsulate(MlKemKey* key, unsigned char* ct,
           word32* ctLen, unsigned char* ss, word32* ssLen, WC_RNG* rng);
int       wc_MlKemKey_Decapsulate(MlKemKey* key, const unsigned char* ct,
           word32 ctLen, unsigned char* ss, word32* ssLen);
int       wc_MlKemKey_PublicKeySize(MlKemKey* key, word32* len);
int       wc_MlKemKey_PrivateKeySize(MlKemKey* key, word32* len);

// ML-DSA (Dilithium/ML-DSA, native wolfCrypt)
int       wc_dilithium_init(dilithium_key* key);
dilithium_key* wc_dilithium_new(void* heap, int devId);
int       wc_dilithium_delete(dilithium_key* key, dilithium_key** key_p);
void      wc_dilithium_free(dilithium_key* key);
int       wc_dilithium_make_key(dilithium_key* key, WC_RNG* rng);
int       wc_dilithium_sign_msg(const byte* msg, word32 msgLen, byte* sig,
           word32* sigLen, dilithium_key* key, WC_RNG* rng);
int       wc_dilithium_verify_msg(const byte* sig, word32 sigLen,
           const byte* msg, word32 msgLen, int* ret, dilithium_key* key);
int       wc_MlDsaSignMsg(int level, const byte* msg, word32 msgLen, byte* sig,
           word32* sigLen, dilithium_key* key, WC_RNG* rng);
int       wc_MlDsaVerifyMsg(int level, const byte* sig, word32 sigLen,
           const byte* msg, word32 msgLen, int* ret, dilithium_key* key);

// XMSS/LMS
int       wc_XmssKey_Init(XmssKey* key, void* heap, int devId);
void      wc_XmssKey_Free(XmssKey* key);
int       wc_LmsKey_Init(LmsKey* key, void* heap, int devId);
void      wc_LmsKey_Free(LmsKey* key);
```

### Go (cgo)

```go
// #cgo CFLAGS: -I${SRCDIR}/.work/prefix/include
// #cgo LDFLAGS: -L${SRCDIR}/.work/prefix/lib -lwolfssl
//
// #include <wolfssl/wolfcrypt/mlkem.h>
// #include <wolfssl/wolfcrypt/dilithium.h>
// #include <wolfssl/wolfcrypt/xmss.h>
// #include <wolfssl/wolfcrypt/lms.h>
import "C"

// use opaque pointers as raw C structs
func mlKemNew(keyType C.int) *C.MlKemKey {
    return C.wc_MlKemKey_New(keyType, nil, -1)
}

func mlKemPublicKeySize(key *C.MlKemKey) (C.int, C.uint) {
    var n C.uint
    rc := C.wc_MlKemKey_PublicKeySize(key, &n)
    return rc, n
}

func dilithiumInit(level C.uchar) (*C.struct_dilithium_key, C.int) {
    k := C.wc_dilithium_new(nil, -1)
    rc := C.wc_dilithium_init(k)
    return k, rc
}
```

### Rust (FFI)

```rust
#[repr(C)]
pub struct MlKemKey { _private: [u8; 0] }
#[repr(C)]
pub struct DilithiumKey { _private: [u8; 0] }
#[repr(C)]
pub struct XmssKey { _private: [u8; 0] }
#[repr(C)]
pub struct LmsKey { _private: [u8; 0] }
#[repr(C)]
pub struct WC_RNG { _private: [u8; 0] }

extern "C" {
    pub fn wc_MlKemKey_New(key_type: i32, heap: *mut core::ffi::c_void, dev_id: i32) -> *mut MlKemKey;
    pub fn wc_MlKemKey_Delete(key: *mut MlKemKey, key_p: *mut *mut MlKemKey) -> i32;
    pub fn wc_MlKemKey_Init(key: *mut MlKemKey, key_type: i32, heap: *mut core::ffi::c_void, dev_id: i32) -> i32;
    pub fn wc_MlKemKey_Free(key: *mut MlKemKey);
    pub fn wc_MlKemKey_MakeKey(key: *mut MlKemKey, rng: *mut WC_RNG) -> i32;
    pub fn wc_MlKemKey_PublicKeySize(key: *mut MlKemKey, len: *mut u32) -> i32;

    pub fn wc_dilithium_new(heap: *mut core::ffi::c_void, dev_id: i32) -> *mut DilithiumKey;
    pub fn wc_dilithium_init(key: *mut DilithiumKey) -> i32;
    pub fn wc_dilithium_free(key: *mut DilithiumKey);
    pub fn wc_dilithium_delete(key: *mut DilithiumKey, key_p: *mut *mut DilithiumKey) -> i32;
    pub fn wc_dilithium_sign_msg(msg: *const u8, msg_len: u32, sig: *mut u8, sig_len: *mut u32,
        key: *mut DilithiumKey, rng: *mut WC_RNG) -> i32;
    pub fn wc_dilithium_verify_msg(sig: *const u8, sig_len: u32, msg: *const u8, msg_len: u32, ret: *mut i32,
        key: *mut DilithiumKey) -> i32;
    pub fn wc_MlDsaSignMsg(level: u8, msg: *const u8, msg_len: u32, sig: *mut u8, sig_len: *mut u32,
        key: *mut DilithiumKey, rng: *mut WC_RNG) -> i32;
    pub fn wc_MlDsaVerifyMsg(level: u8, sig: *const u8, sig_len: u32, msg: *const u8, msg_len: u32, ret: *mut i32,
        key: *mut DilithiumKey) -> i32;

    pub fn wc_XmssKey_Init(key: *mut XmssKey, heap: *mut core::ffi::c_void, dev_id: i32) -> i32;
    pub fn wc_XmssKey_Free(key: *mut XmssKey);
    pub fn wc_LmsKey_Init(key: *mut LmsKey, heap: *mut core::ffi::c_void, dev_id: i32) -> i32;
    pub fn wc_LmsKey_Free(key: *mut LmsKey);
}
```

## 5) Smoke test API coverage (C)

Скрипт `run-smoke.sh` компилирует и запускает `smoke_mlkem_dilithium.c`, который:

- инициализирует и освобождает ML-KEM/Dilithium контексты
- дёргает символы/функции XMSS/LMS
- завершается с non-zero кодом при ошибки линковки или несовместимости API

## 6) CI job

В репозитории добавлен `.github/workflows/wolfssl-native-pqc.yml`, который:

1. Собирает native wolfSSL с нужными флагами PQ,
2. Проверяет отсутствие `liboqs`,
3. Держит `pkg-config`-пути/`LD_LIBRARY_PATH`,
4. Запускает C smoke.

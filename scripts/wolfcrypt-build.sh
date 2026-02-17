#!/usr/bin/env bash

# Single-step, reproducible wolfCrypt/wolfSSL build checklist for RUBIN.
# Non-consensus tooling. Uses only official wolfSSL/wolfCrypt (no liboqs).

set -euo pipefail

WOLFSSL_TAG="${RUBIN_WOLFSSL_TAG:-v5.8.4-stable}"
WORKROOT="${RUBIN_WOLFCRYPT_WORKROOT:-/tmp/rubin-wolfcrypt}"
WOLFSSL_REPO="${RUBIN_WOLFSSL_REPO:-https://github.com/wolfSSL/wolfssl.git}"
PREFIX="${RUBIN_WOLFSSL_PREFIX:-${WORKROOT}/install}"
SRC_DIR="${WORKROOT}/wolfssl-src"
BUILD_DIR="${WORKROOT}/wolfssl-build-${WOLFSSL_TAG}"
SMOKE_DIR="${WORKROOT}/wolfssl-smoke"
SMOKE_SRC="${SMOKE_DIR}/sha3_smoke.c"
SMOKE_BIN="${SMOKE_DIR}/wolfssl_sha3_smoke"
SHIM_OUT_ROOT="${RUBIN_WOLFCRYPT_SHIM_OUT:-${WORKROOT}/wolfcrypt-shim}"
SHIM_LOG="${WORKROOT}/wolfcrypt-shim-smoke.c"
SHIM_BIN="${SHIM_LOG%.c}.bin"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [[ "${OS}" == "darwin" ]]; then
  CPU_CORES="$(sysctl -n hw.ncpu)"
  SHARED_EXT="dylib"
  RPATH_ARGS='-Wl,-rpath,@loader_path'
  LD_ENV_VAR="DYLD_LIBRARY_PATH"
elif [[ "${OS}" == "linux" ]]; then
  CPU_CORES="$(nproc)"
  SHARED_EXT="so"
  RPATH_ARGS='-Wl,-rpath,$ORIGIN'
  LD_ENV_VAR="LD_LIBRARY_PATH"
else
  echo "Unsupported OS: ${OS}" >&2
  exit 1
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

need_cmd git
need_cmd cc
need_cmd make

mkdir -p "${WORKROOT}" "${SMOKE_DIR}"

configure_has_flag() {
  local flag="$1"
  grep -Fq -- "${flag}" <<<"${CONFIGURE_HELP}"
}

append_flag_if_supported() {
  local flag="$1"
  if configure_has_flag "${flag}"; then
    CONFIGURE_ARGS+=("${flag}")
  fi
}

if [[ ! -d "${SRC_DIR}/.git" ]]; then
  echo "Cloning wolfSSL ${WOLFSSL_TAG} from ${WOLFSSL_REPO}..."
  rm -rf "${SRC_DIR}"
  git clone --depth 1 --branch "${WOLFSSL_TAG}" --single-branch "${WOLFSSL_REPO}" "${SRC_DIR}"
else
  echo "Updating local wolfSSL checkout at ${SRC_DIR}..."
  (cd "${SRC_DIR}" && git fetch --all --tags --prune)
fi

(
  cd "${SRC_DIR}" && \
  git fetch --all --tags --prune

  if ! git rev-parse -q --verify "refs/tags/${WOLFSSL_TAG}" >/dev/null; then
    if [[ "${WOLFSSL_TAG}" != *"-stable" ]] && \
       git rev-parse -q --verify "refs/tags/${WOLFSSL_TAG}-stable" >/dev/null; then
      WOLFSSL_TAG="${WOLFSSL_TAG}-stable"
      echo "Resolved legacy tag to ${WOLFSSL_TAG}"
    fi
  fi

  git checkout "${WOLFSSL_TAG}"
  if git show-ref --verify --quiet "refs/remotes/origin/${WOLFSSL_TAG}"; then \
    git reset --hard "origin/${WOLFSSL_TAG}"; \
  else \
    git reset --hard "${WOLFSSL_TAG}"; \
  fi

  if [[ -x ./autogen.sh ]]; then ./autogen.sh; fi
)

CONFIGURE_HELP="$("${SRC_DIR}/configure" --help 2>&1)"

if configure_has_flag "--enable-ml-dsa"; then
  ML_DSA_FLAG="--enable-ml-dsa"
elif configure_has_flag "--enable-dilithium"; then
  ML_DSA_FLAG="--enable-dilithium"
else
  echo "Build guard failed: ML-DSA configure flag unavailable in this wolfSSL version" >&2
  exit 1
fi

if configure_has_flag "--enable-slh-dsa"; then
  SLH_DSA_FLAG="--enable-slh-dsa"
elif configure_has_flag "--enable-sphincs+"; then
  SLH_DSA_FLAG="--enable-sphincs+"
elif configure_has_flag "--enable-sphincs"; then
  SLH_DSA_FLAG="--enable-sphincs"
else
  SLH_DSA_FLAG=""
  echo "Warning: SLH-DSA flag not found in this wolfSSL build profile. SLH verification will stay disabled." >&2
fi

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

CONFIGURE_ARGS=(
  "--prefix=${PREFIX}"
  "${ML_DSA_FLAG}"
)
if [[ -n "${SLH_DSA_FLAG}" ]]; then
  CONFIGURE_ARGS+=("${SLH_DSA_FLAG}")
fi
append_flag_if_supported "--enable-shared"
append_flag_if_supported "--disable-examples"
append_flag_if_supported "--disable-tests"
append_flag_if_supported "--disable-demos"

(
  cd "${BUILD_DIR}"
  echo "Configuring wolfSSL (${WOLFSSL_TAG}) ..."
  "${SRC_DIR}/configure" "${CONFIGURE_ARGS[@]}"
  make -j"${CPU_CORES}"
  make install
)

if ! grep -Fq -- "${ML_DSA_FLAG}" "${BUILD_DIR}/config.log"; then
  echo "Build guard failed: ML-DSA not present in config.log." >&2
  exit 1
fi

if [[ -n "${SLH_DSA_FLAG}" ]]; then
  if ! grep -Fq -- "${SLH_DSA_FLAG}" "${BUILD_DIR}/config.log"; then
    echo "Build guard failed: SLH-DSA flag ${SLH_DSA_FLAG} not present in config.log." >&2
    exit 1
  fi
fi

# Guard against explicit liboqs enablement in this profile.
# A broad string match on "liboqs" is too noisy because wolfsSL configure files
# intentionally contain unrelated macro placeholders (e.g. BUILD_LIBOQS_*).
if grep -Eiq "(--with-liboqs|have_liboqs|HAVE_LIBOQS|ENABLED_LIBOQS|enable-liboqs|liboqs isn't found|liboqs_linked=yes)" "${BUILD_DIR}/config.log"; then
  echo "Build guard failed: explicit liboqs enablement detected in config.log." >&2
  exit 1
fi

build_rubin_wolfcrypt_shim() {
  local shim_script
  local project_root
  project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  shim_script="${project_root}/crypto/wolfcrypt/shim/build_wolfcrypt_shim.sh"
  if [[ ! -x "${shim_script}" ]]; then
    echo "Shim build script missing or not executable: ${shim_script}" >&2
    return 1
  fi

  RUBIN_WOLFCRYPT_WORKROOT="${WORKROOT}" \
    RUBIN_WOLFSSL_PREFIX="${PREFIX}" \
    CC="${CC:-cc}" \
    RUBIN_WOLFCRYPT_SHIM_OUT="${SHIM_OUT_ROOT}" \
    "${shim_script}"
}

cat > "${SMOKE_SRC}" <<'EOF'
#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha3.h>

int main(void) {
    wc_Sha3 hash;
    unsigned char out[32];
    const unsigned char msg[] = "RUBIN";
    int rc;

    rc = wc_InitSha3_256(&hash, NULL, INVALID_DEVID);
    if (rc != 0) {
        fprintf(stderr, "wc_InitSha3_256 failed: %d\n", rc);
        return 2;
    }

    rc = wc_Sha3_256_Update(&hash, (const unsigned char*)msg, (word32)sizeof(msg) - 1);
    if (rc != 0) {
        fprintf(stderr, "wc_Sha3_256_Update failed: %d\n", rc);
        return 3;
    }

    rc = wc_Sha3_256_Final(&hash, out);
    if (rc != 0) {
        fprintf(stderr, "wc_Sha3_256_Final failed: %d\n", rc);
        return 4;
    }

    if (out[0] == 0 && out[31] == 0) {
        fprintf(stderr, "Unexpected SHA3 digest for smoke test\n");
        return 5;
    }

    printf("wolfCrypt SHA3-256 smoke test OK\n");
    return 0;
}
EOF

echo "Building SHA3-256 smoke test..."
"${CC:-cc}" -std=c11 -O2 -I"${PREFIX}/include" \
  "${SMOKE_SRC}" \
  -L"${PREFIX}/lib" -lwolfssl -lm ${RPATH_ARGS} \
  -o "${SMOKE_BIN}"

if [[ ! -x "${SMOKE_BIN}" ]]; then
  echo "Smoke binary not built: ${SMOKE_BIN}" >&2
  exit 1
fi

(
  cd "${SMOKE_DIR}"
  echo "Running wolfCrypt smoke test..."
  if [[ "${LD_ENV_VAR}" == "DYLD_LIBRARY_PATH" ]]; then
    DYLD_LIBRARY_PATH="${PREFIX}/lib:${DYLD_LIBRARY_PATH-}" "${SMOKE_BIN}"
  else
    LD_LIBRARY_PATH="${PREFIX}/lib:${LD_LIBRARY_PATH-}" "${SMOKE_BIN}"
  fi
  )

build_rubin_wolfcrypt_shim

if [[ ! -f "${SHIM_OUT_ROOT}/librubin_wc_shim.${SHARED_EXT}" ]]; then
  echo "Missing shim output: ${SHIM_OUT_ROOT}/librubin_wc_shim.${SHARED_EXT}" >&2
  exit 1
fi

for lib in \
  "${PREFIX}/lib/libwolfssl."*.${SHARED_EXT} \
  "${PREFIX}/lib"/libwolfssl.${SHARED_EXT}* \
  "${PREFIX}/lib"/libwolfssl.*.${SHARED_EXT}* \
  "${PREFIX}/lib"/libwolfssl*.${SHARED_EXT} \
  "${PREFIX}/lib"/libwolfssl.*dylib* \
  "${PREFIX}/lib"/libwolfssl.dylib*; do
  if [ -e "${lib}" ] && [ -f "${lib}" ]; then
    cp -L "${lib}" "${SHIM_OUT_ROOT}/" || true
  fi
done

SHIM_DYLIB_PATH="${SHIM_OUT_ROOT}/librubin_wc_shim.${SHARED_EXT}"

cat > "${SHIM_LOG}" <<EOF
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <dlfcn.h>

typedef int32_t (*rubin_sha3_fn)(const uint8_t* input, size_t input_len, uint8_t out32[32]);

#ifdef __APPLE__
#define DYLIB_PATH "${SHIM_DYLIB_PATH}"
#else
#define DYLIB_PATH "${SHIM_DYLIB_PATH}"
#endif

int main(void) {
    const unsigned char msg[] = "RUBIN";
    unsigned char out[32] = {0};
    int rc;
    rubin_sha3_fn fn;
    void* h;
    char* err;

    h = dlopen(DYLIB_PATH, RTLD_NOW);
    if (!h) {
        return 12;
    }

    err = dlerror();
    (void)err;
    *(void**)(&fn) = dlsym(h, "rubin_wc_sha3_256");
    if (!fn) {
        dlclose(h);
        return 13;
    }

    rc = fn(msg, (size_t)sizeof(msg) - 1, out);
    dlclose(h);
    if (rc != 1) {
        return 14;
    }

    printf("rubin_wc_shim smoke OK\n");
    return 0;
}
EOF

if [[ "${OS}" == "darwin" ]]; then
  DLFLAGS=""
else
  DLFLAGS="-ldl"
fi

"${CC:-cc}" -std=c11 -O2 \
  -I"${PREFIX}/include" -o "${SHIM_BIN}" "${SHIM_LOG}" -L"${PREFIX}/lib" ${RPATH_ARGS} ${DLFLAGS} -lwolfssl

if [[ ! -x "${SHIM_BIN}" ]]; then
  echo "Shim smoke binary not built: ${SHIM_BIN}" >&2
  exit 1
fi

(
  cd "${WORKROOT}"
  if [[ "${LD_ENV_VAR}" == "DYLD_LIBRARY_PATH" ]]; then
    DYLD_LIBRARY_PATH="${PREFIX}/lib:${DYLD_LIBRARY_PATH-}" "${SHIM_BIN}"
  else
    LD_LIBRARY_PATH="${PREFIX}/lib:${LD_LIBRARY_PATH-}" "${SHIM_BIN}"
  fi
)

echo ""
echo "wolfCrypt build checklist completed."
echo "  repo:      ${SRC_DIR}"
echo "  version:   ${WOLFSSL_TAG}"
echo "  prefix:    ${PREFIX}"
echo "  shared:    ${PREFIX}/lib/libwolfssl.${SHARED_EXT}"
echo "  smoke:     ${SMOKE_BIN}"
echo ""
echo "Smoke test output log: ${SMOKE_BIN}"

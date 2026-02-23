#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${WOLFSSL_WORKDIR:-$(dirname "$0")/.work}"
WOLFSSL_REPO="${WOLFSSL_REPO:-https://github.com/wolfSSL/wolfssl.git}"
WOLFSSL_REF="${WOLFSSL_REF:-master}"
KEEP_SRC="${WOLFSSL_KEEP_SRC:-false}"

# Supported profiles for wolfCrypt-native PQ (no liboqs).
# See wolfSSL configure help:
# --enable-kyber=[all,512,768,1024,ml-kem,small,original,yes]
# --enable-dilithium=[all,44,65,87,small,make,sign,verify,verify-only]
MLKEM_VARIANTS="${WOLFSSL_MLKEM_VARIANTS:-${WOLFSSL_MLKEM_OPTION:-768,make,encapsulate,decapsulate,ml-kem}}"
MLDSA_VARIANTS="${WOLFSSL_MLDSA_VARIANTS:-${WOLFSSL_MLDSA_OPTION:-87,make,sign,verify}}"
WOLFSSL_EXTRA_CONFIGURE_ARGS="${WOLFSSL_EXTRA_CONFIGURE_ARGS:-}"
WOLFSSL_EXTRA_CFLAGS="${WOLFSSL_EXTRA_CFLAGS:--Wno-error=unused-function -Wno-error}"

THREADS="${WOLFSSL_BUILD_THREADS:-$(sysctl -n hw.ncpu 2>/dev/null || nproc)}"

mkdir -p "$WORKDIR"
WORKDIR="$(cd "$WORKDIR" && pwd)"
INSTALL_DIR="${WOLFSSL_INSTALL_DIR:-$WORKDIR/prefix}"
SRC_DIR="$WORKDIR/wolfssl"
LOG_FILE="$WORKDIR/build.log"

if [ -d "$SRC_DIR" ]; then
  if [ "$KEEP_SRC" = "true" ]; then
    echo "Using existing source at $SRC_DIR"
    (cd "$SRC_DIR" && git fetch --depth=1 origin "$WOLFSSL_REF")
    (cd "$SRC_DIR" && git checkout -f "$WOLFSSL_REF")
  else
    rm -rf "$SRC_DIR"
    git clone --depth 1 --branch "$WOLFSSL_REF" "$WOLFSSL_REPO" "$SRC_DIR"
  fi
else
  git clone --depth 1 --branch "$WOLFSSL_REF" "$WOLFSSL_REPO" "$SRC_DIR"
fi

cd "$SRC_DIR"

if [ -x ./autogen.sh ]; then
  ./autogen.sh
fi

./configure \
  CFLAGS="${WOLFSSL_EXTRA_CFLAGS} ${CFLAGS:-}" \
  CPPFLAGS="${CPPFLAGS:-}" \
  --prefix="$INSTALL_DIR" \
  --enable-static \
  --disable-shared \
  --disable-examples \
  --disable-crypttests \
  --enable-experimental \
  --enable-kyber="$MLKEM_VARIANTS" \
  --enable-dilithium="$MLDSA_VARIANTS" \
  --enable-xmss \
  --enable-lms \
  $WOLFSSL_EXTRA_CONFIGURE_ARGS \
  >"$LOG_FILE" 2>&1

if [ -f "$SRC_DIR/config.status" ] && grep -Eq "with-liboqs.*(yes|\\\"yes\\\")" "$SRC_DIR/config.status"; then
  echo "ERROR: config.status indicates liboqs"
  exit 1
fi
if [ -f "$SRC_DIR/config.h" ] && grep -Eq "WOLFSSL_WITH_LIBOQS" "$SRC_DIR/config.h"; then
  echo "ERROR: config.h contains disallowed liboqs flags"
  exit 1
fi

make -j "$THREADS" >>"$LOG_FILE" 2>&1
make install >>"$LOG_FILE" 2>&1

mkdir -p "$WORKDIR/logs"
cp "$LOG_FILE" "$WORKDIR/logs/last-build.log"

echo "Built wolfSSL at $INSTALL_DIR"
echo "Log: $WORKDIR/logs/last-build.log"

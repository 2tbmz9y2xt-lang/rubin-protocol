#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${WOLFSSL_WORKDIR:-$(dirname "$0")/.work}"
INSTALL_DIR="${WOLFSSL_INSTALL_DIR:-$WORKDIR/prefix}"
SRC_DIR="$WORKDIR/wolfssl"
SMOKE_SRC="$(dirname "$0")/smoke_mlkem_dilithium.c"
SMOKE_BIN="$WORKDIR/smoke_mlkem_dilithium"
PLATFORM_LINK_FLAGS=""

if [ "$(uname -s)" = "Darwin" ]; then
  PLATFORM_LINK_FLAGS="-framework Security -framework CoreFoundation"
fi

if [ ! -f "$SMOKE_SRC" ]; then
  echo "Smoke source not found: $SMOKE_SRC"
  exit 1
fi

if [ ! -d "$INSTALL_DIR/include/wolfssl" ] || [ ! -f "$INSTALL_DIR/lib/libwolfssl.a" ]; then
  echo "wolfSSL install not found. run build-wolfssl-native.sh first."
  exit 1
fi

cc -std=c11 -I"$INSTALL_DIR/include" -I"$SRC_DIR" "$SMOKE_SRC" \
  -L"$INSTALL_DIR/lib" -lwolfssl -lm $PLATFORM_LINK_FLAGS -o "$SMOKE_BIN"

"$SMOKE_BIN"

echo "Smoke test OK"

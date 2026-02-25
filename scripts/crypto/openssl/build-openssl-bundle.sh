#!/usr/bin/env bash
set -euo pipefail

OPENSSL_VERSION="${OPENSSL_VERSION:-3.5.5}"
OPENSSL_TAG="openssl-${OPENSSL_VERSION}"
ARCHIVE="openssl-${OPENSSL_VERSION}.tar.gz"
ARCHIVE_URL="${ARCHIVE_URL:-https://github.com/openssl/openssl/releases/download/${OPENSSL_TAG}/${ARCHIVE}}"
WORK_ROOT="${WORK_ROOT:-$HOME/.cache/rubin-openssl/work}"
PREFIX="${PREFIX:-$HOME/.cache/rubin-openssl/bundle-${OPENSSL_VERSION}}"
BUILD_DIR="${WORK_ROOT}/openssl-${OPENSSL_VERSION}"
TARBALL_PATH="${WORK_ROOT}/${ARCHIVE}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 8)}"

mkdir -p "${WORK_ROOT}"

echo "[openssl-bundle] version=${OPENSSL_VERSION}"
echo "[openssl-bundle] archive=${ARCHIVE_URL}"
echo "[openssl-bundle] work=${WORK_ROOT}"
echo "[openssl-bundle] prefix=${PREFIX}"

if [ ! -f "${TARBALL_PATH}" ]; then
  curl -fL "${ARCHIVE_URL}" -o "${TARBALL_PATH}"
fi

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
tar -xzf "${TARBALL_PATH}" -C "${BUILD_DIR}" --strip-components=1

cd "${BUILD_DIR}"

./config \
  --prefix="${PREFIX}" \
  --openssldir="${PREFIX}/ssl" \
  enable-fips \
  no-tests

make -j"${JOBS}"
make install_sw
make install_fips

MODULE_PATH=""
for candidate in \
  "${PREFIX}/lib64/ossl-modules/fips.so" \
  "${PREFIX}/lib64/ossl-modules/fips.dylib" \
  "${PREFIX}/lib64/ossl-modules/fips.dll" \
  "${PREFIX}/lib/ossl-modules/fips.so" \
  "${PREFIX}/lib/ossl-modules/fips.dylib" \
  "${PREFIX}/lib/ossl-modules/fips.dll"
do
  if [[ -f "${candidate}" ]]; then
    MODULE_PATH="${candidate}"
    break
  fi
done

if [[ -z "${MODULE_PATH}" ]]; then
  echo "ERROR: FIPS provider module not found under ${PREFIX}/lib*/ossl-modules" >&2
  exit 1
fi

OPENSSL_RUN_LD_LIBRARY_PATH="${PREFIX}/lib64:${PREFIX}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
LD_LIBRARY_PATH="${OPENSSL_RUN_LD_LIBRARY_PATH}" "${PREFIX}/bin/openssl" fipsinstall \
  -out "${PREFIX}/ssl/fipsmodule.cnf" \
  -module "${MODULE_PATH}"

cat > "${PREFIX}/ssl/openssl-fips.cnf" <<EOF
config_diagnostics = 1
openssl_conf = openssl_init

.include ${PREFIX}/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
default = default_sect
fips = fips_sect

[default_sect]
activate = 1

[fips_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
EOF

echo "[openssl-bundle] done"
LD_LIBRARY_PATH="${OPENSSL_RUN_LD_LIBRARY_PATH}" "${PREFIX}/bin/openssl" version -a
LD_LIBRARY_PATH="${OPENSSL_RUN_LD_LIBRARY_PATH}" "${PREFIX}/bin/openssl" list -signature-algorithms | sed -n '1,40p'

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
FIPS_SECTION_NAME="${FIPS_SECTION_NAME:-fips_sect}"

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

FIPS_MODULE_DIR=""
for module_dir in \
  "${PREFIX}/lib/ossl-modules" \
  "${PREFIX}/lib64/ossl-modules"
do
  if [[ -d "${module_dir}" ]]; then
    FIPS_MODULE_DIR="${module_dir}"
    break
  fi
done

FIPS_MODULE=""
if [[ -n "${FIPS_MODULE_DIR}" ]]; then
  for candidate in \
    "${FIPS_MODULE_DIR}/fips.so" \
    "${FIPS_MODULE_DIR}/fips.dylib" \
    "${FIPS_MODULE_DIR}/fips.dll"
  do
    if [[ -f "${candidate}" ]]; then
      FIPS_MODULE="${candidate}"
      break
    fi
  done
fi

if [[ -z "${FIPS_MODULE}" ]]; then
  echo "ERROR: FIPS module not found under ${PREFIX}/lib*/ossl-modules" >&2
  exit 1
fi

mkdir -p "${PREFIX}/ssl"
FIPS_MODULE_CNF="${PREFIX}/ssl/fipsmodule.cnf"
OPENSSL_FIPS_CNF="${PREFIX}/ssl/openssl-fips.cnf"

OPENSSL_RUN_LD_LIBRARY_PATH="${PREFIX}/lib64:${PREFIX}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
LD_LIBRARY_PATH="${OPENSSL_RUN_LD_LIBRARY_PATH}" "${PREFIX}/bin/openssl" fipsinstall \
  -module "${FIPS_MODULE}" \
  -out "${FIPS_MODULE_CNF}" \
  -provider_name fips \
  -mac_name HMAC \
  -section_name "${FIPS_SECTION_NAME}"

cat > "${OPENSSL_FIPS_CNF}" <<EOF
config_diagnostics = 1
openssl_conf = openssl_init

.include ${FIPS_MODULE_CNF}

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
default = default_sect
fips = ${FIPS_SECTION_NAME}

[default_sect]
activate = 1

[algorithm_sect]
default_properties = fips=yes
EOF

echo "[openssl-bundle] done"
LD_LIBRARY_PATH="${OPENSSL_RUN_LD_LIBRARY_PATH}" "${PREFIX}/bin/openssl" version -a
LD_LIBRARY_PATH="${OPENSSL_RUN_LD_LIBRARY_PATH}" "${PREFIX}/bin/openssl" list -signature-algorithms | sed -n '1,40p'
echo "[openssl-bundle] fips-module=${FIPS_MODULE}"
echo "[openssl-bundle] fips-config=${OPENSSL_FIPS_CNF}"

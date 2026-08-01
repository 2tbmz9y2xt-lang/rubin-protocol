#!/usr/bin/env bash
set -euo pipefail

CHECK_SELECTION_ONLY=0
case "$#" in
  0) ;;
  1)
    if [ "$1" != "--check-selection" ]; then
      echo "ERROR: unknown argument: $1" >&2
      exit 2
    fi
    CHECK_SELECTION_ONLY=1
    ;;
  *)
    echo "ERROR: expected no arguments or --check-selection" >&2
    exit 2
    ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${OPENSSL_VERSION:-}" ]; then
  VERSION_FILE="${SCRIPT_DIR}/VERSION"
  if [ ! -r "${VERSION_FILE}" ]; then
    echo "ERROR: cannot read selected OpenSSL version from ${VERSION_FILE}" >&2
    exit 1
  fi
  VERSION_LINE_COUNT="$(wc -l < "${VERSION_FILE}" | tr -d '[:space:]')"
  VERSION_FINAL_NEWLINE="$(tail -c 1 "${VERSION_FILE}" | wc -l | tr -d '[:space:]')"
  if [ "${VERSION_LINE_COUNT}" != 1 ] || [ "${VERSION_FINAL_NEWLINE}" != 1 ]; then
    echo "ERROR: ${VERSION_FILE} must contain exactly one newline-terminated line" >&2
    exit 1
  fi
  IFS= read -r OPENSSL_VERSION < "${VERSION_FILE}"
fi
IFS=. read -r VERSION_MAJOR VERSION_MINOR VERSION_PATCH VERSION_EXTRA <<< "${OPENSSL_VERSION}"
if [ -n "${VERSION_EXTRA:-}" ] || [ -z "${VERSION_MAJOR:-}" ] || [ -z "${VERSION_MINOR:-}" ] || [ -z "${VERSION_PATCH:-}" ] \
  || [[ "${VERSION_MAJOR}${VERSION_MINOR}${VERSION_PATCH}" == *[!0-9]* ]] \
  || [ "${OPENSSL_VERSION}" != "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}" ]; then
  echo "ERROR: OpenSSL version must be MAJOR.MINOR.PATCH decimal" >&2
  exit 1
fi
OPENSSL_TAG="openssl-${OPENSSL_VERSION}"
ARCHIVE="openssl-${OPENSSL_VERSION}.tar.gz"
ARCHIVE_URL="${ARCHIVE_URL:-https://github.com/openssl/openssl/releases/download/${OPENSSL_TAG}/${ARCHIVE}}"
WORK_ROOT="${WORK_ROOT:-$HOME/.cache/rubin-openssl/work}"
PREFIX="${PREFIX:-$HOME/.cache/rubin-openssl/bundle-${OPENSSL_VERSION}}"
BUILD_DIR="${WORK_ROOT}/openssl-${OPENSSL_VERSION}"
TARBALL_PATH="${WORK_ROOT}/${ARCHIVE}"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 8)}"
FIPS_SECTION_NAME="${FIPS_SECTION_NAME:-fips_sect}"
CHECKSUM_FILE="${SCRIPT_DIR}/source-checksums.sha256"
CHECKSUM_LINE_RE='^([0-9a-f]{64})  ([^[:space:]]+)$'

# The pinned sha256 of every supported upstream source tarball lives in
# CHECKSUM_FILE, selected by archive name — i.e. by OPENSSL_VERSION — and never by
# ARCHIVE_URL, so a mirror serving the pinned bytes passes and anything else fails
# without any URL-specific logic. A pin file that is unreadable, malformed anywhere,
# or ambiguous about the selected archive fails the build rather than being trusted.
lookup_pinned_sha256() {
  local archive="$1" line digest="" lineno=0
  if [ ! -r "${CHECKSUM_FILE}" ]; then
    echo "ERROR: cannot read pinned checksum file ${CHECKSUM_FILE}; refusing to build" >&2
    return 1
  fi
  while IFS= read -r line || [ -n "${line}" ]; do
    lineno=$((lineno + 1))
    case "${line}" in ''|'#'*) continue ;; esac
    if [[ ! "${line}" =~ ${CHECKSUM_LINE_RE} ]]; then
      echo "ERROR: malformed entry at ${CHECKSUM_FILE}:${lineno}" >&2
      echo "Every entry must be '<64 lowercase hex>  <archive>'; refusing to build" >&2
      return 1
    fi
    if [ "${BASH_REMATCH[2]}" = "${archive}" ]; then
      if [ -n "${digest}" ]; then
        echo "ERROR: duplicate pinned sha256 for ${archive} at ${CHECKSUM_FILE}:${lineno}; refusing to build" >&2
        return 1
      fi
      digest="${BASH_REMATCH[1]}"
    fi
  done < "${CHECKSUM_FILE}"
  if [ -z "${digest}" ]; then
    echo "ERROR: no pinned sha256 for OpenSSL ${OPENSSL_VERSION}; refusing to build" >&2
    echo "Add a '<sha256>  ${ARCHIVE}' line to ${CHECKSUM_FILE}" >&2
    echo "using the digest published at https://github.com/openssl/openssl/releases/download/${OPENSSL_TAG}/${ARCHIVE}.sha256" >&2
    return 1
  fi
  printf '%s\n' "${digest}"
}

if ! EXPECTED_SHA256="$(lookup_pinned_sha256 "${ARCHIVE}")"; then
  exit 1
fi
if [ "${CHECK_SELECTION_ONLY}" -eq 1 ]; then
  echo "[openssl-bundle] selection-ok version=${OPENSSL_VERSION} source-sha256=${EXPECTED_SHA256}"
  exit 0
fi

compute_sha256() {
  local output
  if command -v sha256sum >/dev/null 2>&1; then
    output="$(sha256sum "$1")" || { echo "ERROR: sha256sum failed for $1" >&2; return 1; }
  elif command -v shasum >/dev/null 2>&1; then
    output="$(shasum -a 256 "$1")" || { echo "ERROR: shasum failed for $1" >&2; return 1; }
  else
    echo "ERROR: no sha256 tool available (need sha256sum or shasum -a 256)" >&2
    return 1
  fi
  printf '%s\n' "${output%% *}"
}

mkdir -p "${WORK_ROOT}"

echo "[openssl-bundle] version=${OPENSSL_VERSION}"
echo "[openssl-bundle] archive=${ARCHIVE_URL}"
echo "[openssl-bundle] work=${WORK_ROOT}"
echo "[openssl-bundle] prefix=${PREFIX}"

if [ ! -f "${TARBALL_PATH}" ]; then
  # Retrying is safe because of the check below: a truncated or partial result
  # fails verification rather than being consumed.
  curl -fL --retry 5 --retry-delay 2 "${ARCHIVE_URL}" -o "${TARBALL_PATH}"
fi

# One verification point covers both paths: a freshly downloaded tarball and one
# restored from a CI or developer cache reach it alike, before extraction.
if ! ACTUAL_SHA256="$(compute_sha256 "${TARBALL_PATH}")"; then
  exit 1
fi
if [ "${ACTUAL_SHA256}" != "${EXPECTED_SHA256}" ]; then
  echo "ERROR: ${ARCHIVE} sha256 mismatch (expected ${EXPECTED_SHA256}, got ${ACTUAL_SHA256}); refusing to build" >&2
  rm -f -- "${TARBALL_PATH}"
  exit 1
fi
echo "[openssl-bundle] source-sha256=${ACTUAL_SHA256}"

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

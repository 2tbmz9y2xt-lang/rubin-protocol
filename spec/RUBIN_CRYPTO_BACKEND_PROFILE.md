# RUBIN Crypto Backend Profile

**Status:** Normative (non-consensus)  
**Date:** 2026-02-23

## 1. Scope

This document defines the required cryptographic implementation profile for
reference clients, CI, and repository policy.

It does **not** change consensus rules. Consensus validity remains defined by
`RUBIN_L1_CANONICAL.md`.

## 2. Required Backend

RUBIN clients in this repository MUST use:

- **OpenSSL 3.5+** EVP APIs for post-quantum primitives.

Mapping:

- `SUITE_ID_ML_DSA_87 (0x01)` -> OpenSSL ML-DSA verification/signing path
- `SUITE_ID_SLH_DSA_SHAKE_256F (0x02)` -> OpenSSL SLH-DSA verification/signing path
- `SHA3-256` consensus hashing -> OpenSSL SHA3 path (or language stdlib equivalent with identical output)

## 3. Explicitly Forbidden Dependencies

The following dependencies are forbidden in this repository:

- `wolfCrypt`
- `wolfSSL`
- `liboqs`
- OQS headers/APIs (`oqs/`, `OQS_*`)

Any introduction of these dependencies in source code, scripts, docs, or CI
MUST fail repository checks.

## 4. FIPS Positioning

- This profile is designed for a direct FIPS migration path through OpenSSL
  provider architecture.
- Current claims in repository docs MUST remain conservative:
  - allowed: "NIST/FIPS-aligned PQ implementation profile"
  - forbidden: "PQ algorithms are already FIPS-validated in production scope"

## 5. Change Control

Switching cryptographic backend/provider is non-consensus only if:

1. consensus bytes and validation semantics remain unchanged;
2. conformance vectors remain green for both reference clients.

If any backend change affects consensus semantics, it is consensus-impacting
and requires explicit controller approval.

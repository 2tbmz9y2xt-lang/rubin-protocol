# RUBIN Protocol (Post-Quantum L1, wolfCrypt-based)

This repository is the canonical home of the RUBIN L1 specification and its supporting formal/operational appendices.

## What this is

RUBIN is a **post-quantum oriented L1 blockchain** (PoW, UTXO-style, deterministic validation) designed to remain secure under **harvest-now-decrypt-later** assumptions and to support long-lived deployments (10–15+ years).

Design focus:
- strict deterministic consensus (cross-client reproducibility gates),
- crypto-agility via VERSION_BITS,
- an operationally realistic **FIPS-path** integration story (wolfCrypt-based behind a provider boundary).

Status: development. Not a production readiness claim.

## Why this chain (philosophy)

1. **Longevity under PQ threat**: treat PQ migration as a first-class requirement instead of a retrofit.
2. **Determinism as a release gate**: txid/sighash/error codes must match across independent clients.
3. **Compliance-oriented supply chain**: keep consensus crypto behind a stable provider/shim ABI to enable controlled builds and future validated-module workflows.

## Cryptography (v1.1)

Consensus primitives (normative in `spec/RUBIN_L1_CANONICAL_v1.1.md`):
- Hashing: `SHA3-256` (FIPS 202)
- Signatures:
  - `suite_id = 0x01`: `ML-DSA-87` (FIPS 204)
  - `suite_id = 0x02`: `SLH-DSA-SHAKE-256f` (FIPS 205) — deployment-gated for CORE_P2PK; also used for RETL envelope signatures under policy

All consensus code must call crypto only via the provider interface (Rust: `clients/rust/crates/rubin-crypto/src/lib.rs`, Go: `clients/go/crypto/provider.go`).

## Why wolfCrypt (FIPS-path)

We use a **wolfCrypt-based** backend path because it enables:
- a controlled crypto supply chain suitable for compliance programs,
- consistent C ABI delivery via a small shim dylib (`crypto/wolfcrypt/SHIM_DELIVERABLE_SPEC.md`),
- runtime loading in both Rust and Go without importing wolfSSL headers into consensus code.

Compliance precision (as of 2026-02-16):
- wolfCrypt has active FIPS 140-3 certificates (e.g., CMVP #4718 and #5041), but those validated modules do not list PQC algorithms in their published Security Policy documents.
- wolfSSL publicly states it is developing a new PQC-enabled FIPS 140-3 certificate covering FIPS 203–205 and that the CMVP submission is in process (2026-02-10).
- NIST CMVP “Modules In Process” lists a wolfCrypt FIPS 140-3 submission as “Review Pending (9/12/2025)”.

Therefore: “FIPS-path” in this repo means build discipline and deployability; it is not a current “FIPS-validated PQC” claim.

## Canonical documents (v1.1)

- L1 consensus spec (normative): `spec/RUBIN_L1_CANONICAL_v1.1.md`
- Spec index (web-friendly): `SPEC.md`
- Formal appendix (non-normative): `formal/RUBIN_FORMAL_APPENDIX_v1.1.md`
- Operational security (non-normative): `operational/RUBIN_OPERATIONAL_SECURITY_v1.1.md`
- Node policy defaults (non-consensus): `operational/RUBIN_NODE_POLICY_DEFAULTS_v1.1.md`
- Mainnet genesis ceremony (controller-run): `operational/RUBIN_MAINNET_GENESIS_CEREMONY_v1.1.md`

## Chain instances (dev/test/main profiles)

Chain-instance profiles publish concrete genesis bytes and derived `chain_id` for a specific network:

- Devnet profile: `spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_DEVNET_v1.1.md`
- Template: `spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_TEMPLATE_v1.1.md`

## VERSION_BITS deployments

Deployments are chain-instance specific and are published using the schema in `spec/RUBIN_L1_CANONICAL_v1.1.md §8.1`:

- Devnet deployments (currently none): `spec/RUBIN_L1_DEPLOYMENTS_DEVNET_v1.1.md`
- Template: `spec/RUBIN_L1_DEPLOYMENTS_TEMPLATE_v1.1.md`

## Auxiliary L1 documents (canonical support)

- Key management (non-consensus): `spec/RUBIN_L1_KEY_MANAGEMENT_v1.1.md`
- Crypto agility notes: `spec/RUBIN_L1_CRYPTO_AGILITY_UPGRADE_v1.1.md`
- Conformance manifest: `spec/RUBIN_L1_CONFORMANCE_MANIFEST_v1.1.md`
- Coinbase and rewards notes: `spec/RUBIN_L1_COINBASE_AND_REWARDS_v1.1.md`
- P2P protocol: `spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md`

## Implementation scaffolds (development)

Two-client roadmap and scaffolds (Rust + Go):

- Rust workspace: `clients/rust/`
- Go module: `clients/go/`
- Shared conformance: `conformance/`
- wolfCrypt notes: `crypto/wolfcrypt/`

## Conformance (determinism gates)

- CV-SIGHASH vectors: `conformance/fixtures/CV-SIGHASH.yml`
- Minimal runner (Rust vs Go parity): `python3 conformance/runner/run_cv_sighash.py`

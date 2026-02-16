# RUBIN L1 Key Management and Address Binding v1.1

Status: CANONICAL-AUXILIARY
Date: 2026-02-15
Scope: Consensus key binding, identity fingerprints, and application-layer key lifecycle

## 1. Consensus-Level Binding

1. L1-consensus validates only:
   - public key bytes,
   - `key_id`,
   - signature over consensus `sighash`.
2. `key_id` is canonicalized as:

   `key_id = SHA3-256(pubkey_wire)`

3. `key_id` is always 32 bytes.
4. Allowed key sizes:
   - ML-DSA-87: public key 2592 bytes, signature 4627 bytes exactly,
   - SLH-DSA-SHAKE-256f: public key 64 bytes, signature 1..`MAX_SLH_DSA_SIG_BYTES` bytes.
5. L1-consensus MUST enforce exact public-key length for the selected `suite_id` and reject malformed encodings.

## 2. Address Binding Layer (Non-Consensus)

1. Address binding is defined by:
   - `address_version || key_id`
2. For this profile:
   - `address_version = 0x00` for ML-DSA-87,
   - `address_version = 0x01` for SLH-DSA-SHAKE-256f.
3. `bech32m("rbin", address_version || key_id)` is RECOMMENDED for human-facing display.
4. Any alternative display encoding MUST decode to the same `key_id_wire`.

## 3. Key Lifecycle and Entropy Requirements

1. Key generation uses at least 256-bit secure entropy.
2. Public-key serialization MUST be deterministic byte-by-byte.
3. Key rotation/revocation status is not consensus-visible.
4. Application layers MAY maintain revocation lists, key-rotation history, and recovery metadata.
5. `key_id` reuse is an application policy unless constrained by script semantics or covenant logic.

## 4. Suite ID Registry (Normative)

| `suite_id` | Algorithm | Pubkey bytes | Sig bytes | Status v1.1 |
|---|---|---|---|---|
| `0x00` | Sentinel (no-op) | 0 | 0 | ACTIVE — keyless covenants only |
| `0x01` | ML-DSA-87 | 2592 | 4627 (fixed) | ACTIVE |
| `0x02` | SLH-DSA-SHAKE-256f | 64 | 1..49856 | RESERVED (pending VERSION_BITS activation) |
| `0x03`–`0xff` | Undefined | — | — | MUST reject as `TX_ERR_SIG_ALG_INVALID` |

`suite_id = 0x00` is valid only for inputs spending `CORE_TIMELOCK_V1` outputs.
Using `suite_id = 0x00` for `CORE_P2PK` MUST be rejected as `TX_ERR_SIG_ALG_INVALID`.

`suite_id` is carried in each `WitnessItem` as defined in `RUBIN_L1_CANONICAL_v1.1.md §3.1`.
`address_version` and `suite_id` are distinct namespaces but numerically aligned for v1.1.

## 5. Error Semantics

1. Unsupported key or algorithm forms in witness checks map to:
   - `TX_ERR_SIG_ALG_INVALID` (unknown `suite_id`),
   - `TX_ERR_DEPLOYMENT_INACTIVE` (known but inactive `suite_id` due to VERSION_BITS gate),
   - `TX_ERR_SIG_NONCANONICAL` (malformed canonical encoding for known algorithm),
   - `TX_ERR_SIG_INVALID` (cryptographic verification failure).

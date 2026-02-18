# RUBIN L1 Key Management and Address Binding v1.1

Status: CANONICAL-AUXILIARY
Date: 2026-02-18
Scope: Consensus key binding, identity fingerprints, and application-layer key lifecycle

## 1. Consensus-Level Binding

1. L1-consensus validates only:
   - public key bytes,
   - `key_id`,
   - signature over consensus `sighash`.
2. `key_id` is canonicalized as:

   `key_id = SHA3-256(pubkey)`

3. `key_id` is always 32 bytes.
4. Allowed key sizes:
   - ML-DSA-87: public key 2592 bytes, signature 4627 bytes exactly,
   - SLH-DSA-SHAKE-256f: public key 64 bytes, signature 1..`MAX_SLH_DSA_SIG_BYTES` bytes.
5. L1-consensus MUST enforce exact public-key length for the selected `suite_id` and reject malformed encodings.
6. `pubkey` is the canonical public-key wire value for the selected `suite_id` (raw key bytes only).
   The `suite_id` byte and any witness length prefixes are NOT included in `key_id` derivation.

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

### 3.1 Key Rotation (Application Layer)

Because key rotation is not consensus-visible (item 3 above), L1 does not enforce a
"current key" concept. Rotation is an application-layer concern.

The RECOMMENDED mechanism for auditable on-chain key rotation is the **shadow-binding envelope**
defined in `spec/RUBIN_L1_CRYPTO_AGILITY_UPGRADE_v1.1.md §5.1`.

Summary of shadow-binding:
- Publish a `CORE_ANCHOR` output containing:
  ```
  ASCII("RUBIN-KEYMIG-v1") ||
  old_suite_id:u8 || old_pubkey:bytes ||
  new_suite_id:u8 || new_pubkey:bytes ||
  sig_old_over_new || sig_new_over_old
  ```
- `sig_old_over_new`: old key signs `SHA3-256(new_suite_id || new_pubkey)`.
- `sig_new_over_old`: new key signs `SHA3-256(old_suite_id || old_pubkey)`.
- The binding is bidirectional and survives partial compromise assumptions.
- Being an ANCHOR payload it is subject to anchor relay and size policy; it does not alter consensus.

For L2 bridges and sequencers, see `spec/RUBIN_L1_CRYPTO_AGILITY_UPGRADE_v1.1.md §5.2`
(shadow-TX protocol) for migration without halting operations.

**Timelock protection against key-replacement attacks:**

Applications that enforce "only the current key can rotate" SHOULD require a minimum
confirmation depth before treating a shadow-binding as authoritative (e.g., K ≥ 6 blocks).
This prevents an attacker who briefly controls a signing key from substituting a new key
before the legitimate owner can react.

The L1 protocol does not enforce this delay; it is the responsibility of bridges, L2
systems, and wallets that consume the shadow-binding.

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

## 6. Key Rotation and Migration Reference

This section provides a consolidated navigation guide for key lifecycle operations.

| Operation | Mechanism | Spec reference |
|-----------|-----------|----------------|
| Bind key to address | `address_version \|\| key_id` | §2 this file |
| Rotate key on-chain (auditable) | Shadow-binding envelope via `CORE_ANCHOR` | `CRYPTO_AGILITY §5.1` |
| Rotate key for L2 / bridges | Shadow-TX protocol | `CRYPTO_AGILITY §5.2` |
| Migrate algorithm (e.g., ML-DSA → SLH-DSA) | VERSION_BITS deployment activation | `CRYPTO_AGILITY §2` |
| Wrap key for HSM transport | AES-256-KW (RFC 3394) via `rubin_wc_aes_keywrap` | `crypto/wolfcrypt/SHIM_DELIVERABLE_SPEC.md` |
| HSM failover during key operations | HSM state machine | `operational/RUBIN_HSM_FAILOVER_v1.0.md` |

Cross-file dependency note: this file (`KEY_MANAGEMENT`) covers consensus-visible key binding
and entropy requirements. All application-layer lifecycle operations (rotation, revocation,
migration) are in `CRYPTO_AGILITY_UPGRADE`. The split is intentional: consensus remains
minimal; application policy is extensible without consensus changes.

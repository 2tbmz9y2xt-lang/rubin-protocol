# RUBIN L1 P2P Protocol v1.1 (auxiliary)

Status: DRAFT (NON-CONSENSUS)  
Date: 2026-02-16

Purpose: collect P2P transport and message-format details referenced by CANONICAL §15.

Current posture:
- CANONICAL §15 defines minimum required P2P envelope and message families.
- This document is a pre-freeze draft and will be expanded with exact wire formats, negotiation, and error handling before production freeze.

Implementers:
- Use CANONICAL §15 as the normative minimum.
- Treat this file as an integration guide until it is promoted.

## 1) Transport envelope (24-byte prefix)

CANONICAL v1.1 requires a 24-byte fixed prefix:

- `magic` (4 bytes)
- `command` (12 bytes ASCII, zero-padded)
- `payload_length` (4 bytes)
- `checksum` (4 bytes)

Recommended (non-consensus) interpretation:
- `magic`: u32be network magic from the chain-instance profile.
- `payload_length`: u32le.
- `checksum`: first 4 bytes of `SHA3-256(payload_bytes)`.

Receivers SHOULD drop messages whose payload length exceeds `MAX_RELAY_MSG_BYTES`.

## 2) Handshake messages

### 2.1 `version` (required)

Payload fields (recommended):

1. `protocol_version`: u32le
2. `chain_id`: bytes32 (MUST match pinned chain_id for the network)
3. `peer_services`: u64le (bitset; non-consensus)
4. `timestamp`: u64le (UNIX seconds)
5. `nonce`: u64le (anti-self-connect)
6. `user_agent_len`: CompactSize
7. `user_agent`: bytes[user_agent_len] (UTF-8)
8. `start_height`: u32le (best-effort)
9. `relay`: u8 (0/1)

Nodes MUST reject peers whose `chain_id` does not match the locally pinned `chain_id_hex`.

### 2.2 `verack` (required)

Empty payload.

## 3) Liveness messages

### 3.1 `ping` / `pong` (required)

Payload:
- `nonce`: u64le

## 4) Inventory families

### 4.1 `inv` (required)

Payload:
- `count`: CompactSize
- repeated `InvVector` entries

`InvVector` (recommended):
- `inv_type`: u32le
- `hash`: bytes32

Suggested `inv_type` values (non-consensus):
- `1`: txid (witness-free)
- `2`: wtxid (full tx bytes hash)
- `3`: block hash

### 4.2 `getdata` (required)

Same payload format as `inv`.

## 5) Header/Block/Tx messages

### 5.1 `headers` (required)

Payload:
- `count`: CompactSize
- repeated `BlockHeaderBytes` (as defined in CANONICAL §5.1)

### 5.2 `block` / `tx` (required)

Payload:
- `block`: `BlockBytes` (CANONICAL wire encodings)
- `tx`: `TxBytes` (CANONICAL wire encoding including witness section)

## 6) Light-client helpers

### 6.1 `mempool` / `getmempool` (required by CANONICAL §15.9)

This message family is non-consensus and may be restricted by policy.

## 7) Notes for future hardening (pre-freeze)

Before production freeze, this document SHOULD be extended with:
- exact checksum semantics and rejection behavior,
- explicit message-size negotiation and caps,
- peer-address relay rules and anti-eclipse heuristics,
- compact headers format (if used),
- ban-score/rate-limit policy hooks.

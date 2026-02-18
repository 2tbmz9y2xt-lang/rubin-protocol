# RUBIN L1 P2P Protocol v1.1 (auxiliary)

Status: DRAFT (NON-CONSENSUS)
Date: 2026-02-18
Scope: P2P transport and message-format details referenced by CANONICAL §15.

Normative minimum: `spec/RUBIN_L1_CANONICAL_v1.1.md §15`.
This document is an integration guide and pre-freeze draft. It extends §15 with
concrete wire formats, rejection behavior, and hardening guidance.

Implementers MUST implement §15 (normative). The additional sections here are
RECOMMENDED and will be promoted to normative at production freeze.

---

## 1. Transport envelope (24-byte prefix)

CANONICAL §15 requires a 24-byte fixed prefix for every message:

```
magic           : bytes4   (u32be network magic from chain-instance profile)
command         : bytes12  (ASCII command string, zero-padded on the right)
payload_length  : bytes4   (u32le)
checksum        : bytes4   (first 4 bytes of SHA3-256(payload_bytes))
```

### 1.1 Checksum semantics and rejection behavior

- `checksum` is computed as `SHA3-256(payload_bytes)[0:4]` (first 4 bytes, big-endian slice).
- On receive: compute expected checksum from received payload bytes.
- If `checksum_received ≠ checksum_computed`: drop the message and increment sender ban-score by 10.
- Do NOT disconnect on first checksum failure (transient corruption may occur); disconnect after cumulative ban-score ≥ 100.
- Empty payload (e.g., `verack`): `SHA3-256("")[0:4]` = `a7ffc6f8` (first 4 bytes). Receivers MUST compute this correctly; a zero checksum for empty payload is invalid.

### 1.2 Message-size enforcement

- Any message whose `payload_length` field exceeds `MAX_RELAY_MSG_BYTES = 8_388_608` (8 MiB) MUST be rejected.
- On rejection: drop the connection immediately (do not attempt to read payload bytes — attacker controls size field).
- `payload_length = 0` is valid for commands with empty payloads (e.g., `verack`, `getmempool`).
- Recommended: read `payload_length` first; if within bounds, read exactly that many bytes; if mismatch between declared and received bytes, drop connection (ban-score +20).

### 1.3 Unknown commands

- Unknown `command` strings MUST be silently ignored (forward compatibility).
- Do not increment ban-score for unknown commands.

---

## 2. Handshake messages

### 2.1 `version` (required)

Payload fields (wire order, all little-endian unless noted):

| # | Field | Type | Notes |
|---|-------|------|-------|
| 1 | `protocol_version` | u32le | Current: `1` |
| 2 | `chain_id` | bytes32 | MUST match locally pinned `chain_id_hex` |
| 3 | `peer_services` | u64le | Service bitset (see §2.1.1) |
| 4 | `timestamp` | u64le | UNIX seconds (best-effort; not consensus) |
| 5 | `nonce` | u64le | Random per-connection anti-self-connect |
| 6 | `user_agent_len` | CompactSize | |
| 7 | `user_agent` | bytes[user_agent_len] | UTF-8, max 256 bytes |
| 8 | `start_height` | u32le | Best-effort tip height |
| 9 | `relay` | u8 | `1` = accept tx relay; `0` = headers only |

`magic` is in the 24-byte transport prefix only — not duplicated in `version` payload.

Nodes MUST reject peers whose `chain_id ≠ locally_pinned_chain_id` with a `reject` message
and immediate disconnect. This is the primary network-domain separation mechanism.

**Interop test vector — chain_id mismatch (normative):**

Implementations MUST pass the following handshake test before release:

1. Node A (devnet, `chain_id = 9e9878...317`) initiates connection to Node B (testnet, `chain_id = 7dcf48...c00`).
2. Node A sends `version` with its `chain_id`.
3. Node B MUST:
   a. Send `reject` with `ccode = REJECT_INVALID` and `message = "version"`.
   b. Disconnect immediately after sending `reject` (or send `reject` concurrently with close).
   c. NOT send `verack`.
   d. Increment ban-score for the peer's IP by 0 (chain_id mismatch is not a ban-worthy offense — the peer may be on a different legitimate network; log and drop silently after `reject`).
4. Node A MUST NOT retry connection to Node B's address for at least 30 minutes after receiving `REJECT_INVALID` on `version`.

This test MUST be verified across at least Go↔Go and Go↔Rust client pairs before testnet freeze.

#### 2.1.1 `peer_services` bitset (non-consensus)

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `NODE_FULL` | Full block validation and relay |
| 1 | `NODE_LIGHT` | Header-only / SPV mode |
| 2 | `NODE_RETL` | RETL batch relay support |
| 3 | `NODE_BLOOM` | Bloom filter support (deprecated, kept for compat) |

Bits 4–63 are reserved and MUST be `0` in v1.1. Receivers MUST ignore unknown service bits.

### 2.2 `verack` (required)

Empty payload. Sent by each side after successfully receiving and validating the peer's `version`.

### 2.3 `reject` (RECOMMENDED)

Payload:

| Field | Type | Notes |
|-------|------|-------|
| `message_len` | CompactSize | Length of rejected message command |
| `message` | bytes[message_len] | Command string that was rejected |
| `ccode` | u8 | Rejection code (see below) |
| `reason_len` | CompactSize | |
| `reason` | bytes[reason_len] | Human-readable UTF-8 string, max 111 bytes |

Rejection codes:

| Code | Name | Usage |
|------|------|-------|
| `0x01` | `REJECT_MALFORMED` | Message could not be parsed |
| `0x10` | `REJECT_INVALID` | Transaction or block is invalid |
| `0x11` | `REJECT_OBSOLETE` | Node is running an outdated version |
| `0x12` | `REJECT_DUPLICATE` | Already have this tx/block |
| `0x40` | `REJECT_NONSTANDARD` | Rejected by local policy (not consensus) |
| `0x41` | `REJECT_DUST` | Output value below dust threshold |
| `0x42` | `REJECT_INSUFFICIENTFEE` | Fee below min relay fee rate |
| `0x43` | `REJECT_CHECKPOINT` | Conflicts with checkpoint |

> **Deprecation note (normative decision):**
> The `reject` message is retained in RUBIN v1.1 and is NOT deprecated at this time.
>
> *Tradeoff evaluation:* Bitcoin Core deprecated `reject` in v0.20 citing that it revealed
> policy information to potentially adversarial peers, created a false sense of reliability
> (delivery was not guaranteed), and leaked local mempool/policy state. These concerns apply
> equally here. However, RUBIN v1.1 is in a pre-public phase where:
> 1. The peer set is controlled and trusted (private testnet),
> 2. Debugging and interop testing benefit significantly from structured rejection feedback,
> 3. No public adversarial peer network exists yet to exploit policy leakage.
>
> **Decision:** keep `reject` as RECOMMENDED through testnet phase. Re-evaluate before
> public mainnet launch. If retained for mainnet, nodes MUST NOT include sensitive local
> policy details (e.g., exact fee thresholds, UTXO set state) in the `reason` field —
> limit to generic human-readable strings that do not reveal node internals.
>
> Nodes that choose to suppress `reject` messages SHOULD still log them locally.
> Receivers MUST NOT rely on `reject` for consensus-critical decisions.

### 3.1 `ping` / `pong` (required)

Payload: `nonce` (u64le). Pong echoes the ping nonce.

Recommended: if no message received from peer in 20 minutes, send `ping`. If no `pong` within 2 minutes, disconnect.

---

## 4. Inventory families

### 4.1 `inv` (required)

```
count     : CompactSize
entries[] : InvVector
```

`InvVector`:
```
inv_type : u32le
hash     : bytes32
```

`inv_type` values:

| Value | Name | Hash content |
|-------|------|--------------|
| `1` | `MSG_TX` | txid (witness-stripped) |
| `2` | `MSG_WITNESS_TX` | wtxid = SHA3-256(TxBytes including witness) |
| `3` | `MSG_BLOCK` | block hash = SHA3-256(BlockHeaderBytes) |
| `4` | `MSG_FILTERED_BLOCK` | block hash (request with merkle proof) |

### 4.2 `getdata` (required)

Same payload format as `inv`. Used to request specific items by hash.

### 4.3 `notfound` (RECOMMENDED)

Same payload format as `inv`. Sent in response to `getdata` for items not found locally.

---

## 5. Header / Block / Tx messages

### 5.1 `headers` (required)

```
count     : CompactSize
headers[] : BlockHeaderBytes  (CANONICAL §5.1, exactly 80 bytes each)
```

### 5.2 `getheaders` (RECOMMENDED)

```
version       : u32le
hash_count    : CompactSize
block_locator : bytes32[]  (from tip backwards, exponential spacing)
hash_stop     : bytes32    (zero to fetch up to 2000 headers)
```

Response: `headers` with up to 2000 entries.

**Block locator construction (normative):**

Starting from the chain tip, include block hashes at the following heights
(expressed as steps back from the current tip height `h`):

```
steps = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,   # first 12: step 1
         14, 18, 26, 42, 74, 138, 266, ...           # then double each step
         genesis]                                    # always include genesis
```

Formally: the first 12 entries are `h, h-1, h-2, ..., h-11`; then for `k ≥ 12`,
the offset doubles: `h - (12 + 2^(k-12))` until 0 is reached, then append genesis hash.
Include a maximum of 64 hashes (plus genesis). This matches Bitcoin Core's algorithm
and ensures any common ancestor is found within O(log N) round trips.

Receiving node responds starting from the first hash it recognises in the locator.

### 5.3 `block` / `tx` (required)

- `block`: `BlockBytes` (CANONICAL wire encoding)
- `tx`: `TxBytes` (CANONICAL wire encoding including witness section)

### 5.4 Compact headers (RECOMMENDED)

A compact header message reduces bandwidth for SPV clients that only need header chains.

```
command: "compacthdr"
payload:
  count       : CompactSize
  headers[]   : BlockHeaderBytes  (same 80-byte format as §5.1)
```

**Negotiation (normative):**
Compact headers are offered only to peers that have advertised `NODE_LIGHT` service bit
(bit 1 in `peer_services`, §2.1.1). A full node MUST NOT send `compacthdr` unless the
receiving peer has set `NODE_LIGHT` in its `version` message. Light peers SHOULD set
`NODE_LIGHT` and MAY request `compacthdr` explicitly by sending `getheaders` — a full node
that supports compact headers SHOULD respond with `compacthdr` to such peers.

There is no separate capability negotiation handshake; `NODE_LIGHT` in `peer_services`
is the sole signal. Full nodes that do not implement compact headers respond with standard
`headers` to all peers regardless of `NODE_LIGHT`.

---

## 6. Light-client helpers

### 6.1 `mempool` / `getmempool` (required by CANONICAL §15.9)

`mempool`: empty payload. Requests the peer send `inv` entries for its mempool contents.
`getmempool`: same. Both names are accepted for compatibility.

### 6.2 `merkleblock` (RECOMMENDED for SPV)

Provides a filtered block with a partial Merkle proof for requested transactions.

```
block_header  : BlockHeaderBytes  (80 bytes)
total_txns    : u32le
hash_count    : CompactSize
hashes[]      : bytes32           (Merkle tree nodes needed for proof)
flag_byte_cnt : CompactSize
flags[]       : bytes             (bit flags for tree traversal)
```

SPV clients request `merkleblock` via `getdata` with `inv_type = MSG_FILTERED_BLOCK`.
The partial Merkle tree follows the same algorithm as CANONICAL §5.1.1.

### 6.3 `msg_anchor` — anchor commitment for light clients (RECOMMENDED)

Audit recommendation (REC-003): SPV clients verifying `CORE_ANCHOR` commitments need
a way to confirm that a specific `anchor_data` is included in a given block without
downloading the full block.

**Finalized wire format (normative):**

```
command: "anchorproof"
payload:
  block_header    : BlockHeaderBytes  (80 bytes — for PoW and timestamp validation)
  tx_index        : u32le             (index of the anchor tx in the block)
  tx_proof        : MerkleProof       (see below)
  output_index    : u32le             (output index within the tx)
  anchor_data_len : CompactSize       (MUST be ≤ MAX_ANCHOR_PAYLOAD_SIZE)
  anchor_data     : bytes[anchor_data_len]
  flags           : u8                (bit 0: tx_bytes_included; reserved bits MUST be 0)
  tx_bytes_len    : CompactSize       (present only if flags & 0x01)
  tx_bytes        : bytes             (full TxBytes, present only if flags & 0x01)
```

`MerkleProof`:
```
depth       : u8                    (tree depth; 0 = single-tx block)
sibling_cnt : CompactSize           (MUST equal depth)
siblings[]  : bytes32               (sibling hashes from leaf to root, left-to-right)
```

**Verification by light client (normative):**

1. Verify `block_header` satisfies PoW (CANONICAL §6.2) and timestamp rules (§6.5).
2. If `flags & 0x01`: parse `tx_bytes` as `TxBytes`; locate output at `output_index`;
   verify `output.covenant_type = CORE_ANCHOR` and `output.anchor_data` matches `anchor_data`.
   Compute `txid = SHA3-256(TxNoWitnessBytes(tx))`.
3. If `!(flags & 0x01)`: the verifier must obtain the txid externally (e.g., via prior `inv`/`tx`).
4. Compute Merkle path: starting from `txid` as leaf, iteratively hash with each `siblings[i]`
   (left or right determined by `(tx_index >> i) & 1`; 0 = sibling on right, 1 = sibling on left).
5. Verify the computed root equals `block_header.merkle_root`.
6. Optionally verify `anchor_data` application prefix (e.g., `"RUBINv1-htlc-preimage/"` for HTLC proofs).

**Size constraint:** `anchor_data_len` MUST NOT exceed `MAX_ANCHOR_PAYLOAD_SIZE = 65_536`.
Senders SHOULD respect `MAX_ANCHOR_PAYLOAD_RELAY = 1_024` for relay-safe payloads.
Receivers MAY reject `anchorproof` messages where `anchor_data_len > MAX_ANCHOR_PAYLOAD_RELAY`
with ban-score +5 (relay policy, not consensus).

**Rate limiting:** at most 100 `anchorproof` messages per peer per minute; excess → drop + ban-score +2.

### 6.4 `getanchorproof` — light client request for anchor proof (Normative)

Used by light clients to request an `anchorproof` for a specific ANCHOR output.
Required for multi-peer confirmation protocol (LIGHT_CLIENT_SECURITY §3.4).

```
command: "getanchorproof"
payload:
  txid         : bytes32    (txid of the transaction containing the ANCHOR output)
  output_index : u32le      (index of the CORE_ANCHOR output within the tx)
  flags        : u8         (bit 0: request tx_bytes in response; reserved bits MUST be 0)
```

The receiving peer MUST respond with an `anchorproof` message (§6.3) for the requested
outpoint if known, or a `notfound` message otherwise.

Rate limiting: `getanchorproof` shares the rate limit with `anchorproof` (100/peer/minute).

---

## 7. Peer management and DoS hardening

### 7.1 Peer address relay

```
command: "addr"
payload:
  count       : CompactSize  (max 1000 per message)
  entries[]   :
    timestamp : u32le        (UNIX seconds, last-seen)
    services  : u64le        (peer_services bitset, §2.1.1)
    ip        : bytes16      (IPv6; IPv4-mapped for IPv4 addresses)
    port      : u16be
```

Relay rules:
- Forward received addresses to at most 2 randomly selected peers (limit amplification).
- Drop addresses with `timestamp` more than 10 minutes in the future or more than 7 days in the past.
- Do not relay addresses from peers that are not `NODE_FULL` (prevents eclipse via low-cost nodes).
- Rate-limit `addr` processing: accept at most 1000 addresses per peer per 24 hours.
- **IPv6 scope filtering (normative):** MUST drop `addr` entries where `ip` is a link-local address
  (`fe80::/10`), loopback (`::1`), multicast (`ff00::/8`), or unspecified (`::`) before relaying.
  IPv4-mapped link-local (`::ffff:169.254.0.0/112`) MUST also be dropped.
  Rationale: link-local addresses are not globally routable and their relay wastes slots,
  aids local-network snooping, and may confuse address manager bucketing.
  Nodes MAY additionally filter site-local (`fec0::/10`) and unique-local (`fc00::/7`)
  addresses from public relay (operator policy).

Anti-eclipse heuristics:
- Maintain at least 8 outbound connections to diverse /16 subnets.
- Rotate 1 outbound slot per 20 minutes to a freshly sampled address.
- Maintain 2–4 long-lived "anchor" connections (peers that have been reliably connected for > 1 hour) that are not rotated; these resist eclipse by requiring the attacker to eclipse all anchor slots simultaneously.
- If > 50% of outbound peers share the same /16 subnet, evict the excess and resample.

### 7.2 Ban-score and rate limiting

Ban-score accumulates per peer IP. Thresholds:

| Score | Action |
|-------|--------|
| ≥ 100 | Disconnect and ban IP for 24 hours |
| ≥ 50 | Throttle message processing (add 500ms delay per message) |

Score increments (selected events):

| Event | Increment |
|-------|-----------|
| Checksum failure | +10 |
| Oversized message | +20 (+ disconnect) |
| Invalid block | +100 (immediate ban) |
| Invalid tx | +5 |
| `addr` flood (> 1000/24h) | +20 |
| Duplicate `inv` spam (> 1000 unsolicited/min) | +10 |
| Repeated `getdata` for unknown items | +2 |

Ban scores decay at a rate of 1 point per minute (half-life ~100 minutes).

### 7.3 Connection limits

Recommended defaults (non-consensus, operator-adjustable):

```
MAX_OUTBOUND_CONNECTIONS = 8
MAX_INBOUND_CONNECTIONS  = 125
MAX_FEELER_CONNECTIONS   = 2     # short-lived probes for address freshness
```

Nodes SHOULD limit inbound connections per /16 subnet to 4 to resist Sybil eclipse.
Inbound slots beyond `MAX_INBOUND_CONNECTIONS` are rejected with a `reject` message (`REJECT_DUPLICATE`).

---

## 8. Pre-freeze checklist

The following items MUST be resolved before this document is promoted from DRAFT to CANONICAL-AUXILIARY:

- [x] `anchorproof` wire format finalized (§6.3) — `flags` field added for optional tx_bytes, Merkle path direction normative, rate limit 100/min, relay size constraint
- [x] Compact headers negotiation protocol defined (§5.4) — `NODE_LIGHT` service bit is the sole signal; no separate capability negotiation
- [x] `addr` message IPv6 scope: link-local (`fe80::/10`), loopback, multicast, unspecified MUST be filtered; IPv4-mapped link-local also filtered (§7.1)
- [x] `reject` message deprecation decision: retained as RECOMMENDED through testnet phase; re-evaluate before public mainnet; receiver MUST NOT use for consensus decisions (§2.3)
- [x] Exact `getheaders` block locator algorithm: first 12 steps at step 1, then doubling offsets, max 64 hashes + genesis (§5.2)
- [x] Cross-client interop test for `version`/`verack` with chain_id mismatch: normative test vector added (§2.1); MUST pass Go↔Go and Go↔Rust before testnet freeze

All pre-freeze items resolved. This document is ready for promotion to CANONICAL-AUXILIARY
pending cross-client interop test execution.

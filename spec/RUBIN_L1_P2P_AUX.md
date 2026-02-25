# RUBIN L1 P2P (AUX)

Status: non-consensus / auxiliary documentation.

This document describes recommended peer-to-peer behavior and message formats. Deviations MAY affect
network performance and interoperability but MUST NOT affect consensus validity.

## 1. Scope

This document covers the transport envelope for P2P messages and the minimal handshake metadata
needed by RUBIN_COMPACT_BLOCKS.md.

All compact block relay rules — including short transaction identifier derivation, DA mempool
state machine, IBD/warm-up, peer quality scoring, and conformance requirements — are defined in
**RUBIN_COMPACT_BLOCKS.md**.

Implementations MUST follow RUBIN_COMPACT_BLOCKS.md for all relay behaviour.
In case of conflict between this document and RUBIN_COMPACT_BLOCKS.md, RUBIN_COMPACT_BLOCKS.md
takes precedence.

## 2. Transport Envelope (Recommended)

Nodes SHOULD use a fixed 24-byte message envelope:

```text
Envelope {
  magic: bytes4
  command: bytes12   # ASCII, NUL-padded
  payload_len: u32le
  checksum: bytes4   # first 4 bytes of SHA3-256(payload)
}
```

Payload bytes immediately follow the 24-byte header.

Nodes SHOULD enforce a relay cap `MAX_RELAY_MSG_BYTES` (operational default, see RUBIN_L1_CANONICAL.md §4),
and SHOULD disconnect peers that violate framing or checksum rules.

## 3. Handshake Metadata (Minimal)

This section defines fields referenced by RUBIN_COMPACT_BLOCKS.md.

### 3.1 `version`

Command: `version`

Payload:

```text
VersionPayloadV1 {
  protocol_version: u32le
  tx_relay: u8               # 1 = transaction relay expected, 0 = block-relay-only
  pruned_below_height: u64le # 0 = not pruned; otherwise lowest retained height (inclusive)
  da_mempool_size: u32le     # bytes; advertised DA mempool size (0 = unknown/legacy)
}
```

Rules:

- A node MUST send `version` as its first P2P message after establishing a connection.
- A node MUST NOT send other P2P messages (except `version`) before receiving the peer's `version`.
- `tx_relay` MUST be either `0` or `1`. If an unknown value is received, the receiver SHOULD treat it as `0`.
- `pruned_below_height` MUST be `0` for non-pruning nodes.
- `da_mempool_size` is in bytes. `536_870_912` means 512 MiB.

Backward-compatible downgrade:

- If `version.payload_len` is 13 bytes (legacy layout without `da_mempool_size`), the receiver MUST
  parse the message as valid and treat `da_mempool_size = 0` (unknown).
- If `da_mempool_size = 0` or `da_mempool_size < 536_870_912`, the receiver MUST downgrade this peer
  from DA high-bandwidth relay (`sendcmpct_mode = 2`) to at most low-bandwidth (`sendcmpct_mode = 1`).
  If `tx_relay = 0`, the receiver SHOULD use `sendcmpct_mode = 0` for that peer.

Forward-compatibility:

- Future versions MAY append additional fields to `VersionPayloadV1`.
  Implementations MUST ignore trailing bytes they do not understand.

### 3.2 `verack`

Command: `verack`

Payload: empty (`payload_len = 0`)

After receiving a peer's `version`, a node SHOULD respond with `verack`.

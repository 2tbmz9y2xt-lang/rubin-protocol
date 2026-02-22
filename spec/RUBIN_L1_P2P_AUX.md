# RUBIN L1 P2P (AUX)

Status: non-consensus / auxiliary documentation.

This document describes recommended peer-to-peer behavior and message formats. Deviations MAY affect
network performance and interoperability but MUST NOT affect consensus validity.

## 1. Scope

This document covers only the transport envelope for P2P messages.

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

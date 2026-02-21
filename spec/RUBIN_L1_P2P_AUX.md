# RUBIN L1 P2P (AUX)

Status: non-consensus / auxiliary documentation.

This document describes recommended peer-to-peer behavior and message formats. Deviations MAY affect
network performance and interoperability but MUST NOT affect consensus validity.

## 1. Scope

This AUX document currently fixes only one interoperability-critical point:

- Compact block relay MUST derive short transaction identifiers from `WTXID` (not `TXID`).

Rationale: `WTXID` commits to witness bytes (and future DA payload bytes). Using `WTXID` prevents a node
from reconstructing a compact block using only "skeleton" transactions that are missing their full
relay bytes.

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

Nodes SHOULD enforce a relay cap `MAX_RELAY_MSG_BYTES` (operational default), and SHOULD disconnect peers
that violate framing or checksum rules.

## 3. Compact Blocks (Recommended)

### 3.1 ShortID Definition (Normative for Interop)

For a given block header `H` and a compact-block nonce `n` (`u64le`), define:

```text
shortid(T, H, n) = SHA3-256(
    ASCII("RUBINv2-shortid/") ||
    BlockHeaderBytes(H) ||
    u64le(n) ||
    WTXID(T)
)[0..6]     # 6 bytes (48 bits)
```

Where:

- `BlockHeaderBytes(H)` is defined in CANONICAL §10.1.
- `WTXID(T)` is defined in CANONICAL §8.3.

Rule:

- Nodes implementing compact blocks MUST use `shortid` derived from `WTXID`, not `TXID`.

### 3.2 Collision / Missing Transaction Resolution (Recommended)

Compact-block reconstruction is non-consensus and may face shortid collisions or mempool misses.

Nodes SHOULD implement the following behavior:

- If reconstruction fails due to missing transactions or collisions, request the missing transactions
  by index (or by full `tx` relay), and only then validate the full block.

### 3.3 Future DA Payload Note

If a future ruleset allows `da_payload_len > 0`, `WTXID` commits to the DA payload bytes (CANONICAL §8.2).
Using `WTXID`-based shortids ensures compact relay remains correct for DA-carrying transactions.


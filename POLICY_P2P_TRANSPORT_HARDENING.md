# POLICY: P2P Transport Hardening

**Status:** NON-CONSENSUS / production relay policy
**Date:** 2026-04-28
**Applies to:** P2P transport, relay, compact block peers
**Canonical precedence:** `RUBIN_L1_CANONICAL.md` remains the only source of consensus validity.

## 0. Scope Boundary

This document is a protocol-side policy baseline. It does not change consensus
validity, P2P wire format, conformance fixtures, Go implementation, Rust
implementation, or CI behavior.

The envelope shown below describes the bounded transport policy surface. It is
not a new wire format and must not be cited as an implementation change in this
PR.

Authenticated transport remains roadmap work unless separately approved and
implemented in a future slice.

Terms in this policy are guardrail names, not new public API. If an
implementation does not already expose a matching name such as
`MAX_RELAY_MSG_BYTES`, the future implementation slice must bind the policy to
its existing local cap before rollout. Peer scoring and disconnect thresholds
are local relay policy parameters; they are not consensus inputs and are not
specified by this document.

Transport byte caps below distinguish between a frame currently being read and
queued decoded relay work. A node MUST NOT reject a single otherwise-valid frame
only because its payload is larger than the queued-work cap; large-but-allowed
frames must either be streamed or accounted separately from queued decoded
payloads.

## 1. Decision

Production relay implementations MUST enforce bounded transport behavior.

The P2P checksum remains corruption detection only. It is not authentication.

## 2. Envelope

Recommended envelope:

```text
Envelope {
  magic: bytes4
  command: bytes12
  payload_len: u32le
  checksum: bytes4
}
```

Checksum:

```text
checksum = first_4_bytes(SHA3-256(payload))
```

A successful checksum match MUST NOT increase peer trust score.

## 3. Deadlines and Caps

Production defaults:

```text
P2P_HEADER_READ_DEADLINE_MS = 5_000
P2P_PAYLOAD_READ_DEADLINE_MS = 15_000
P2P_MAX_PAYLOAD_READ_BYTES = MAX_RELAY_MSG_BYTES
P2P_MAX_INFLIGHT_MSGS_PER_CONN = 64
P2P_MAX_QUEUED_DECODED_BYTES_PER_CONN = 8_388_608
P2P_MIN_PAYLOAD_PROGRESS_BYTES_PER_SEC = 32_768
```

## 4. Enforcement

Disconnect the peer if:

1. Header read exceeds deadline.
2. Payload read exceeds deadline.
3. Payload progress falls below the minimum rate.
4. Payload exceeds maximum read bytes.
5. Frame checksum validation fails for a received frame.
6. Compact payload is malformed and peer score reaches or exceeds disconnect
   threshold.

A checksum failure is a terminal frame-read error for that connection. It
remains corruption detection only, not adversarial tamper protection.

If queued decoded caps are exceeded, stop admitting more decoded relay work from
the peer until backlog falls below cap. Persistent offenders SHOULD be penalized
and disconnected. This queued-work cap does not lower
`P2P_MAX_PAYLOAD_READ_BYTES`.

## 5. Handshake Rules

A peer SHOULD send `version` first.

Implementations MAY accept an early `verack` before receiving the peer's
`version`, but MUST NOT mark the handshake complete or apply any
`version`-gated state changes until that peer's `version` has been received and
validated.

Other non-`version` messages received before the peer's `version` MUST NOT
complete the handshake and SHOULD be ignored or treated as a local transport
policy violation.

`version.payload_len` MUST be exactly 89 bytes.

Reject or disconnect if:

1. `chain_id` differs.
2. `genesis_hash` differs.
3. `protocol_version` differs by more than 1.
4. `tx_relay` is malformed and cannot be normalized.

## 6. Compact Relay Payloads

Malformed compact payloads MUST NOT affect consensus validity.

Treat these as malformed relay inputs:

- truncated payload;
- non-minimal CompactSize;
- impossible lengths;
- duplicate prefilled indices;
- invalid transaction index mappings;
- unsupported compact relay wire version.

Malformed relay inputs MAY affect peer score.

## 7. Authenticated Transport Roadmap

Authenticated transport is roadmap work.

Any authenticated profile MUST:

1. Keep consensus payload bytes unchanged.
2. Define capability negotiation.
3. Define anti-downgrade behavior.
4. Define replay handling.
5. Bind peer identity.
6. Publish conformance vectors.
7. Preserve bounded fallback during migration.

## 8. Telemetry

Nodes SHOULD expose:

The names below are policy counter suffixes. Implementations MAY namespace them
for their telemetry backend, for example by adding the existing `rubin_node_`
Prometheus prefix.

```text
p2p_header_timeout_total
p2p_payload_timeout_total
p2p_payload_progress_violation_total
p2p_payload_oversize_total
p2p_checksum_fail_total
p2p_inflight_msg_cap_hit_total
p2p_queued_decoded_byte_cap_hit_total
p2p_protocol_version_disconnect_total
p2p_chain_id_mismatch_total
p2p_genesis_hash_mismatch_total
p2p_malformed_compact_payload_total
```

## 9. Security Wording

Operator-facing output MUST NOT describe the 4-byte checksum as:

- authentication;
- identity proof;
- anti-replay;
- anti-spoofing;
- encrypted transport;
- MITM protection.

Correct wording:

```text
4-byte checksum provides transport corruption detection only.
```

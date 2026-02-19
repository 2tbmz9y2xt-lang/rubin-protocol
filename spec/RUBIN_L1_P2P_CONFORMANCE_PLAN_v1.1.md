# RUBIN L1 P2P Conformance Plan v1.1 (auxiliary)

Status: DRAFT (NON-CONSENSUS)
Date: 2026-02-19
Scope: Conformance fixture schema and runner plan for P2P interoperability.

This document is a plan only. It does not add consensus rules.

Authoritative protocol reference:

- `spec/RUBIN_L1_CANONICAL_v1.1.md §15` (normative minimum)
- `spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md` (auxiliary wire formats / policy profile)

---

## 1. Goal

Create deterministic, cross-client P2P interoperability checks (Go <-> Rust) that:

- validate wire parsing of the 24-byte transport envelope,
- validate handshake behavior (`version` / `verack` / optional `reject`),
- validate enforcement of parsing caps (count/len fields) and oversized message handling,
- validate light-client helper message formats (`anchorproof` / `getanchorproof`),
- validate peer-management policy invariants that are explicitly normative in the P2P profile
  (e.g., IPv6 scope filtering for `addr`).

These checks are non-consensus. They exist to prevent network-level divergence and DoS regressions.

---

## 2. Proposed fixture format (YAML)

Location (planned):

- `conformance/fixtures/CV-P2P.yml`

Top-level shape:

```
version: "1.1"
gate: CV-P2P
status: DRAFT
description: >
  Cross-client P2P interoperability and policy profile checks (non-consensus).

tests:
  - id: P2P-ENV-01
    title: "REJECT: oversized payload_length without reading payload"
    kind: envelope
    transcript:
      - action: connect
      - action: send_raw
        bytes_hex: "<24-byte-prefix-with-payload_length>MAX_RELAY_MSG_BYTES</...>"
      - expect: disconnect

  - id: P2P-HS-01
    title: "REJECT: chain_id mismatch (version -> reject invalid -> close)"
    kind: handshake
    transcript:
      - action: connect
      - action: send
        command: version
        payload:
          protocol_version: 1
          chain_id_hex: "<wrong chain_id>"
          ...
      - expect: send
        command: reject
        payload:
          ccode: REJECT_INVALID
          message: "version"
      - expect: disconnect
```

Notes:

- `transcript` is intentionally abstract: it can be compiled to raw bytes for injection into a
  test socket, or interpreted by a client-side test harness.
- `send_raw.bytes_hex` allows testing checksum errors and non-minimal `CompactSize` encodings.

---

## 3. Proposed runner design (Python)

Location (planned):

- `conformance/runner/run_cv_p2p.py`

Minimum functionality:

1. Spawn two processes (Rust node and Go node) in a deterministic "p2p-test" mode.
2. Bind each to localhost-only ports (no real network discovery).
3. Execute transcript steps from the fixture and validate expected observable events:
   - socket close / timeout
   - optional `reject` response bytes (if enabled in the client)
   - optional ban-score counter changes (if exposed in test mode)

Recommended client CLI interface (planned; non-breaking to existing node commands):

- `rubin-node p2p-test --listen <addr> --chain-profile <profile.md> --script-json <path>`

Where `--script-json` is the compiled transcript for a single test case.

---

## 4. Initial test inventory (minimum)

Envelope:

- oversized `payload_length` reject-without-read
- checksum mismatch (drop + ban-score +10)
- unknown command ignore

Handshake:

- chain_id mismatch (normative vector from P2P_PROTOCOL §2.1)
- user_agent_len > 256 (malformed)
- early non-handshake message before READY (ban-score +5 each)

Caps:

- inv.count > 50_000 (malformed)
- headers.count > 2_000 (malformed)
- getheaders.hash_count > 64 (malformed)
- addr.count > 1_000 (malformed)

Light-client helpers:

- anchorproof: sibling_cnt != depth (malformed)
- anchorproof: depth > 32 (malformed)
- getanchorproof: reserved flags bits set (malformed)

Peer management:

- addr relay drops IPv6 link-local (`fe80::/10`) and IPv4-mapped link-local (`::ffff:169.254.0.0/112`)

---

## 5. Non-goals

- This plan does not define encrypted transport / hybrid key exchange.
  If added later, it should be validated as a separate gate (e.g., CV-P2P-CRYPTO) and remain non-consensus.


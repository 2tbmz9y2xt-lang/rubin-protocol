# RUBIN L1 Light Client Security: Checkpoints and AnchorProof Confirmation v1.1

Status: CANONICAL-AUXILIARY
Date: 2026-02-18
Scope: Light client checkpoint protocol, anchorproof multi-peer confirmation, eclipse
       resistance for embedded and mobile clients.
Required before: mainnet launch (see FREEZE_TRANSITION_POLICY §4)
Ref: CANONICAL §14.2, P2P_PROTOCOL §6.3

---

## 1. Overview

RUBIN light clients verify chain state using compact headers and `anchorproof` messages
without downloading full blocks. This creates an eclipse attack surface absent from full
nodes: an adversary controlling all peer connections can feed a fraudulent high-PoW header
chain and fabricated `anchorproof` messages, enabling HTLC theft and unauthorized key
rotation (CANONICAL §14.2.5).

This document specifies two normative mechanisms to bound that risk:

1. **Checkpoint protocol** — hard-coded block hashes at known heights that bound the
   adversary's ability to present a forked history.
2. **AnchorProof multi-peer confirmation** — a mandatory quorum requirement before a
   light client acts on an `anchorproof` for high-value operations.

Both mechanisms are required to be implemented before mainnet launch.

---

## 2. Checkpoint Protocol (Normative)

### 2.1 Checkpoint record format

A checkpoint is a triplet:

```
Checkpoint = {
  height      : u32le       // block height
  block_hash  : bytes32     // SHA3-256(BlockHeaderBytes) at this height
  timestamp   : u64le       // header.timestamp at this height (informational, not verified)
}
```

`block_hash` is the sole security-critical field. `timestamp` is informational only and
MUST NOT be used as a trust anchor.

Checkpoints MUST be serialized in the canonical wire order above for any persistence or
transport use. No signature over individual checkpoint records is required (trust derives
from build-time embedding; see §2.3).

### 2.2 Checkpoint validation rules (Normative)

When a light client processes a header chain:

1. For each header at height `h` where a checkpoint `C` exists with `C.height = h`:
   - Compute `block_hash(B_h) = SHA3-256(BlockHeaderBytes(B_h))`.
   - If `block_hash(B_h) ≠ C.block_hash`, reject the entire chain as
     `ECLIPSE_ERR_CHECKPOINT_MISMATCH` and disconnect all peers that served it.
2. A chain that diverges from any checkpoint MUST NOT be considered a valid best chain,
   regardless of claimed cumulative work.
3. Checkpoint evaluation MUST occur before chain selection (CANONICAL §6.6). A higher-work
   chain that conflicts with a checkpoint is invalid and MUST be rejected.
4. Checkpoints MUST be applied to all header sources: P2P peers, compact header responses
   (`getheaders` / compact headers), and any out-of-band header feeds.

### 2.3 Checkpoint distribution (Normative)

Checkpoints MUST be distributed by one of the following methods, in order of preference:

**Method A — Build-time embedding (REQUIRED for mainnet clients):**
Checkpoints are hard-coded in client source code as a static array, compiled into the
binary. The build process is reproducible and the source code is public. Users can verify
checkpoint correctness by independently querying the chain.

Build-time checkpoints MUST satisfy:
- `height ≥ COINBASE_MATURITY` (100) to avoid orphan-risk blocks.
- `height ≤ chain_height_at_build_time − COINBASE_MATURITY` to avoid reorg-risk.
- At least one checkpoint per major release. For testnet: at least one per epoch
  (`SUBSIDY_HALVING_INTERVAL = 210_000` blocks). For mainnet: at least one per year
  of expected block production.

**Method B — Operator-signed checkpoint file (OPTIONAL, testnet only):**
A JSON file signed by the trusted operator key (SLH-DSA-SHAKE-256f, `suite_id = 0x02`).

```json
{
  "version": 1,
  "chain_id_hex": "<chain_id as hex>",
  "checkpoints": [
    { "height": 210000, "block_hash_hex": "<hex>", "timestamp": 1700000000 }
  ],
  "operator_pubkey_hex": "<SLH-DSA pubkey, 64 bytes, hex>",
  "signature_hex": "<SLH-DSA sig over SHA3-256(canonical_payload), hex>"
}
```

`canonical_payload` for signing:
```
ASCII("RUBIN-CHECKPOINT-v1") || chain_id || u32le(count) ||
for each checkpoint in order: u32le(height) || block_hash
```

`timestamp` is NOT included in the signed payload. Light clients MUST ignore `timestamp`
for security decisions.

Clients consuming Method B files MUST:
1. Verify `chain_id_hex` matches their configured chain identity.
2. Verify the `signature_hex` over `SHA3-256(canonical_payload)` using
   `operator_pubkey_hex` and SLH-DSA-SHAKE-256f.
3. Reject the file if signature verification fails.
4. Apply the same validation rules from §2.2 to all checkpoints in the file.

Method B MUST NOT be used for mainnet clients. Build-time embedding (Method A) is
the only accepted distribution method for mainnet.

### 2.4 Checkpoint hygiene (Normative)

- A genesis checkpoint at `height = 0` is permitted and RECOMMENDED to bind chain identity.
  It is not subject to the `COINBASE_MATURITY`-buffer requirement.
- For non-genesis checkpoints (`height > 0`), checkpoints MUST be at heights with
  `COINBASE_MATURITY`-block buffer from the current tip, to guard against reorg-risk at
  the checkpoint itself.
- For non-genesis checkpoints (`height > 0`), light clients MUST NOT use a checkpoint
  height that is within `COINBASE_MATURITY` blocks of the checkpoint-publisher's reported
  tip at time of publishing.
- After a checkpoint mismatch (`ECLIPSE_ERR_CHECKPOINT_MISMATCH`), the client MUST:
  1. Disconnect and ban (ban-score MAX) all peers that served the conflicting chain.
  2. Emit a user-visible alert with the conflicting `block_hash` and `height`.
  3. Refuse to process new headers until at least one honest peer is reconnected and
     serves a chain consistent with all checkpoints.

### 2.5 Checkpoint gap limit (Normative)

Light clients MUST reject a new best-chain candidate if:

```
gap = height(candidate_tip) − height(latest_checkpoint)
gap > MAX_CHECKPOINT_GAP
```

where `MAX_CHECKPOINT_GAP = 100_800` (approximately 2 years at 10-minute blocks).

A gap exceeding this limit indicates either the client's checkpoints are severely stale
(requiring a client update) or an eclipse attempt presenting a very long fabricated chain.
In either case, the client MUST alert the user and refuse to confirm any transactions
until updated checkpoints are available.

---

## 3. AnchorProof Multi-Peer Confirmation (Normative)

### 3.1 Scope

Multi-peer confirmation is REQUIRED for any `anchorproof` used to trigger:

- HTLC preimage acceptance (release of funds or commitment state transition).
- Key-migration shadow-binding acceptance (CRYPTO_AGILITY §5.1).
- Any application-layer decision with irreversible on-chain consequence.

Multi-peer confirmation is RECOMMENDED for all other `anchorproof` uses.

### 3.2 Confirmation quorum requirement

For a high-value `anchorproof` to be accepted by a light client:

1. The client MUST request the same `anchorproof` from at least
   `MIN_ANCHORPROOF_PEERS = 2` independent peers.
2. "Independent" means: peers from different `/16` IPv4 subnets (or different `/32`
   IPv6 prefixes), or peers behind different Tor circuits if using Tor transport.
3. All responses MUST agree on:
   - `block_hash` (SHA3-256 of the `block_header` bytes in the response).
   - `merkle_root` (as present in `block_header.merkle_root`).
   - `anchor_data` (byte-for-byte identical).
4. If any peer returns a different `block_hash`, `merkle_root`, or `anchor_data` for the
   same requested outpoint, the client MUST:
   - Classify the response as `ANCHORPROOF_CONFLICT`.
   - Emit a user-visible alert.
   - Not act on either response until the conflict is resolved (e.g., by querying
     additional peers or waiting for checkpoint confirmation of the relevant block).

### 3.3 AnchorProof request procedure (Normative)

A light client implementing multi-peer confirmation MUST:

1. Select `MIN_ANCHORPROOF_PEERS` peers from distinct `/16` subnets.
2. Send `getanchorproof` (see §3.4) to each selected peer simultaneously.
3. Apply a timeout of `ANCHORPROOF_TIMEOUT = 30` seconds per peer.
4. Collect responses. If fewer than `MIN_ANCHORPROOF_PEERS` responses arrive within the
   timeout, retry with replacement peers up to `ANCHORPROOF_MAX_RETRIES = 3` times.
5. Verify each response independently:
   a. Validate `block_header` PoW (CANONICAL §6.2).
   b. Validate `block_header.timestamp` (CANONICAL §6.5).
   c. Verify the checkpoint chain covers the `block_header` height (§2.2).
   d. Verify Merkle proof per P2P_PROTOCOL §6.3 verification procedure.
   e. Verify `anchor_data` application prefix if applicable (e.g., HTLC prefix check).
6. Compare all verified responses for quorum (§3.2 rule 3).
7. Accept only if all `MIN_ANCHORPROOF_PEERS` responses pass verification AND agree.

### 3.4 `getanchorproof` wire message (Normative)

```
command: "getanchorproof"
payload:
  txid         : bytes32    (txid of the transaction containing the ANCHOR output)
  output_index : u32le      (index of the CORE_ANCHOR output within the tx)
  flags        : u8         (bit 0: request tx_bytes in response; reserved bits MUST be 0)
```

The peer MUST respond with an `anchorproof` message (P2P_PROTOCOL §6.3) for the
requested outpoint, or with a `notfound` message if the outpoint is unknown.

Rate limiting: `getanchorproof` requests are subject to the same rate limit as
`anchorproof` responses: 100 per peer per minute.

### 3.5 Confirmation depth requirement (Normative)

Before accepting an `anchorproof` for any high-value operation:

```
confirmation_depth = height(current_tip) − height(anchorproof_block) + 1
```

The client MUST require `confirmation_depth ≥ MIN_ANCHORPROOF_DEPTH = 6`.

This bound is cross-referenced in CANONICAL §14.2.5. The 6-block minimum provides
probabilistic finality against reorgs at standard hashrate (< 0.1% reorg probability
for a 6-deep block, per standard Bitcoin-model analysis). High-value deployments MAY
increase this bound.

---

## 4. Constants (Normative)

| Constant | Value | Description |
|----------|-------|-------------|
| `MIN_ANCHORPROOF_PEERS` | 2 | Minimum independent peers for anchorproof quorum |
| `ANCHORPROOF_TIMEOUT` | 30s | Per-peer timeout for anchorproof response |
| `ANCHORPROOF_MAX_RETRIES` | 3 | Max retry rounds with replacement peers |
| `MIN_ANCHORPROOF_DEPTH` | 6 | Minimum confirmation depth for high-value anchorproof |
| `MAX_CHECKPOINT_GAP` | 100_800 | Max blocks between latest checkpoint and new tip |
| `CHECKPOINT_MIN_DEPTH` | `COINBASE_MATURITY` (100) | Min depth from tip at publish time |

---

## 5. Error Codes (Normative)

| Code | Name | Description |
|------|------|-------------|
| `ECLIPSE_ERR_CHECKPOINT_MISMATCH` | Checkpoint mismatch | Received header conflicts with hard-coded checkpoint |
| `ECLIPSE_ERR_CHECKPOINT_GAP` | Checkpoint gap exceeded | Tip is more than `MAX_CHECKPOINT_GAP` ahead of latest checkpoint |
| `ANCHORPROOF_CONFLICT` | AnchorProof quorum conflict | Two peers returned different anchorproof data for the same outpoint |
| `ANCHORPROOF_TIMEOUT` | AnchorProof timeout | Insufficient peer responses within timeout |
| `ANCHORPROOF_DEPTH_INSUFFICIENT` | Depth insufficient | Block depth < `MIN_ANCHORPROOF_DEPTH` |

---

## 6. Interaction with §14.2 Mitigations

This document normatively specifies items 2 and 6 from CANONICAL §14.2.4:

- Item 2 (Checkpoints): fully specified by §2 above.
- Item 6 (AnchorProof multi-path confirmation): fully specified by §3 above.

Items 1, 3, 4, 5, 7 remain non-normative operational recommendations in CANONICAL §14.2.4.
Their normative specification (if required) is deferred to a future revision.

---

## 7. Conformance

### 7.1 Implementation requirements

A conforming light client implementation MUST:

1. Hard-code at least one checkpoint for each supported chain (testnet / mainnet) — Method A (§2.3).
2. Reject any header chain that conflicts with a checkpoint — §2.2 rule 1.
3. Enforce `MAX_CHECKPOINT_GAP` — §2.5.
4. For HTLC preimage acceptance and key-migration operations: use `MIN_ANCHORPROOF_PEERS`
   independent peers and require quorum — §3.2.
5. Enforce `MIN_ANCHORPROOF_DEPTH ≥ 6` for high-value operations — §3.5.
6. Implement `getanchorproof` message — §3.4.

### 7.2 Testnet checkpoint (initial value)

The testnet checkpoint at height 0 is derived from
`spec/RUBIN_L1_CHAIN_INSTANCE_PROFILE_TESTNET_v1.1.md`:

```
chain_id_hex: "7dcf48a266788491e77bbb7b9c97ad6a2c89b882293dfaf3bdebeec62548cc00"
checkpoints:
  - height: 0
    block_hash_hex: "2577dca80125dacfde2f0ed90a121442c857accb11176b0f0d5d35ab03056388"
    timestamp: 1700000000
```

If testnet genesis bytes are replaced, this checkpoint MUST be updated accordingly.
Mainnet checkpoints: populated at mainnet genesis ceremony (Q-017).

---

## 8. Security Considerations

- **Checkpoint trust model:** build-time checkpoints shift trust to the build process
  and source code review, not to any online oracle. This is the same trust model as
  Bitcoin Core's hard-coded checkpoints.
- **Checkpoint stale risk:** if a client's checkpoints are older than `MAX_CHECKPOINT_GAP`
  blocks, the client will alert and refuse to process headers. This prevents silent
  degradation to unprotected operation.
- **Quorum under eclipse:** `MIN_ANCHORPROOF_PEERS = 2` with `/16` subnet diversity requires
  an adversary to control nodes in at least 2 distinct subnets simultaneously — significantly
  harder than controlling a single AS. For high-risk deployments, operators MAY increase
  `MIN_ANCHORPROOF_PEERS` to 3 or more.
- **Tor transport:** light clients on Tor MUST use distinct circuits (not the same exit node)
  for each peer counted toward the quorum.
- **Checkpoint signing (Method B):** the operator signature covers `chain_id` explicitly,
  preventing cross-chain replay of checkpoint files.

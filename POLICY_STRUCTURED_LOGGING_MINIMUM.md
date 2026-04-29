# POLICY: Minimum Structured Logging Contract

**Status:** NON-CONSENSUS / operational policy
**Date:** 2026-04-29
**Revision:** post-review rc3 aligned with `rubin-spec` PR #245 / issue #242
**Applies to:** Go node, Rust node, devnet observability, operator logs
**Canonical precedence:** `spec/RUBIN_L1_CANONICAL.md` remains the only source of consensus validity.

## 0. Scope Boundary

This document is a protocol-side policy baseline for structured logging. It does
not change consensus validity, wire format, conformance fixtures, Go
implementation, Rust implementation, metrics code, or CI behavior.

This file does not claim current Go or Rust event emission. A future
implementation slice that claims compliance with this policy must bind the names
and fields here to that implementation's logging backend.

No concrete logging framework is selected by this policy. Framework selection,
JSON schema tooling, runtime configuration, and validator work require separate
controller-approved implementation slices.

## 0.1 Source Taxonomy

The event taxonomy is aligned with the merged `rubin-spec` structured logging
contract:

```text
spec/RUBIN_STRUCTURED_LOGGING_CONTRACT.md
rubin-spec PR #245 / issue #242
```

As in other root policy documents in this repository, `spec/...` paths refer to
the private `rubin-spec` repository; see `SPEC_LOCATION.md` for the cross-repo
convention.

The rc3 archive source for this policy is:

```text
POLICY_STRUCTURED_LOGGING_MINIMUM.md
sha256 5054e8b9803b71dc3df428efae14bd135345d6707828663476d63a28eb8215a2
```

## 1. Decision

Structured logging is the minimum operator evidence surface for future Rubin
node observability work. When a node implementation adds structured logging, its
default operator log format SHOULD be machine-parseable JSON Lines unless a later
approved profile supersedes this policy.

This policy fixes the minimum common schema, event classes, log levels, required
event families, redaction rules, and metrics bridge. It does not select an
implementation framework and it does not make any current runtime logging claim.

## 2. Common Event Schema

A structured log event SHOULD be an object with the following required fields:

| Field | Type | Requirement |
|---|---|---|
| `timestamp` | RFC3339 UTC string | Event time. |
| `level` | enum string | One of `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`. |
| `class` | enum string | One of the event classes in §3. |
| `event` | string | Fully-qualified event name, for example `mempool.tx_rejected`. |
| `message` | string | Bounded human-readable summary. |
| `details` | object | Event-specific structured fields. Empty object allowed. |

Recommended bounded context fields:

| Field | Type | Requirement |
|---|---|---|
| `chain_id` | hex string or `null` | Chain identity when relevant. |
| `best_height` | unsigned integer or `null` | Local best-chain height at event time. |
| `block_hash` | hex string or `null` | Relevant block hash when bounded and useful. |
| `txid` | hex string or `null` | Relevant transaction id when bounded and useful. |
| `wtxid` | hex string or `null` | Relevant witness transaction id when bounded and useful. |
| `peer_id` | string or `null` | Peer identifier when bounded and useful. |
| `policy_version` | integer or string or `null` | Local policy version or profile identifier. |

`txid`, `wtxid`, outpoints, peer IDs, raw error strings, and request IDs are
high-cardinality values. They MAY appear in structured logs when needed for
operator diagnosis, subject to redaction and retention policy, but they MUST NOT
be used as metric labels or as unbounded aggregation keys.

## 3. Event Classes

Allowed event classes:

```text
consensus
p2p
mempool
compact
da
crypto
storage
rpc
mining
node
governance
```

The event `class` field MUST be the lowercase class name. The `event` field MUST
use the class prefix followed by a dot and the event name.

## 4. Log Levels

| Level | Usage |
|---|---|
| `ERROR` | Unrecoverable failure, data corruption, or consensus-critical failure requiring operator intervention. |
| `WARN` | Degraded operation, peer abuse, threshold breach, unsafe configuration, or security-relevant anomaly. |
| `INFO` | Normal lifecycle and important state changes suitable for default production logs. |
| `DEBUG` | Diagnostic details safe for devnet or targeted operator troubleshooting. |
| `TRACE` | Wire-level or backend-debug diagnostics; disabled in production by default. |

`TRACE` MUST NOT be required for normal operational evidence. Any future raw wire
or payload diagnostic mode must be explicitly disabled in production defaults and
must still follow the redaction rules in §6.

## 5. Mandatory Event Families

The names below are the minimum taxonomy. A client that implements the relevant
subsystem and claims structured logging compliance MUST use these event names for
the corresponding events. This section is taxonomy only, not a current-emission
claim for any client.

### 5.1 Node

```text
node.start
node.stop
node.config_loaded
node.unsafe_config_enabled
node.genesis_loaded
node.chain_id_verified
```

### 5.2 Consensus

```text
consensus.block_validated
consensus.block_rejected
consensus.tx_rejected
consensus.reorg_detected
consensus.tip_updated
```

### 5.3 Mempool

This event family MUST match the `rubin-spec` taxonomy from
`spec/RUBIN_STRUCTURED_LOGGING_CONTRACT.md`.

```text
mempool.tx_admitted
mempool.tx_rejected
mempool.tx_evicted
mempool.conflict_rejected
mempool.reorg_requeue
mempool.policy_changed
```

These are structured log event names, not metric counters. They do not add
labels to mempool metrics and they do not claim current Go or Rust event
emission.

### 5.4 P2P

```text
p2p.peer_connected
p2p.peer_disconnected
p2p.version_received
p2p.version_rejected
p2p.transport_timeout
p2p.malformed_payload
```

### 5.5 Compact and DA

```text
compact.reconstruction_ok
compact.reconstruction_miss
compact.getblocktxn_sent
compact.full_block_fallback
compact.shortid_collision

da.set_staged
da.set_complete
da.orphan_admitted
da.orphan_expired
da.duplicate_commit_rejected
da.storm_mode_enter
da.storm_mode_exit
```

Compact relay and DA relay readiness are not claimed by this policy. These names
are reserved for future implementation slices that already own those runtime
surfaces.

### 5.6 Crypto

```text
crypto.backend_initialized
crypto.fips_preflight_ok
crypto.fips_preflight_failed
crypto.verify_failed
```

Crypto events MUST NOT expose secret material. FIPS/provider wording in logs must
remain consistent with the applicable crypto backend profile.

## 6. Redaction Rules

Structured logs MUST NOT include:

- secret key material;
- seed material;
- mnemonic material;
- raw entropy;
- private-key file contents;
- full witness bytes at `INFO`, `WARN`, or `ERROR`;
- full DA payload bytes at `INFO`, `WARN`, or `ERROR`;
- controller private evidence;
- environment variables containing credentials or tokens;
- unbounded raw error strings as metric labels or aggregation keys.

Structured logs MAY include bounded public identifiers and public policy facts:

- `txid` or `wtxid` when needed for operator diagnosis;
- `key_id` without corresponding secret material;
- `chain_id` or `genesis_hash`;
- bounded policy names and public error codes;
- byte counts;
- peer IDs when the implementation has a retention and cardinality policy.

A log message MUST NOT require full transaction bytes, full witness bytes, full
DA payload bytes, or private evidence to prove the event class. Store bounded
reason codes in `details` instead of embedding arbitrary payloads in `message`.

## 7. Metrics Bridge

Structured logs and metrics are separate operator surfaces. A structured log
event MUST NOT be treated as a metric counter by itself, and a metric counter
MUST NOT inherit unbounded labels from log fields.

The logging or metrics layer must preserve operator visibility for the telemetry
surfaces already identified by the spec taxonomy, including:

```text
shortid_collision_count
shortid_collision_blocks
shortid_collision_peers
da_mempool_fill_pct
orphan_pool_fill_pct
miss_rate_bytes_L1
miss_rate_bytes_DA
partial_set_count
partial_set_age_p95
prefetch_latency_ms
orphan_recovery_success_rate
peer_quality_score
locktime_zero_pct
da_fill_warning_pct
checksum_collision_incidents
```

It must also preserve the standard mempool metric families documented by
`spec/RUBIN_STRUCTURED_LOGGING_CONTRACT.md` §2.3 and
`spec/RUBIN_MEMPOOL_POLICY.md`. Those metrics retain their own bounded-label
rules; the mempool structured log event names in §5.3 do not redefine them.

## 8. Example Rejection Event

The example below illustrates shape only. It is not evidence that runtime logging
exists today.

```json
{
  "timestamp": "2026-04-29T00:00:00Z",
  "level": "INFO",
  "class": "mempool",
  "event": "mempool.tx_rejected",
  "message": "transaction rejected by relay policy",
  "chain_id": "88f8a9acdeeb902e27aa2fdcb8c46ecf818bf68dec5273ec1bcc5084e2333103",
  "best_height": 120,
  "block_hash": null,
  "txid": null,
  "wtxid": null,
  "peer_id": null,
  "policy_version": 1,
  "details": {
    "reason": "CORE_EXT_PREACTIVATION",
    "consensus_validity_changed": false
  }
}
```

## 9. Review Triggers

Review this policy when:

1. A Go or Rust structured logging framework is proposed.
2. The first runtime implementation of these event names is proposed.
3. A devnet metrics dashboard is implemented.
4. RPC observability endpoints are added or changed.
5. A new mandatory telemetry field is added.
6. A security review finds missing event evidence or redaction drift.

## 10. Relationship to Other Artifacts

| Artifact | Relationship |
|---|---|
| `spec/RUBIN_STRUCTURED_LOGGING_CONTRACT.md` | Parent taxonomy source merged via `rubin-spec` PR #245 / issue #242. |
| `spec/RUBIN_MEMPOOL_POLICY.md` | Standard mempool metrics and bounded-label constraints. |
| `spec/RUBIN_COMPACT_BLOCKS.md` §13, §14 | Compact relay telemetry and peer quality score sources. |
| `spec/RUBIN_NETWORK_PARAMS.md` | Network telemetry thresholds. |
| `spec/RUBIN_L1_CANONICAL.md` §23.2 | Feature activation telemetry source. |
| `SPEC_LOCATION.md` | Cross-repo convention for `spec/...` references. |

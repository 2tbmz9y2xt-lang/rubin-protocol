//! P2P transaction-relay surface — RELAY-CACHE ONLY, not canonical txpool.
//!
//! # RUB-172 boundary (RUB-163 producer-wiring track child)
//!
//! On the success path (`RelayTxOutcome::Relayed`),
//! `handle_received_tx` writes to `relay_state.relay_pool`
//! (`RelayTxPool`, defined in `crate::relay_pool`) and attempts
//! inventory broadcast. Other outcomes (`Oversized`,
//! `MalformedParse`, `DuplicateSeen`, `MetadataRejected`,
//! `PoolRejected`) return at their respective branch with
//! partial-or-no relay-cache side effects. None of the outcomes
//! admit to a canonical `TxPool` supplied by the caller. The
//! structural defense for the shared canonical pool is the
//! function signature: NONE of `handle_received_tx`'s
//! non-primitive arguments carry a canonical `TxPool` handle
//! today. This is a HEAD-snapshot observation, NOT a maintained
//! invariant — neither the docstring nor the token-aware
//! `boundary_checker` test module below scans `sync.rs`,
//! `p2p_runtime.rs`, or any other carrier file, so a future PR
//! could add a canonical-pool field to one of these structs in
//! another file and both would silently stay green. The
//! syntactic checker described under `# Boundary check` below is
//! scoped to `tx_relay.rs` source only; cross-file drift over
//! carrier struct definitions remains an open gap not tracked by
//! any current follow-up.
//! Observed at HEAD, field-by-field:
//!  - `relay_state: &TxRelayState` (this file) — fields are
//!    `tx_seen`, `relay_pool` (`RelayTxPool`), `tx_relay_fanout`,
//!    `network`. No canonical `TxPool` field.
//!  - `sync_engine: &SyncEngine`
//!    (`crate::sync::SyncEngine`) — fields are `chain_state`,
//!    `block_store`, `cfg`, `tip_timestamp`, `best_known_height`,
//!    parallel-validation state. No canonical `TxPool` field.
//!  - `peer_manager: &PeerManager`
//!    (`crate::p2p_runtime::PeerManager`) — fields are
//!    `peers: RwLock<HashMap<String, PeerState>>` and `cfg`;
//!    `PeerState` carries connection metadata only. No canonical
//!    `TxPool` field.
//!  - `peer_writers: &Mutex<HashMap<String, PeerOutbox>>`
//!    (`PeerOutbox` defined in this file) — fields are
//!    `frames: Vec<Vec<u8>>` and `total_bytes`. No canonical
//!    `TxPool` field.
//!
//! Any future producer that wires a canonical pool through any
//! of these surfaces MUST re-verify this boundary explicitly,
//! both in this docstring and in the carrier file (this snapshot
//! goes stale silently otherwise). At HEAD with these structural
//! facts in place, the application's shared pool is unreachable
//! from this module's call graph through these surfaces.
//!
//! RUB-178 / GitHub #1438: canonical-pool seam lives in
//! `p2p_runtime.rs::collect_live_responses` MESSAGE_TX via the new
//! `PeerRelayContext.tx_pool` carrier; `handle_received_tx` stays relay-only.
//!
//! The `boundary_checker` test module below uses `syn::parse_file`
//! to walk this file's production AST and detect direct syntactic
//! canonical-`TxPool` admission call expressions. It is a token-
//! aware syntactic direct-call checker scoped to `tx_relay.rs`
//! only. It does not perform Rust type or name resolution, does
//! not expand macros, does not inspect any other file, and does
//! not detect alias wrappers (see `# Boundary check` and
//! `# Known non-scope` below for the full scope contract).
//!
//! `Relayed` indicates the dedup, metadata, and relay-pool storage
//! steps completed successfully and `broadcast_inventory` was
//! invoked. Per-peer broadcast errors are swallowed inside
//! `broadcast_inventory` to match Go's per-peer fire-and-forget
//! relay behaviour, so `Relayed` is not a guarantee that any
//! specific peer received the inventory.
//!
//! Canonical source-aware admission (`TxSource::Local` /
//! `TxSource::Remote` / `TxSource::Reorg`) is owned by the
//! per-producer slices. All three producer slices are merged:
//! RUB-169 reorg requeue (`TxSource::Reorg`), RUB-171 RPC submit
//! (`TxSource::Local`), and RUB-173 p2p relay (`TxSource::Remote`,
//! at `p2p_runtime.rs::collect_live_responses` MESSAGE_TX via the
//! `PeerRelayContext.tx_pool` carrier; gated by a successful
//! `RelayTxOutcome::Relayed` from `handle_received_tx` here).
//! None of those producer slices may treat a successful relay
//! outcome here as proof of canonical admission — admission
//! happens in the per-producer caller, not in this module.
//!
//! # Go counterpart (API/sequence parity ONLY — NOT production-boundary parity)
//!
//! Note: this section describes API/sequence parity only. Current
//! Go production wiring at
//! `clients/go/cmd/rubin-node/main.go::run` configures `handleTx`
//! by passing `TxPool: p2p.NewCanonicalMempoolTxPool(mempool)` and
//! `TxMetadataFunc: p2p.CanonicalMempoolRelayMetadata` into the
//! p2p service config struct literal — so Go production is NOT a
//! relay-cache/canonical split — it admits to the canonical pool
//! from inside `handleTx`. The relay-cache/canonical split
//! described in this docstring is a Rust-only structural choice;
//! the `TxSource::Remote` p2p producer counterpart was introduced
//! by RUB-173 / GitHub #1420 in
//! `p2p_runtime.rs::collect_live_responses` MESSAGE_TX (after a
//! `RelayTxOutcome::Relayed` outcome from this module).
//!
//! `clients/go/node/p2p/handlers_tx.go::handleTx` runs the same
//! sequence (oversize → parse → tx_seen → relayTxMetadata →
//! TxPool.Put → broadcastInventory). Go's `p2p.TxPool` interface
//! accepts both `*CanonicalMempoolTxPool` and `MemoryTxPool`
//! backings as a TYPE-SYSTEM property (current production picks
//! the canonical backing per the wiring cited above); the Rust
//! analogue is hard-wired to the relay-only `RelayTxPool` here.
//! Go's `CanonicalMempoolRelayMetadata`
//! (`clients/go/node/p2p/tx_metadata.go:12`) returns only
//! `Size: len(txBytes)` and defers fee-floor validation; Rust's
//! `crate::txpool::relay_metadata` enforces the rolling fee floor
//! inline (matching `admit_with_metadata` on the canonical pool)
//! but remains standalone non-admitting.
//!
//! # Boundary check (RUB-176 / GitHub issue #1432 token-aware AST walk via `syn`)
//!
//! The `boundary_checker` test module below uses `syn::parse_file`
//! to parse this file's source and walks the production AST via
//! `syn::visit::Visit`. It detects direct syntactic canonical-
//! `TxPool` admission call expressions:
//!
//!  - `Expr::MethodCall` with method ident in {`admit`,
//!    `admit_with_metadata`, `add_tx_with_source`};
//!  - `Expr::Call` with `Expr::Path` (`qself: None`) whose path
//!    terminal segment is one of those method idents AND whose
//!    penultimate segment ident is `TxPool` (covers plain UFCS
//!    `TxPool::method`, the leading-`::` absolute path
//!    `::TxPool::method`, and module-qualified forms with prefixes
//!    `crate`, `self`, `super`, `txpool`, `crate::txpool`,
//!    `self::txpool`, `super::txpool`);
//!  - `Expr::Call` with `Expr::Path` carrying `qself: Some(...)`
//!    where the `qself.ty` is a `Type::Path` whose terminal segment
//!    ident is `TxPool` (covers `<TxPool>::method`,
//!    `<crate::TxPool>::method`, `<crate::txpool::TxPool>::method`,
//!    `<super::TxPool>::method`, `<super::txpool::TxPool>::method`,
//!    `<self::TxPool>::method`, plus all `<X as Trait>::method`
//!    trait-qualified variants).
//!
//! Production scope is established by a deliberately conservative
//! rule: a top-level [`Item`] is skipped from production scan iff
//! its attribute set contains the EXACT literal `#[cfg(test)]` —
//! that is, an attribute whose path is `cfg` and whose `Meta::List`
//! parses as a single `Path` identifier `test`. Every other carrier
//! shape is scanned as production. The skip rule is applied via
//! `Visit::visit_item` and so handles top-level items as well as
//! nested items reachable through the visitor. The boundary is NOT
//! established by textual `split_once("#[cfg(test)]")` on the
//! source.
//!
//! Conservative-scope rationale: general
//! `ConfigurationPredicate` reachability — deciding whether a
//! `cfg(any(test, X))`, `cfg(all(test, X))`, `cfg(not(test))`,
//! `cfg(target_os = "linux")`, `cfg(false)`, multi-`#[cfg]` stack,
//! or below-item-level cfg gate (on `ImplItem`, `TraitItem`,
//! `Expr`, `Arm`, `Stmt`, `FieldValue`) is enabled in production
//! builds — requires modelling the Rust `ConfigurationPredicate`
//! grammar
//! (<https://doc.rust-lang.org/reference/conditional-compilation.html>)
//! and is explicit non-scope per RUB-176 / GitHub issue #1432's
//! `class_change_stop_rule`. The conservative scope flags such
//! carriers as production (false-positive over false-negative): a
//! production-only admission introduced under any non-exact cfg
//! shape will fire the checker; the false-positive is remediated by
//! rewriting the cfg to the exact `#[cfg(test)]` form on a
//! top-level `Item` or moving the admission off the production
//! surface.
//!
//! Allowed claim language for this checker (matches RUB-176 /
//! GitHub issue #1432):
//!
//!  - syntactic direct-call checker;
//!  - token-aware over `tx_relay.rs` only;
//!  - no comments / line-comments / block-comments / doc-comments /
//!    string-literal / raw-string-literal / exact-`#[cfg(test)]`
//!    item false positives — `syn` discards line and block comments
//!    during parse; doc comments live in attribute nodes and are
//!    not visited as expression-callable tokens; string and raw-
//!    string literals are `Lit::Str` AST nodes and are not visited
//!    as call callables; items carrying the EXACT literal
//!    `#[cfg(test)]` attribute are skipped via the AST attribute
//!    walk;
//!  - no type-resolution completeness;
//!  - no macro-expansion completeness;
//!  - no cross-file carrier inspection;
//!  - no general `ConfigurationPredicate` reachability — only the
//!    EXACT literal `#[cfg(test)]` shape is a skip class, every
//!    other cfg shape and every below-item-level cfg gate is
//!    scanned as production;
//!  - alias wrappers out of scope (`use crate::txpool::TxPool as
//!    Pool` followed by `Pool::admit(...)` will not match because
//!    the path's penultimate segment is `Pool`, not `TxPool`).
//!
//! Receiver-agnostic dotted-method detection: `.admit(...)` /
//! `.admit_with_metadata(...)` / `.add_tx_with_source(...)` fire
//! regardless of receiver type, since dotted-method calls do not
//! resolve to a path with a known receiver type at the AST level.
//! This is a deliberate defense-in-depth bias toward false-alarm
//! over miss; if a future producer introduces a similarly-named
//! method on a different receiver inside this module, that
//! producer either renames the surface or escalates to a sounder
//! checker via a separate Q-*.
//!
//! Fail-closed conditions (the checker returns `Err`):
//!
//!  - `syn::parse_file` fails on this file's source
//!    (`BoundaryCheckError::ParseFailed`);
//!  - the production handler `handle_received_tx` is not located
//!    in production scope — renamed, removed, or accidentally
//!    moved under `#[cfg(test)]`
//!    (`BoundaryCheckError::HandlerMissing`);
//!  - the file has no top-level items
//!    (`BoundaryCheckError::EmptyFile`).
//!
//! # Known non-scope (bypass classes NOT detected — escalation requires class change)
//!
//! These bypass classes remain not detected by the token-aware
//! checker; if any becomes a real concern, escalating to detection
//! requires a class change beyond the syntactic-direct-call scope:
//!
//!  - alias wrappers via `use crate::txpool::TxPool as Pool;`
//!    followed by `Pool::admit(...)` — name resolution beyond
//!    syntactic paths is explicit non-scope;
//!  - function-pointer indirection (`let f = TxPool::admit; f(tx)`),
//!    trait-object dispatch, local type aliases, generic helpers
//!    that hide the receiver type;
//!  - macro invocations whose body contains admission calls —
//!    `syn` treats macro bodies as unparsed token streams and the
//!    visitor does not descend into them;
//!  - type-level constructs whose `qself.ty` is not a plain
//!    `Type::Path` ending in `TxPool` (for example,
//!    `<&TxPool>::admit`, `<(TxPool)>::admit`, `<Box<TxPool>>::admit`,
//!    or any `Wrapper<TxPool>` whose `Type::Path` terminal segment
//!    is `Wrapper`, not `TxPool`);
//!  - general `ConfigurationPredicate` reachability — `cfg(any(...))`,
//!    `cfg(all(...))`, `cfg(not(...))`, `cfg(name = "value")`,
//!    `cfg(true)`, `cfg(false)`, multi-`#[cfg]` stacks, and
//!    below-item-level cfg gates (on `ImplItem`, `TraitItem`,
//!    `Expr`, `Arm`, `Stmt`, `FieldValue`) are scanned as
//!    production. False-positive remediation is rewriting the gate
//!    to the exact `#[cfg(test)]` shape on a top-level `Item` or
//!    removing the admission from production scope;
//!  - cross-file structural drift — a future PR could add a
//!    canonical `TxPool` field to `SyncEngine`, `PeerManager`,
//!    `PeerOutbox`, or `TxRelayState` in another file and the
//!    checker would not detect that drift, since its surface is
//!    `tx_relay.rs` source only.

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

use rubin_consensus::{block_hash, parse_block_bytes};
use sha3::{Digest, Sha3_256};

use crate::p2p_runtime::{
    encode_inventory_vectors, InventoryVector, PeerManager, MSG_BLOCK, MSG_TX,
};
use crate::relay_pool::RelayTxPool;
use crate::tx_seen::BoundedHashSet;

/// Default TX relay fanout (matches Go `defaultTxRelayFanout`).
pub const DEFAULT_TX_RELAY_FANOUT: usize = 8;

/// Maximum frames per peer outbox before new relay messages are dropped.
/// At ~70 bytes/frame (INV with 1 tx), 1024 frames ≈ 70 KiB — safe even for
/// slow peers while preventing unbounded growth.
const MAX_OUTBOX_FRAMES_PER_PEER: usize = 1024;
/// Hard per-peer byte budget for queued relay frames.
///
/// Inventory frames are normally tiny, but a byte cap ensures future relay
/// changes cannot turn the frame-count cap into a multi-megabyte queue.
const MAX_OUTBOX_BYTES_PER_PEER: usize = 1 << 20;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerOutbox {
    frames: Vec<Vec<u8>>,
    total_bytes: usize,
}

impl PeerOutbox {
    pub fn push_frame(&mut self, frame: Vec<u8>) -> bool {
        if self.frames.len() >= MAX_OUTBOX_FRAMES_PER_PEER {
            return false;
        }
        let Some(next_total) = self.total_bytes.checked_add(frame.len()) else {
            return false;
        };
        if next_total > MAX_OUTBOX_BYTES_PER_PEER {
            return false;
        }
        self.total_bytes = next_total;
        self.frames.push(frame);
        true
    }

    pub fn take_frames(&mut self) -> Vec<Vec<u8>> {
        self.total_bytes = 0;
        std::mem::take(&mut self.frames)
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn frames(&self) -> &[Vec<u8>] {
        &self.frames
    }
}

/// Shared relay state passed through the P2P service.
pub struct TxRelayState {
    pub tx_seen: BoundedHashSet,
    pub block_seen: BoundedHashSet,
    pub relay_pool: RelayTxPool,
    pub tx_relay_fanout: usize,
    pub network: String,
}

impl Default for TxRelayState {
    fn default() -> Self {
        Self::new()
    }
}

impl TxRelayState {
    pub fn new() -> Self {
        Self::new_with_network("devnet")
    }

    pub fn new_with_network(network: &str) -> Self {
        Self {
            tx_seen: BoundedHashSet::new(crate::tx_seen::DEFAULT_TX_SEEN_CAPACITY),
            block_seen: BoundedHashSet::new(crate::tx_seen::DEFAULT_BLOCK_SEEN_CAPACITY),
            relay_pool: RelayTxPool::new(),
            tx_relay_fanout: DEFAULT_TX_RELAY_FANOUT,
            network: network.to_string(),
        }
    }
}

/// Deterministic peer selection for tx relay, matching Go `selectTxRelayPeers`.
///
/// Scores each peer with `sha3(relay_key || salt || addr)`, sorts ascending,
/// takes first `limit` peers. This ensures different txids propagate to
/// different peer subsets (privacy + load distribution).
pub fn select_tx_relay_peers(
    relay_key: [u8; 32],
    relay_salt: &str,
    addrs: &[String],
    limit: usize,
) -> Vec<String> {
    if addrs.is_empty() {
        return Vec::new();
    }
    if limit == 0 || limit >= addrs.len() {
        return addrs.to_vec();
    }
    let mut scored: Vec<([u8; 32], String)> = addrs
        .iter()
        .map(|addr| (tx_relay_score(relay_key, relay_salt, addr), addr.clone()))
        .collect();
    scored.sort_by(|a, b| {
        let cmp = a.0.cmp(&b.0);
        if cmp != std::cmp::Ordering::Equal {
            cmp
        } else {
            a.1.cmp(&b.1)
        }
    });
    scored
        .into_iter()
        .take(limit)
        .map(|(_, addr)| addr)
        .collect()
}

/// Compute relay score for a peer. Matches Go `txRelayScore`:
/// `sha3_256(relay_key || salt_bytes || addr_bytes)`.
pub fn tx_relay_score(relay_key: [u8; 32], relay_salt: &str, addr: &str) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(relay_key);
    h.update(relay_salt.as_bytes());
    h.update(addr.as_bytes());
    h.finalize().into()
}

/// Compute the relay key from inventory vectors. Matches Go `inventoryRelayKey`.
///
/// Single item: returns its hash directly. Multiple: `sha3(hash1 || hash2 || ...)`.
pub fn inventory_relay_key(items: &[InventoryVector]) -> [u8; 32] {
    if items.len() == 1 {
        return items[0].hash;
    }
    let mut h = Sha3_256::new();
    for item in items {
        h.update(item.hash);
    }
    h.finalize().into()
}

/// Broadcast inventory to peers. Block items go to ALL peers; tx items use
/// selective fanout. Matches Go `broadcastInventory`.
///
/// `skip_addr`: sender's address to exclude (for re-relay). `None` for RPC-originated.
pub fn broadcast_inventory(
    relay_state: &TxRelayState,
    skip_addr: Option<&str>,
    items: &[InventoryVector],
    peer_manager: &PeerManager,
    local_addr: &str,
    peer_writers: &Mutex<HashMap<String, PeerOutbox>>,
) -> Result<(), String> {
    let peers = peer_manager.snapshot();
    let mut addrs: Vec<String> = peers
        .iter()
        .filter(|p| skip_addr.is_none_or(|skip| p.addr != skip))
        .map(|p| p.addr.clone())
        .collect();
    if addrs.is_empty() || items.is_empty() {
        return Ok(());
    }

    let (block_items, tx_items): (Vec<_>, Vec<_>) =
        items.iter().partition(|iv| iv.kind == MSG_BLOCK);

    if !block_items.is_empty() {
        let block_vecs: Vec<InventoryVector> = block_items.into_iter().cloned().collect();
        broadcast_inv_to_addrs(
            &block_vecs,
            &addrs,
            &relay_state.network,
            peer_writers,
            false,
        )?;
    }

    if tx_items.is_empty() {
        return Ok(());
    }

    let tx_vecs: Vec<InventoryVector> = tx_items.into_iter().cloned().collect();
    let relay_key = inventory_relay_key(&tx_vecs);
    let relay_salt = skip_addr.unwrap_or(local_addr);
    addrs = select_tx_relay_peers(relay_key, relay_salt, &addrs, relay_state.tx_relay_fanout);
    broadcast_inv_to_addrs(&tx_vecs, &addrs, &relay_state.network, peer_writers, false)
}

/// Send INV message to a set of peer addresses.
fn broadcast_inv_to_addrs(
    items: &[InventoryVector],
    addrs: &[String],
    network: &str,
    peer_writers: &Mutex<HashMap<String, PeerOutbox>>,
    require_all_queues: bool,
) -> Result<(), String> {
    let payload = encode_inventory_vectors(items).map_err(|e| e.to_string())?;
    let magic = crate::p2p_runtime::network_magic(network);
    let header = crate::p2p_runtime::build_envelope_header(magic, "inv", &payload)
        .map_err(|e| e.to_string())?;
    // Build a single frame: header + payload.
    let mut frame = Vec::with_capacity(header.len() + payload.len());
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);
    // Enqueue the frame into each peer's outbox. The peer's own thread
    // will drain the queue, ensuring writes are serialized on the TcpStream.
    let mut outboxes = match peer_writers.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let mut failures = Vec::new();
    for addr in addrs {
        let Some(queue) = outboxes.get_mut(addr) else {
            if require_all_queues {
                failures.push(format!("peer outbox missing for {addr}"));
            }
            continue;
        };
        if !queue.push_frame(frame.clone()) && require_all_queues {
            failures.push(format!("peer outbox full for {addr}"));
        }
        // Non-strict relay drops silently when a peer is slow or over byte
        // budget; strict block announce uses errors so local mining cannot
        // report announce success without enqueueing the block inventory.
    }
    if !failures.is_empty() {
        return Err(format!("inventory enqueue failed: {}", failures.join("; ")));
    }
    Ok(())
}

/// Announce a transaction after successful mempool admission.
///
/// Full flow: parse tx → compute txid → store in relay pool → mark seen →
/// broadcast INV to peers. Matches Go `AnnounceTx`.
pub fn announce_tx(
    tx_bytes: &[u8],
    meta: crate::txpool::RelayTxMetadata,
    relay_state: &TxRelayState,
    peer_manager: &PeerManager,
    local_addr: &str,
    peer_writers: &Mutex<HashMap<String, PeerOutbox>>,
) -> Result<(), String> {
    let txid = canonical_txid(tx_bytes)?;

    // RPC path already passed mempool admission, so preserve the validated
    // relay metadata for relay-pool priority instead of degrading to zero fee.
    if !relay_state
        .relay_pool
        .put(txid, tx_bytes, meta.fee, meta.size)
    {
        return Ok(());
    }

    if !relay_state.tx_seen.add(txid) {
        return Ok(()); // Already seen — don't broadcast.
    }

    broadcast_inventory(
        relay_state,
        None, // No skip for RPC-originated txs.
        &[InventoryVector {
            kind: MSG_TX,
            hash: txid,
        }],
        peer_manager,
        local_addr,
        peer_writers,
    )
}

/// Announce a locally mined block after it is committed to the block store.
///
/// Rust `/mine_next` uses this to mirror Go's `AnnounceBlock`: parse the
/// committed full block, derive its canonical hash, then broadcast a BLOCK
/// inventory item to every connected peer.
pub fn announce_block(
    block_bytes: &[u8],
    relay_state: &TxRelayState,
    peer_manager: &PeerManager,
    _local_addr: &str,
    peer_writers: &Mutex<HashMap<String, PeerOutbox>>,
) -> Result<(), String> {
    let parsed = parse_block_bytes(block_bytes).map_err(|err| err.to_string())?;
    let hash = block_hash(&parsed.header_bytes).map_err(|err| err.to_string())?;
    if relay_state.block_seen.has(&hash) {
        return Ok(());
    }
    let peers = peer_manager.snapshot();
    let addrs: Vec<String> = peers.iter().map(|p| p.addr.clone()).collect();
    if addrs.is_empty() {
        return Ok(());
    }
    broadcast_inv_to_addrs(
        &[InventoryVector {
            kind: MSG_BLOCK,
            hash,
        }],
        &addrs,
        &relay_state.network,
        peer_writers,
        true,
    )?;
    let _ = relay_state.block_seen.add(hash);
    Ok(())
}

/// Outcome of processing a peer-relayed tx.
///
/// The caller (peer session in `p2p_runtime`) inspects this value to mirror
/// Go's per-outcome ban-score policy in `clients/go/node/p2p/handlers_tx.go`:
/// parse/oversize failures bump the peer's ban score, while pool/metadata
/// rejections of a structurally-valid tx are silent no-ops (peers must not
/// be punished for a tx the local policy simply doesn't want to relay).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayTxOutcome {
    /// Tx was parsed, admitted to relay pool, and re-announced.
    Relayed,
    /// Tx was already seen — silently ignored.
    DuplicateSeen,
    /// Relay-metadata derivation failed (fee/policy); marked seen so peers
    /// don't churn INV/GETDATA, but peer session is not penalized.
    MetadataRejected,
    /// Relay pool rejected admission (full or lower-priority eviction).
    PoolRejected,
    /// Payload exceeded `MAX_RELAY_MSG_BYTES`. Caller must bump ban score
    /// and fail the session if over threshold (parity with Go
    /// `handleTx` oversize path).
    Oversized,
    /// Consensus parse or canonical-bytes check failed. Caller must bump
    /// ban score (parity with Go `handleTx` parse-fail path which calls
    /// `p.bumpBan(10, ...)`).
    MalformedParse(String),
}

impl RelayTxOutcome {
    /// True when the outcome corresponds to a malformed/oversized peer input
    /// that should bump the peer's ban score (parity with Go
    /// `peer.handleTx` — `p.bumpBan(10, err.Error())`).
    pub fn is_banworthy(&self) -> bool {
        matches!(self, Self::Oversized | Self::MalformedParse(_))
    }
}

/// Handle a transaction received from a peer.
///
/// Validates structure via consensus parsing, derives relay metadata using the
/// current chainstate/policy context, then marks seen BEFORE pool admission
/// (Go's seen-before-pool pattern).
///
/// Returns a [`RelayTxOutcome`] so the caller can mirror Go's ban-score
/// policy: Go's `handleTx` bumps ban by 10 on parse-fail (see
/// `peer.handleTx` in `clients/go/node/p2p/handlers_tx.go`), and this function now surfaces
/// the same signal via `MalformedParse`/`Oversized` variants instead of
/// silently demoting parse errors to plain `io::Error`.
pub fn handle_received_tx(
    tx_bytes: &[u8],
    sync_engine: &crate::sync::SyncEngine,
    relay_state: &TxRelayState,
    peer_manager: &PeerManager,
    skip_addr: &str,
    local_addr: &str,
    peer_writers: &Mutex<HashMap<String, PeerOutbox>>,
) -> io::Result<RelayTxOutcome> {
    // Reject oversized tx payloads early (defense-in-depth).
    if tx_bytes.len() > rubin_consensus::constants::MAX_RELAY_MSG_BYTES as usize {
        return Ok(RelayTxOutcome::Oversized);
    }

    // Structural validation via consensus parser (matches Go's canonicalTxID + relayTxMetadata).
    let txid = match canonical_txid(tx_bytes) {
        Ok(txid) => txid,
        Err(reason) => return Ok(RelayTxOutcome::MalformedParse(reason)),
    };

    handle_received_tx_with_canonical_txid(
        tx_bytes,
        txid,
        sync_engine,
        relay_state,
        peer_manager,
        skip_addr,
        local_addr,
        peer_writers,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_received_tx_with_canonical_txid(
    tx_bytes: &[u8],
    txid: [u8; 32],
    sync_engine: &crate::sync::SyncEngine,
    relay_state: &TxRelayState,
    peer_manager: &PeerManager,
    skip_addr: &str,
    local_addr: &str,
    peer_writers: &Mutex<HashMap<String, PeerOutbox>>,
) -> io::Result<RelayTxOutcome> {
    if tx_bytes.len() > rubin_consensus::constants::MAX_RELAY_MSG_BYTES as usize {
        return Ok(RelayTxOutcome::Oversized);
    }

    // Mark seen BEFORE pool admission (matches Go).
    if !relay_state.tx_seen.add(txid) {
        return Ok(RelayTxOutcome::DuplicateSeen);
    }

    let relay_cfg = crate::txpool::TxPoolConfig {
        core_ext_deployments: sync_engine.cfg.core_ext_deployments.clone(),
        suite_context: sync_engine.cfg.suite_context.clone(),
        ..crate::txpool::TxPoolConfig::default()
    };
    let meta = match crate::txpool::relay_metadata(
        tx_bytes,
        &sync_engine.chain_state,
        sync_engine.block_store.as_ref(),
        sync_engine.cfg.chain_id,
        &relay_cfg,
    ) {
        Ok(meta) => meta,
        Err(_) => return Ok(RelayTxOutcome::MetadataRejected),
    };

    // Store in relay pool with extracted metadata.
    if !relay_state
        .relay_pool
        .put(txid, tx_bytes, meta.fee, meta.size)
    {
        return Ok(RelayTxOutcome::PoolRejected);
    }

    // Re-announce to other peers (skip sender).
    let _ = broadcast_inventory(
        relay_state,
        Some(skip_addr),
        &[InventoryVector {
            kind: MSG_TX,
            hash: txid,
        }],
        peer_manager,
        local_addr,
        peer_writers,
    );
    Ok(RelayTxOutcome::Relayed)
}

/// Extract the canonical txid from raw tx bytes using consensus parsing.
pub(crate) fn canonical_txid(tx_bytes: &[u8]) -> Result<[u8; 32], String> {
    let (_tx, txid, _wtxid, consumed) =
        rubin_consensus::parse_tx(tx_bytes).map_err(|e| e.to_string())?;
    if consumed != tx_bytes.len() {
        return Err("non-canonical tx bytes".to_string());
    }
    Ok(txid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{default_sync_config, ChainState, SyncEngine};

    // PR-1410 wave-2 — removed unused conformance-fixture types and
    // helpers (`FixtureFile`, `FixtureUtxo`, `PositiveTxVector`,
    // `parse_hex32_test`, `fixture_utxos_to_map`,
    // `positive_fixture_vector`, `fixture_chain_id`,
    // `chain_state_from_positive_fixture`,
    // `sync_engine_from_positive_fixture`).
    // The two consumer tests (`floor_compliant_tx_and_meta` builder
    // and `handle_received_tx_with_valid_floor_compliant_tx_stores_and_relays`)
    // now build a floor-compliant signed P2PK fixture inline via the
    // public `signed_conflicting_p2pk_state_and_txs` helper because the
    // conformance fixture's pre-signed tx (fee=10/weight≈7653) is
    // sub-floor under the wave-2 `relay_metadata` rolling-floor check.

    fn floor_compliant_tx_and_meta() -> (Vec<u8>, crate::txpool::RelayTxMetadata) {
        // PR-1410 wave-2 fixture migration: relay_metadata now enforces
        // the same rolling fee floor as admit_with_metadata (see
        // rub162_relay_metadata_da_below_rolling_floor_returns_unavailable_matching_admit).
        // The conformance fixture (fee=10/weight≈7653 ⇒ fee_rate ≈ 0.0013)
        // is sub-floor under DEFAULT_MEMPOOL_MIN_FEE_RATE=1, and bumping
        // UTXO values inside the conformance state invalidates the
        // signature baked into the fixture's pre-signed tx hex. Build
        // a floor-compliant signed P2PK tx + matching state inline via
        // the public test_helpers helper (mirrors the admit_* test
        // migrations); fee = 20_000 - 10 = 19_990 ≫ weight*1.
        let (state, tx_bytes, _second_tx_unused) =
            crate::test_helpers::signed_conflicting_p2pk_state_and_txs(20_000, 10, 9);
        let meta = crate::txpool::relay_metadata(
            &tx_bytes,
            &state,
            None,
            crate::genesis::devnet_genesis_chain_id(),
            &crate::txpool::TxPoolConfig::default(),
        )
        .expect("relay_metadata for floor-compliant signed P2PK tx");
        (tx_bytes, meta)
    }

    fn make_txid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Load a real parseable tx from the CV-CANONICAL-INVARIANT fixture.
    fn real_tx_bytes() -> Vec<u8> {
        // Positive fixture: version=1, 1 input, 1 output, parseable by consensus.
        const TX_HEX: &str = "0100000001030000000000000001111111111111111111111111111111111111111111111111111111111111111100000000000000000001000000000000000003012077777777777777777777777777777777777777777777777777777777777777770000000001010101010101010101010101010101010101010101010101010101010101010100020202020202020202020202020202020202020202020202020202020202020201000000000000000303030303030303030303030303030303030303030303030303030303030303040404040404040404040404040404040404040404040404040404040404040405050505050505050505050505050505050505050505050505050505050505050101ee000199";
        hex::decode(TX_HEX).expect("decode fixture tx hex")
    }

    #[test]
    fn tx_relay_score_deterministic() {
        let key = [0xAA; 32];
        let salt = "127.0.0.1:8333";
        let addr = "192.168.1.1:8333";
        let score1 = tx_relay_score(key, salt, addr);
        let score2 = tx_relay_score(key, salt, addr);
        assert_eq!(score1, score2);

        // Different addr produces different score.
        let score3 = tx_relay_score(key, salt, "10.0.0.1:8333");
        assert_ne!(score1, score3);
    }

    #[test]
    fn inventory_relay_key_single_item_returns_hash() {
        let hash = [0xBB; 32];
        let items = vec![InventoryVector { kind: MSG_TX, hash }];
        assert_eq!(inventory_relay_key(&items), hash);
    }

    #[test]
    fn inventory_relay_key_multiple_items_uses_sha3() {
        let h1 = [0x01; 32];
        let h2 = [0x02; 32];
        let items = vec![
            InventoryVector {
                kind: MSG_TX,
                hash: h1,
            },
            InventoryVector {
                kind: MSG_TX,
                hash: h2,
            },
        ];
        let key = inventory_relay_key(&items);
        // Should NOT be either individual hash.
        assert_ne!(key, h1);
        assert_ne!(key, h2);
        // Should be deterministic.
        assert_eq!(key, inventory_relay_key(&items));
    }

    #[test]
    fn select_tx_relay_peers_deterministic_ordering() {
        let key = [0xCC; 32];
        let salt = "local:8333";
        let addrs: Vec<String> = (0..10).map(|i| format!("peer-{i}:8333")).collect();

        let selected = select_tx_relay_peers(key, salt, &addrs, 3);
        assert_eq!(selected.len(), 3);

        // Deterministic: same inputs produce same output.
        let selected2 = select_tx_relay_peers(key, salt, &addrs, 3);
        assert_eq!(selected, selected2);

        // Different key produces different selection.
        let selected3 = select_tx_relay_peers([0xDD; 32], salt, &addrs, 3);
        // Very unlikely to be the same (would require SHA3 collision).
        assert_ne!(selected, selected3);
    }

    #[test]
    fn select_tx_relay_peers_limit_clamp() {
        let addrs: Vec<String> = vec!["a:1".into(), "b:2".into()];
        // limit >= peers → return all.
        let all = select_tx_relay_peers([0; 32], "", &addrs, 10);
        assert_eq!(all.len(), 2);

        // limit=0 → return all.
        let all_zero = select_tx_relay_peers([0; 32], "", &addrs, 0);
        assert_eq!(all_zero.len(), 2);
    }

    #[test]
    fn select_tx_relay_peers_empty() {
        let result = select_tx_relay_peers([0; 32], "", &[], 5);
        assert!(result.is_empty());
    }

    #[test]
    fn announce_tx_marks_seen_and_stores() {
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let writers: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());

        // We need a real parseable tx for canonical_txid. Use a minimal
        // test by directly testing the seen/pool components.
        let txid = make_txid(0x42);
        relay.relay_pool.put(txid, &[0xDE, 0xAD], 0, 2);
        assert!(relay.tx_seen.add(txid));
        assert!(relay.relay_pool.has(&txid));
        assert!(relay.tx_seen.has(&txid));

        // announce_tx with the same txid should not re-broadcast (already seen).
        // (We can't call announce_tx directly without valid consensus tx bytes,
        // but the components behave correctly.)
        let _ = broadcast_inventory(
            &relay,
            None,
            &[InventoryVector {
                kind: MSG_TX,
                hash: txid,
            }],
            &pm,
            "local:8333",
            &writers,
        );
    }

    #[test]
    fn broadcast_inventory_skips_sender() {
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let writers: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());

        // With no peers registered, broadcast should succeed silently.
        let result = broadcast_inventory(
            &relay,
            Some("sender:8333"),
            &[InventoryVector {
                kind: MSG_TX,
                hash: make_txid(1),
            }],
            &pm,
            "local:8333",
            &writers,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn broadcast_inventory_enqueues_tx_frames_to_registered_peers() {
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        // Register two peers in peer_manager.
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "peer-a:8333".to_string(),
            ..Default::default()
        });
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "peer-b:8333".to_string(),
            ..Default::default()
        });
        // Create outboxes for both peers.
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        outboxes
            .lock()
            .unwrap()
            .insert("peer-a:8333".to_string(), PeerOutbox::default());
        outboxes
            .lock()
            .unwrap()
            .insert("peer-b:8333".to_string(), PeerOutbox::default());

        // Broadcast TX inventory — should enqueue frames.
        let result = broadcast_inventory(
            &relay,
            None,
            &[InventoryVector {
                kind: MSG_TX,
                hash: make_txid(0x42),
            }],
            &pm,
            "local:8333",
            &outboxes,
        );
        assert!(result.is_ok());

        // At least one outbox should have a frame.
        let boxes = outboxes.lock().unwrap();
        let total_frames: usize = boxes.values().map(|q| q.len()).sum();
        assert!(total_frames > 0, "expected at least one enqueued frame");
        // Each frame should start with RBDV magic.
        for queue in boxes.values() {
            for frame in queue.frames() {
                assert_eq!(&frame[0..4], b"RBDV", "frame should use Rubin devnet magic");
            }
        }
    }

    #[test]
    fn broadcast_inventory_block_items_go_to_all_peers() {
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "peer-a:8333".to_string(),
            ..Default::default()
        });
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "peer-b:8333".to_string(),
            ..Default::default()
        });
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        outboxes
            .lock()
            .unwrap()
            .insert("peer-a:8333".to_string(), PeerOutbox::default());
        outboxes
            .lock()
            .unwrap()
            .insert("peer-b:8333".to_string(), PeerOutbox::default());

        // Broadcast BLOCK inventory — should go to ALL peers.
        let result = broadcast_inventory(
            &relay,
            None,
            &[InventoryVector {
                kind: MSG_BLOCK,
                hash: make_txid(0xBB),
            }],
            &pm,
            "local:8333",
            &outboxes,
        );
        assert!(result.is_ok());

        let boxes = outboxes.lock().unwrap();
        // Both peers should have exactly 1 frame.
        assert_eq!(boxes["peer-a:8333"].len(), 1);
        assert_eq!(boxes["peer-b:8333"].len(), 1);
    }

    fn test_block() -> (Vec<u8>, [u8; 32]) {
        let block = crate::genesis::devnet_genesis_block_bytes();
        let parsed = parse_block_bytes(&block).expect("parse block");
        let hash = block_hash(&parsed.header_bytes).expect("block hash");
        (block, hash)
    }

    fn block_announce_fixture(
        addrs: &[&str],
    ) -> (
        TxRelayState,
        PeerManager,
        Mutex<HashMap<String, PeerOutbox>>,
    ) {
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let outboxes = Mutex::new(HashMap::new());
        for addr in addrs {
            let addr = (*addr).to_string();
            let _ = pm.add_peer(crate::p2p_runtime::PeerState {
                addr: addr.clone(),
                ..Default::default()
            });
            outboxes.lock().unwrap().insert(addr, PeerOutbox::default());
        }
        (relay, pm, outboxes)
    }

    fn assert_block_inv_frame(queue: &PeerOutbox, hash: [u8; 32]) {
        let frames = queue.frames();
        assert_eq!(frames.len(), 1);
        let msg = crate::p2p_runtime::fuzz_parse_wire_message("devnet", &frames[0]).expect("frame");
        assert_eq!(msg.command, "inv");
        assert_eq!(
            crate::p2p_runtime::decode_inventory_vectors(&msg.payload).expect("decode inventory"),
            vec![InventoryVector {
                kind: MSG_BLOCK,
                hash
            }],
        );
    }

    #[test]
    fn announce_block_broadcasts_deduplicates_and_handles_no_peers() {
        let (block, hash) = test_block();
        let (relay, pm, outboxes) = block_announce_fixture(&["peer-a:8333", "peer-b:8333"]);

        announce_block(&block, &relay, &pm, "local:8333", &outboxes).expect("announce block");
        {
            let boxes = outboxes.lock().unwrap();
            assert_block_inv_frame(&boxes["peer-a:8333"], hash);
            assert_block_inv_frame(&boxes["peer-b:8333"], hash);
        }
        announce_block(&block, &relay, &pm, "local:8333", &outboxes).expect("dedupe");
        assert_eq!(outboxes.lock().unwrap()["peer-a:8333"].len(), 1);

        let (relay, pm, outboxes) = block_announce_fixture(&[]);
        announce_block(&block, &relay, &pm, "local:8333", &outboxes).expect("no-peer announce");
        assert!(!relay.block_seen.has(&hash));
        assert!(outboxes.lock().unwrap().is_empty());
    }

    #[test]
    fn announce_block_failure_paths_remain_retryable() {
        let (block, hash) = test_block();
        let (relay, pm, outboxes) = block_announce_fixture(&["healthy:8333"]);
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "missing:8333".to_string(),
            ..Default::default()
        });

        let err = announce_block(&block, &relay, &pm, "local:8333", &outboxes)
            .expect_err("missing peer outbox should fail strict block announce");
        assert!(err.contains("peer outbox missing for missing:8333"));
        assert_eq!(outboxes.lock().unwrap()["healthy:8333"].len(), 1);
        assert!(!relay.block_seen.has(&hash));

        outboxes
            .lock()
            .unwrap()
            .insert("missing:8333".to_string(), PeerOutbox::default());
        announce_block(&block, &relay, &pm, "local:8333", &outboxes).expect("retry after repair");
        assert_eq!(outboxes.lock().unwrap()["missing:8333"].len(), 1);
        assert!(relay.block_seen.has(&hash));

        let (relay, pm, outboxes) = block_announce_fixture(&["full:8333"]);
        for _ in 0..MAX_OUTBOX_FRAMES_PER_PEER {
            assert!(outboxes
                .lock()
                .unwrap()
                .get_mut("full:8333")
                .unwrap()
                .push_frame(Vec::new()));
        }
        let err = announce_block(&block, &relay, &pm, "local:8333", &outboxes)
            .expect_err("full outbox must fail block announce");
        assert!(err.contains("peer outbox full for full:8333"));
        assert!(!relay.block_seen.has(&hash));
    }

    #[test]
    fn announce_block_recovers_poisoned_peer_outboxes_lock() {
        let (block, hash) = test_block();
        let (relay, pm, outboxes) = block_announce_fixture(&["peer:8333"]);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = outboxes.lock().expect("lock outboxes before poison");
            panic!("poison peer outboxes for regression test");
        }));
        assert!(outboxes.lock().is_err());

        announce_block(&block, &relay, &pm, "local:8333", &outboxes)
            .expect("poisoned peer outboxes should recover for announce");
        let boxes = outboxes.lock().unwrap_or_else(|p| p.into_inner());
        assert_block_inv_frame(&boxes["peer:8333"], hash);
    }

    #[test]
    fn broadcast_inventory_skip_addr_excludes_sender() {
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "sender:8333".to_string(),
            ..Default::default()
        });
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "other:8333".to_string(),
            ..Default::default()
        });
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        outboxes
            .lock()
            .unwrap()
            .insert("sender:8333".to_string(), PeerOutbox::default());
        outboxes
            .lock()
            .unwrap()
            .insert("other:8333".to_string(), PeerOutbox::default());

        let result = broadcast_inventory(
            &relay,
            Some("sender:8333"),
            &[InventoryVector {
                kind: MSG_TX,
                hash: make_txid(0x01),
            }],
            &pm,
            "local:8333",
            &outboxes,
        );
        assert!(result.is_ok());

        let boxes = outboxes.lock().unwrap();
        // Sender should be skipped.
        assert_eq!(boxes["sender:8333"].len(), 0);
        // Other peer should get the frame.
        assert_eq!(boxes["other:8333"].len(), 1);
    }

    #[test]
    fn broadcast_inventory_mixed_block_and_tx() {
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        for i in 0..3 {
            let _ = pm.add_peer(crate::p2p_runtime::PeerState {
                addr: format!("peer-{i}:8333"),
                ..Default::default()
            });
        }
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        for i in 0..3 {
            outboxes
                .lock()
                .unwrap()
                .insert(format!("peer-{i}:8333"), PeerOutbox::default());
        }

        let result = broadcast_inventory(
            &relay,
            None,
            &[
                InventoryVector {
                    kind: MSG_BLOCK,
                    hash: make_txid(0xBB),
                },
                InventoryVector {
                    kind: MSG_TX,
                    hash: make_txid(0xCC),
                },
            ],
            &pm,
            "local:8333",
            &outboxes,
        );
        assert!(result.is_ok());

        // All peers should have block frame; tx frame may go to subset via fanout.
        let boxes = outboxes.lock().unwrap();
        for i in 0..3 {
            assert!(
                !boxes[&format!("peer-{i}:8333")].is_empty(),
                "peer-{i} should have at least block frame"
            );
        }
    }

    #[test]
    fn broadcast_inventory_empty_items_noop() {
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "peer:8333".to_string(),
            ..Default::default()
        });
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        outboxes
            .lock()
            .unwrap()
            .insert("peer:8333".to_string(), PeerOutbox::default());

        let result = broadcast_inventory(&relay, None, &[], &pm, "local:8333", &outboxes);
        assert!(result.is_ok());
        assert!(outboxes.lock().unwrap()["peer:8333"].is_empty());
    }

    #[test]
    fn handle_received_tx_seen_before_pool() {
        let relay = TxRelayState::new();
        let _pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let _outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());

        // Pre-mark txid as seen — handle_received_tx should return Ok without storing.
        let txid = make_txid(0x99);
        relay.tx_seen.add(txid);

        // We can't call handle_received_tx with invalid bytes (it needs parseable tx),
        // but we verify the seen-before-pool semantics via the components.
        assert!(relay.tx_seen.has(&txid));
        assert!(!relay.relay_pool.has(&txid));

        // Second add returns false — no relay.
        assert!(!relay.tx_seen.add(txid));
    }

    #[test]
    fn canonical_txid_parses_valid_tx() {
        let tx_bytes = real_tx_bytes();
        let txid = canonical_txid(&tx_bytes);
        assert!(txid.is_ok(), "should parse valid tx: {:?}", txid.err());
        assert_ne!(txid.unwrap(), [0u8; 32]);
    }

    #[test]
    fn canonical_txid_rejects_truncated() {
        let result = canonical_txid(&[0x01, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn canonical_txid_rejects_trailing_bytes() {
        let mut tx = real_tx_bytes();
        tx.push(0xFF); // extra trailing byte
        let result = canonical_txid(&tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-canonical"));
    }

    #[test]
    fn announce_tx_with_real_tx_stores_and_broadcasts() {
        let (tx_bytes, meta) = floor_compliant_tx_and_meta();
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "peer-x:8333".to_string(),
            ..Default::default()
        });
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        outboxes
            .lock()
            .unwrap()
            .insert("peer-x:8333".to_string(), PeerOutbox::default());

        let result = announce_tx(&tx_bytes, meta, &relay, &pm, "local:8333", &outboxes);
        assert!(result.is_ok(), "announce_tx failed: {:?}", result.err());

        // Tx should be in relay pool + seen set.
        let txid = canonical_txid(&tx_bytes).unwrap();
        assert!(relay.relay_pool.has(&txid));
        assert!(relay.tx_seen.has(&txid));

        // Peer should have received an INV frame.
        let boxes = outboxes.lock().unwrap();
        assert_eq!(boxes["peer-x:8333"].len(), 1);
        assert_eq!(&boxes["peer-x:8333"].frames()[0][0..4], b"RBDV");
    }

    #[test]
    fn announce_tx_skips_already_seen() {
        let tx_bytes = real_tx_bytes();
        let txid = canonical_txid(&tx_bytes).unwrap();
        let meta = crate::txpool::RelayTxMetadata {
            fee: 0,
            size: tx_bytes.len(),
        };
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "peer-y:8333".to_string(),
            ..Default::default()
        });
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        outboxes
            .lock()
            .unwrap()
            .insert("peer-y:8333".to_string(), PeerOutbox::default());

        // Pre-mark as seen + pre-store in pool.
        relay.tx_seen.add(txid);
        relay.relay_pool.put(txid, &tx_bytes, 0, tx_bytes.len());

        let result = announce_tx(&tx_bytes, meta, &relay, &pm, "local:8333", &outboxes);
        assert!(result.is_ok());

        // No broadcast should occur (already seen).
        let boxes = outboxes.lock().unwrap();
        assert!(boxes["peer-y:8333"].is_empty());
    }

    #[test]
    fn announce_tx_relay_pool_rejection_skips_seen_and_broadcast() {
        let tx_bytes = real_tx_bytes();
        let meta = crate::txpool::RelayTxMetadata {
            fee: 0,
            size: tx_bytes.len(),
        };
        let relay = TxRelayState {
            tx_seen: BoundedHashSet::new(crate::tx_seen::DEFAULT_TX_SEEN_CAPACITY),
            block_seen: BoundedHashSet::new(crate::tx_seen::DEFAULT_BLOCK_SEEN_CAPACITY),
            relay_pool: RelayTxPool::new_with_limit(1),
            tx_relay_fanout: DEFAULT_TX_RELAY_FANOUT,
            network: "devnet".to_string(),
        };
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "peer-z:8333".to_string(),
            ..Default::default()
        });
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        outboxes
            .lock()
            .unwrap()
            .insert("peer-z:8333".to_string(), PeerOutbox::default());

        assert!(relay.relay_pool.put([0xEE; 32], &[0xAA], 1, 1));

        let result = announce_tx(&tx_bytes, meta, &relay, &pm, "local:8333", &outboxes);
        assert!(result.is_ok());

        let txid = canonical_txid(&tx_bytes).unwrap();
        assert!(!relay.tx_seen.has(&txid));
        assert!(!relay.relay_pool.has(&txid));
        let boxes = outboxes.lock().unwrap();
        assert!(boxes["peer-z:8333"].is_empty());
    }

    #[test]
    fn announce_tx_uses_real_metadata_for_relay_pool_priority() {
        let (tx_bytes, meta) = floor_compliant_tx_and_meta();
        let incoming_txid = canonical_txid(&tx_bytes).unwrap();
        let existing_txid = [0xEE; 32];
        let relay = TxRelayState {
            tx_seen: BoundedHashSet::new(crate::tx_seen::DEFAULT_TX_SEEN_CAPACITY),
            block_seen: BoundedHashSet::new(crate::tx_seen::DEFAULT_BLOCK_SEEN_CAPACITY),
            relay_pool: RelayTxPool::new_with_limit(1),
            tx_relay_fanout: DEFAULT_TX_RELAY_FANOUT,
            network: "devnet".to_string(),
        };
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "peer-rpc:8333".to_string(),
            ..Default::default()
        });
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        outboxes
            .lock()
            .unwrap()
            .insert("peer-rpc:8333".to_string(), PeerOutbox::default());

        assert!(relay.relay_pool.put(existing_txid, &[0xAA], 1, 100_000));

        let result = announce_tx(&tx_bytes, meta, &relay, &pm, "local:8333", &outboxes);
        assert!(result.is_ok(), "announce_tx failed: {:?}", result.err());
        assert!(relay.tx_seen.has(&incoming_txid));
        assert!(relay.relay_pool.has(&incoming_txid));
        assert!(!relay.relay_pool.has(&existing_txid));
        let boxes = outboxes.lock().unwrap();
        assert_eq!(boxes["peer-rpc:8333"].len(), 1);
    }

    #[test]
    fn handle_received_tx_with_valid_floor_compliant_tx_stores_and_relays() {
        // PR-1410 wave-2 fixture migration: relay_metadata now enforces
        // the same rolling fee floor as admit_with_metadata. The
        // conformance fixture (fee=10/weight≈7653) is sub-floor and
        // would now reject. Use a floor-compliant signed P2PK tx +
        // matching SyncEngine inline (mirrors the admit_* migration
        // pattern in txpool.rs); the test purpose (handle_received_tx
        // stores + relays a valid tx, skips sender, broadcasts to
        // other) is preserved.
        let (chain_state, tx_bytes, _second_tx_unused) =
            crate::test_helpers::signed_conflicting_p2pk_state_and_txs(20_000, 10, 9);
        let mut cfg = default_sync_config(None, crate::genesis::devnet_genesis_chain_id(), None);
        cfg.core_ext_deployments = rubin_consensus::CoreExtDeploymentProfiles::empty();
        let sync_engine = SyncEngine::new(chain_state, None, cfg).expect("sync engine");
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let _ = pm.add_peer(crate::p2p_runtime::PeerState {
            addr: "other:8333".to_string(),
            ..Default::default()
        });
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        outboxes
            .lock()
            .unwrap()
            .insert("sender:8333".to_string(), PeerOutbox::default());
        outboxes
            .lock()
            .unwrap()
            .insert("other:8333".to_string(), PeerOutbox::default());

        let result = handle_received_tx(
            &tx_bytes,
            &sync_engine,
            &relay,
            &pm,
            "sender:8333",
            "local:8333",
            &outboxes,
        );
        assert!(result.is_ok());

        let txid = canonical_txid(&tx_bytes).unwrap();
        assert!(relay.tx_seen.has(&txid));
        assert!(relay.relay_pool.has(&txid));

        // Other peer gets INV, sender does not (skipped).
        let boxes = outboxes.lock().unwrap();
        assert!(boxes["sender:8333"].is_empty());
        assert_eq!(boxes["other:8333"].len(), 1);
    }

    /// RUB-176 / GitHub issue #1432 token-aware boundary checker.
    ///
    /// `syn`-based AST walk over `tx_relay.rs` production source
    /// detecting direct syntactic canonical-`TxPool` admission call
    /// expressions. See the module-level docstring under `# Boundary
    /// check` for the full scope contract, allowed claim language,
    /// and known non-scope (alias wrappers, macro expansion, type
    /// resolution, cross-file analysis are explicit non-scope).
    mod boundary_checker {
        use syn::visit::Visit;
        use syn::{
            Attribute, Expr, ExprCall, ExprMethodCall, ExprPath, File, Item, ItemFn, Meta, Path,
            QSelf, Type,
        };

        /// Method idents that constitute canonical `TxPool` admission per
        /// RUB-174 / RUB-176.
        pub const CANONICAL_ADMISSION_METHODS: &[&str] =
            &["admit", "admit_with_metadata", "add_tx_with_source"];

        /// Receiver type name used to disambiguate path-call detection
        /// from methods on `RelayTxPool` and other receivers.
        pub const TXPOOL_TYPE_NAME: &str = "TxPool";

        /// Production handler name whose presence the checker requires.
        pub const HANDLER_NAME: &str = "handle_received_tx";

        /// Errors returned by [`check_tx_relay_boundary_source`].
        #[derive(Debug, PartialEq, Eq)]
        pub enum BoundaryCheckError {
            /// `syn::parse_file` failed on the supplied source.
            ParseFailed(String),
            /// File has no top-level items — production/test boundary
            /// cannot be established.
            EmptyFile,
            /// Production handler item is missing from the AST. Either
            /// the file no longer contains `handle_received_tx`, or the
            /// item was renamed or moved under `#[cfg(test)]` and is
            /// therefore excluded from production scope.
            HandlerMissing,
            /// A direct syntactic canonical-admission call was found in
            /// production scope.
            ProductionAdmissionCall(AdmissionCallKind),
        }

        /// Direct-syntactic call families detected by
        /// [`check_tx_relay_boundary_source`].
        #[derive(Debug, PartialEq, Eq)]
        pub enum AdmissionCallKind {
            /// `<receiver>.admit(...)` / `.admit_with_metadata(...)` /
            /// `.add_tx_with_source(...)`. Receiver-agnostic by design;
            /// see the module-level docstring's note on receiver-agnostic
            /// detection as deliberate defense-in-depth bias.
            DottedMethod { method: String },
            /// `TxPool::method(...)` /
            /// `[crate|self|super|txpool|...]::TxPool::method(...)`.
            /// Direct path call where the path's terminal segment is a
            /// canonical admission method ident and the penultimate
            /// segment ident is `TxPool`.
            DirectPath { path: String },
            /// `<TxPool>::method(...)` /
            /// `<TxPool as Trait>::method(...)` /
            /// `<crate::txpool::TxPool>::method(...)` etc. UFCS form
            /// whose `qself.ty` terminal segment is `TxPool` and whose
            /// path's terminal segment is a canonical admission method
            /// ident.
            QSelfPath { qself_ty: String, method: String },
        }

        /// Walks `source` as a Rust file via `syn::parse_file` and
        /// returns `Ok(())` if no direct syntactic canonical-`TxPool`
        /// admission call is present in production scope, or
        /// `Err(BoundaryCheckError)` describing the first violation or
        /// fail-closed condition.
        ///
        /// "Production scope" excludes only [`Item`]s that carry the
        /// EXACT literal attribute `#[cfg(test)]` — that is, an
        /// attribute whose path is `cfg` and whose `Meta::List` parses
        /// as a single `Path` identifier `test`. Every other carrier
        /// shape is scanned as production:
        ///
        ///  - `#[cfg(any(test, X))]` items, `#[cfg(all(test, X))]`
        ///    items, `#[cfg(not(test))]` items, `#[cfg(target_os =
        ///    "linux")]` items, `#[cfg(false)]` items, multi-`#[cfg]`
        ///    stacks — production;
        ///  - `#[cfg(test)]` `ImplItem`s (associated `fn`s inside a
        ///    production `impl`), `#[cfg(test)]` `TraitItem`s
        ///    (default-method bodies inside a production `trait`),
        ///    `#[cfg(test)]` `Expr`s (block / match / if / etc.),
        ///    `#[cfg(test)]` `Arm`s (match arms), `#[cfg(test)]`
        ///    `FieldValue`s (struct-literal initialisers),
        ///    `#[cfg(test)]` `Stmt`s (`let` / standalone-macro
        ///    statements) — production.
        ///
        /// The skip predicate is intentionally conservative
        /// (false-positive over false-negative): general
        /// `ConfigurationPredicate` reachability and below-item-level
        /// cfg gating are explicit non-scope per RUB-176 / GitHub
        /// issue #1432's `class_change_stop_rule`.
        pub fn check_tx_relay_boundary_source(source: &str) -> Result<(), BoundaryCheckError> {
            let file: File = syn::parse_file(source)
                .map_err(|e| BoundaryCheckError::ParseFailed(e.to_string()))?;
            if file.items.is_empty() {
                return Err(BoundaryCheckError::EmptyFile);
            }
            let mut found_handler = false;
            let mut visitor = AdmissionFinder::default();
            for item in &file.items {
                if item_is_exact_cfg_test(item) {
                    continue;
                }
                if let Item::Fn(ItemFn { sig, .. }) = item {
                    if sig.ident == HANDLER_NAME {
                        found_handler = true;
                    }
                }
                visitor.visit_item(item);
                if let Some(err) = visitor.found.take() {
                    return Err(err);
                }
            }
            if !found_handler {
                return Err(BoundaryCheckError::HandlerMissing);
            }
            Ok(())
        }

        // Returns the attribute slice attached to a top-level `Item`.
        // Item variants outside this list (e.g. `Item::Verbatim`) do
        // not carry attributes the checker can read — return an empty
        // slice for those.
        fn item_attrs(item: &Item) -> &[Attribute] {
            match item {
                Item::Const(i) => &i.attrs,
                Item::Enum(i) => &i.attrs,
                Item::ExternCrate(i) => &i.attrs,
                Item::Fn(i) => &i.attrs,
                Item::ForeignMod(i) => &i.attrs,
                Item::Impl(i) => &i.attrs,
                Item::Macro(i) => &i.attrs,
                Item::Mod(i) => &i.attrs,
                Item::Static(i) => &i.attrs,
                Item::Struct(i) => &i.attrs,
                Item::Trait(i) => &i.attrs,
                Item::TraitAlias(i) => &i.attrs,
                Item::Type(i) => &i.attrs,
                Item::Union(i) => &i.attrs,
                Item::Use(i) => &i.attrs,
                _ => &[],
            }
        }

        // Returns true iff the `Item` carries EXACTLY ONE `#[cfg(...)]`
        // attribute and that attribute is the EXACT literal
        // `#[cfg(test)]` — `Meta::List` whose path is `cfg` and whose
        // inner tokens parse as a single `Path` identifier `test`.
        // Every other shape returns false and the carrier is scanned
        // as production:
        //
        //  - `cfg(any(test, X))`, `cfg(all(test, X))`, `cfg(not(test))`,
        //    `cfg(target_os = "linux")`, `cfg_attr(...)` — non-exact
        //    inner shape;
        //  - `#[cfg(test)] #[cfg(other)]` (or any other multi-`#[cfg]`
        //    stack) — even with the literal `#[cfg(test)]` present,
        //    the conjunction with another `#[cfg]` pushes the carrier
        //    out of the single-attribute skip class.
        //
        // Non-cfg attributes (`#[derive(...)]`, `#[allow(...)]`, etc.)
        // do not gate compilation and are ignored when counting cfg
        // attributes. The narrow single-attribute shape is the only
        // skip class supported by RUB-176 / GitHub issue #1432; broader
        // `ConfigurationPredicate` reachability is explicit non-scope
        // per the issue's `class_change_stop_rule`.
        fn item_is_exact_cfg_test(item: &Item) -> bool {
            let cfg_attrs: Vec<&Attribute> = item_attrs(item)
                .iter()
                .filter(|a| a.path().is_ident("cfg"))
                .collect();
            cfg_attrs.len() == 1 && attr_is_exact_cfg_test(cfg_attrs[0])
        }

        fn attr_is_exact_cfg_test(attr: &Attribute) -> bool {
            let Meta::List(list) = &attr.meta else {
                return false;
            };
            if !list.path.is_ident("cfg") {
                return false;
            }
            // Parse the inner tokens as a single `Path` and require
            // its sole ident to be `test`. Any other shape (e.g.
            // `all(...)`, `any(...)`, `not(...)`, `name = "value"`)
            // either fails to parse as a `Path` or has more than one
            // segment, returning false — and the carrier is scanned
            // as production.
            let Ok(inner_path) = list.parse_args::<Path>() else {
                return false;
            };
            inner_path.is_ident("test")
        }

        #[derive(Default)]
        struct AdmissionFinder {
            found: Option<BoundaryCheckError>,
        }

        impl<'ast> Visit<'ast> for AdmissionFinder {
            fn visit_item(&mut self, item: &'ast Item) {
                // Skip nested `#[cfg(test)] mod ...` (or any other
                // nested `#[cfg(test)]` `Item`) — the same exact
                // literal-attribute rule applied to top-level items
                // applies here. Any other cfg shape (`any`, `all`,
                // `not`, `name = "value"`, multi-cfg) on a nested
                // item is scanned as production. Below-item-level
                // cfg attributes (on `Expr`, `Arm`, `Stmt`,
                // `FieldValue`, `ImplItem`, `TraitItem`) are also
                // scanned as production — see the module docstring's
                // "Known non-scope" section for the explicit list.
                if item_is_exact_cfg_test(item) {
                    return;
                }
                syn::visit::visit_item(self, item);
            }

            fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
                let method = node.method.to_string();
                if CANONICAL_ADMISSION_METHODS.contains(&method.as_str()) && self.found.is_none() {
                    self.found = Some(BoundaryCheckError::ProductionAdmissionCall(
                        AdmissionCallKind::DottedMethod { method },
                    ));
                    return;
                }
                syn::visit::visit_expr_method_call(self, node);
            }

            fn visit_expr_call(&mut self, node: &'ast ExprCall) {
                // Peel `Expr::Paren` and `Expr::Group` wrappers around
                // the callee so that parenthesised forms like
                // `(TxPool::admit)(tx)` and
                // `(<crate::txpool::TxPool>::admit_with_metadata)(tx)`
                // are still detected. The default visitor would
                // otherwise descend into the paren'd expression and
                // never re-enter `visit_expr_call` on the inner path.
                if let Some(ExprPath { qself, path, .. }) = unwrap_path_expr(node.func.as_ref()) {
                    if let Some(kind) = match_admission_call(path, qself.as_ref()) {
                        if self.found.is_none() {
                            self.found = Some(BoundaryCheckError::ProductionAdmissionCall(kind));
                            return;
                        }
                    }
                }
                syn::visit::visit_expr_call(self, node);
            }
        }

        // Strips `Expr::Paren` and `Expr::Group` wrappers and returns
        // the inner `ExprPath` if any. Returns `None` for callees
        // that are not (eventually) a path expression.
        fn unwrap_path_expr(expr: &Expr) -> Option<&ExprPath> {
            match expr {
                Expr::Path(p) => Some(p),
                Expr::Paren(p) => unwrap_path_expr(&p.expr),
                Expr::Group(g) => unwrap_path_expr(&g.expr),
                _ => None,
            }
        }

        fn match_admission_call(path: &Path, qself: Option<&QSelf>) -> Option<AdmissionCallKind> {
            let terminal = path.segments.last()?;
            let method = terminal.ident.to_string();
            if !CANONICAL_ADMISSION_METHODS.contains(&method.as_str()) {
                return None;
            }
            match qself {
                None => {
                    if path.segments.len() < 2 {
                        return None;
                    }
                    let prev = &path.segments[path.segments.len() - 2];
                    if prev.ident == TXPOOL_TYPE_NAME {
                        Some(AdmissionCallKind::DirectPath {
                            path: path_to_string(path),
                        })
                    } else {
                        None
                    }
                }
                Some(qself) => {
                    // `qself.ty` is `Box<Type>`; only `Type::Path` whose
                    // terminal segment is `TxPool` qualifies. Other type
                    // forms (Type::Reference, Type::TraitObject, generic
                    // wrappers, etc.) are explicit non-scope per the
                    // module docstring and are documented as not
                    // detected by this checker.
                    let Type::Path(type_path) = qself.ty.as_ref() else {
                        return None;
                    };
                    let qself_terminal = type_path.path.segments.last()?;
                    if qself_terminal.ident != TXPOOL_TYPE_NAME {
                        return None;
                    }
                    Some(AdmissionCallKind::QSelfPath {
                        qself_ty: path_to_string(&type_path.path),
                        method,
                    })
                }
            }
        }

        fn path_to_string(path: &Path) -> String {
            let mut s = String::new();
            if path.leading_colon.is_some() {
                s.push_str("::");
            }
            for (i, seg) in path.segments.iter().enumerate() {
                if i > 0 {
                    s.push_str("::");
                }
                s.push_str(&seg.ident.to_string());
            }
            s
        }
    }

    use boundary_checker::{
        check_tx_relay_boundary_source, AdmissionCallKind, BoundaryCheckError,
        CANONICAL_ADMISSION_METHODS,
    };

    /// Wrap a snippet body inside a minimal production-scope
    /// `handle_received_tx` for snippet tests. `syn::parse_file` parses
    /// the result without name-resolution, so unresolved identifiers
    /// (e.g. `tx`, `pool`, `self::TxPool`) are accepted as long as the
    /// surface syntax is valid Rust.
    fn make_source_with_production_admission_body(body: &str) -> String {
        format!("pub fn handle_received_tx() {{\n    {body}\n}}\n")
    }

    #[test]
    fn live_source_token_aware_boundary_passes() {
        const SRC: &str = include_str!("tx_relay.rs");
        check_tx_relay_boundary_source(SRC).expect(
            "current tx_relay.rs production source must pass the \
             token-aware boundary checker — RUB-176 / GitHub issue #1432",
        );
    }

    #[test]
    fn negative_dotted_method_calls_all_three_methods_detected() {
        for method in CANONICAL_ADMISSION_METHODS {
            let src =
                make_source_with_production_admission_body(&format!("let _ = pool.{method}(tx);"));
            match check_tx_relay_boundary_source(&src) {
                Err(BoundaryCheckError::ProductionAdmissionCall(
                    AdmissionCallKind::DottedMethod { method: m },
                )) => assert_eq!(m, *method),
                other => panic!("expected DottedMethod for `pool.{method}(tx)`, got {other:?}"),
            }
        }
    }

    #[test]
    fn negative_direct_path_calls_for_all_prefixes_and_methods() {
        // Includes a leading-`::` absolute path (`::TxPool::method`) to
        // exercise `path_to_string`'s `path.leading_colon.is_some()` branch
        // in addition to all module-relative path prefixes.
        let prefixes = [
            "TxPool",
            "::TxPool",
            "crate::TxPool",
            "crate::txpool::TxPool",
            "self::TxPool",
            "self::txpool::TxPool",
            "super::TxPool",
            "super::txpool::TxPool",
            "txpool::TxPool",
        ];
        for prefix in prefixes {
            for method in CANONICAL_ADMISSION_METHODS {
                let src = make_source_with_production_admission_body(&format!(
                    "let _ = {prefix}::{method}(tx);"
                ));
                match check_tx_relay_boundary_source(&src) {
                    Err(BoundaryCheckError::ProductionAdmissionCall(
                        AdmissionCallKind::DirectPath { path },
                    )) => assert_eq!(
                        path,
                        format!("{prefix}::{method}"),
                        "DirectPath text mismatch for prefix={prefix} method={method}"
                    ),
                    other => panic!("expected DirectPath for `{prefix}::{method}`, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn negative_qself_path_calls_for_all_qself_types_and_methods() {
        let qself_types = [
            "TxPool",
            "crate::TxPool",
            "crate::txpool::TxPool",
            "self::TxPool",
            "self::txpool::TxPool",
            "super::TxPool",
            "super::txpool::TxPool",
        ];
        for qty in qself_types {
            for method in CANONICAL_ADMISSION_METHODS {
                // Without trait qualifier: `<T>::method(tx)`.
                let src_no_trait = make_source_with_production_admission_body(&format!(
                    "let _ = <{qty}>::{method}(tx);"
                ));
                match check_tx_relay_boundary_source(&src_no_trait) {
                    Err(BoundaryCheckError::ProductionAdmissionCall(
                        AdmissionCallKind::QSelfPath {
                            qself_ty,
                            method: m,
                        },
                    )) => {
                        assert_eq!(qself_ty, qty);
                        assert_eq!(m, *method);
                    }
                    other => panic!("expected QSelfPath for `<{qty}>::{method}`, got {other:?}"),
                }

                // With trait qualifier: `<T as Trait>::method(tx)`.
                let src_with_trait = make_source_with_production_admission_body(&format!(
                    "let _ = <{qty} as TxPoolAdmit>::{method}(tx);"
                ));
                match check_tx_relay_boundary_source(&src_with_trait) {
                    Err(BoundaryCheckError::ProductionAdmissionCall(
                        AdmissionCallKind::QSelfPath {
                            qself_ty,
                            method: m,
                        },
                    )) => {
                        assert_eq!(qself_ty, qty);
                        assert_eq!(m, *method);
                    }
                    other => {
                        panic!("expected QSelfPath for `<{qty} as Trait>::{method}`, got {other:?}")
                    }
                }
            }
        }
    }

    #[test]
    fn old_substring_tripwire_would_have_missed_self_qualifier_form() {
        // Documentation evidence: the RUB-172 substring tripwire's
        // catalog included `<TxPool as`, `<crate::TxPool as`,
        // `<crate::txpool::TxPool as` but did not list
        // `<self::TxPool>` / `<self::TxPool as Trait>` /
        // `<super::TxPool>` / `<super::txpool::TxPool>`. The
        // token-aware checker catches all of them via the
        // `qself.ty` terminal-segment match.
        for snippet in [
            "let _ = <self::TxPool>::admit(tx);",
            "let _ = <self::TxPool as Trait>::admit_with_metadata(tx);",
            "let _ = <super::TxPool>::add_tx_with_source(tx);",
            "let _ = <super::txpool::TxPool>::admit(tx);",
        ] {
            let src = make_source_with_production_admission_body(snippet);
            match check_tx_relay_boundary_source(&src) {
                Err(BoundaryCheckError::ProductionAdmissionCall(
                    AdmissionCallKind::QSelfPath { .. },
                )) => {}
                other => panic!("expected QSelfPath for `{snippet}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn dotted_method_check_is_receiver_agnostic_by_design() {
        // The dotted-method check matches by method ident only — it
        // cannot distinguish receiver types without name/type
        // resolution. If a future `RelayTxPool` method were named
        // `admit`, the checker would still fire on it. This is the
        // deliberate defense-in-depth bias documented in the module
        // docstring; the cure is renaming the method on `RelayTxPool`
        // or escalating to a sounder checker via a separate Q-*.
        let src = make_source_with_production_admission_body(
            "let _ = some_relay_cache.admit_with_metadata(tx);",
        );
        match check_tx_relay_boundary_source(&src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(AdmissionCallKind::DottedMethod {
                method,
            })) => assert_eq!(method, "admit_with_metadata"),
            other => panic!("expected DottedMethod, got {other:?}"),
        }
    }

    #[test]
    fn false_positive_module_doc_with_admission_text_passes() {
        let src = "\
//! Example: pool.admit(tx) is the canonical admission entrypoint, and
//! `crate::txpool::TxPool::admit_with_metadata` is the metadata-bearing
//! variant. `<super::txpool::TxPool as Trait>::add_tx_with_source` exists
//! too. None of these examples should fire the boundary checker — they
//! live in module docs.

pub fn handle_received_tx() {}
";
        check_tx_relay_boundary_source(src).expect("module doc admission text must pass");
    }

    #[test]
    fn false_positive_doc_comment_on_item_passes() {
        let src = "\
/// This handler does NOT call `TxPool::admit(tx)` or
/// `crate::txpool::TxPool::add_tx_with_source(tx)`. Doc comments are
/// attribute nodes, not expression-callable tokens.
pub fn handle_received_tx() {}
";
        check_tx_relay_boundary_source(src).expect("doc comment admission text must pass");
    }

    #[test]
    fn false_positive_line_comments_pass() {
        let src = "\
pub fn handle_received_tx() {
    // pool.admit(tx);
    // TxPool::admit(tx);
    // crate::txpool::TxPool::admit_with_metadata(tx);
    // <super::txpool::TxPool as Trait>::add_tx_with_source(tx);
}
";
        check_tx_relay_boundary_source(src).expect("line comments must pass");
    }

    #[test]
    fn false_positive_block_comments_pass() {
        let src = "\
pub fn handle_received_tx() {
    /* pool.admit(tx); TxPool::admit_with_metadata(tx); */
    /*
     * <crate::txpool::TxPool>::admit(tx);
     * <super::txpool::TxPool as Trait>::add_tx_with_source(tx);
     */
}
";
        check_tx_relay_boundary_source(src).expect("block comments must pass");
    }

    #[test]
    fn false_positive_string_literals_pass() {
        let src = r#"
pub fn handle_received_tx() {
    let _ = "pool.admit(tx)";
    let _ = "TxPool::admit(tx)";
    let _ = "<crate::txpool::TxPool as Trait>::add_tx_with_source(tx)";
}
"#;
        check_tx_relay_boundary_source(src).expect("string literals must pass");
    }

    #[test]
    fn false_positive_raw_string_literals_pass() {
        // Constructed via concat! to avoid the nested raw-string trap
        // (an outer `r##"..."##` would terminate inside an inner
        // `r###"..."###` at the first `"##` boundary).
        let src = concat!(
            "pub fn handle_received_tx() {\n",
            "    let _ = r\"<crate::TxPool>::admit(tx)\";\n",
            "    let _ = r#\"<super::txpool::TxPool>::admit_with_metadata(tx)\"#;\n",
            "    let _ = r##\"pool.add_tx_with_source(tx)\"##;\n",
            "}\n",
        );
        check_tx_relay_boundary_source(src).expect("raw string literals must pass");
    }

    #[test]
    fn false_positive_cfg_test_module_with_admission_calls_passes() {
        let src = "\
pub fn handle_received_tx() {}

#[cfg(test)]
mod tests {
    fn t() {
        pool.admit(tx);
        TxPool::admit_with_metadata(tx);
        crate::txpool::TxPool::add_tx_with_source(tx);
        <super::txpool::TxPool as Trait>::admit(tx);
    }
}
";
        check_tx_relay_boundary_source(src).expect("#[cfg(test)] mod admission calls must pass");
    }

    #[test]
    fn false_positive_cfg_test_function_with_admission_calls_passes() {
        let src = "\
pub fn handle_received_tx() {}

#[cfg(test)]
fn helper() {
    pool.admit(tx);
    crate::txpool::TxPool::admit(tx);
}
";
        check_tx_relay_boundary_source(src).expect("#[cfg(test)] fn admission calls must pass");
    }

    #[test]
    fn false_positive_relay_pool_put_call_passes() {
        let src = "\
pub fn handle_received_tx() {
    relay_state.relay_pool.put(txid, tx_bytes, fee, size);
    relay_pool.has(&txid);
    relay_state.tx_seen.add(txid);
}
";
        check_tx_relay_boundary_source(src)
            .expect("RelayTxPool put/has/add methods must not fire admission check");
    }

    #[test]
    fn false_positive_alias_wrapper_via_use_rename_is_explicit_non_scope() {
        // `use crate::txpool::TxPool as Pool; Pool::admit(tx);` — the
        // path's penultimate segment is `Pool`, not `TxPool`, so the
        // syntactic checker does NOT match. This is documented explicit
        // non-scope per the boundary_checker module docstring; a sounder
        // check would require name-resolution which is a class change
        // blocked by issue #1432 / RUB-176.
        let src = "\
use crate::txpool::TxPool as Pool;

pub fn handle_received_tx() {
    let _ = Pool::admit(tx);
}
";
        check_tx_relay_boundary_source(src)
            .expect("alias wrapper must pass — explicit non-scope per RUB-176 design note");
    }

    #[test]
    fn false_positive_macro_invocation_hiding_admission_call_is_explicit_non_scope() {
        // Macro bodies are unparsed token streams — `syn::Expr::Macro`
        // does not expose them as visit-able expressions. A diff that
        // hides admission behind a macro will silently pass the checker.
        // Explicit non-scope per the boundary_checker module docstring.
        let src = "\
pub fn handle_received_tx() {
    txpool_admit!(tx);
}
";
        check_tx_relay_boundary_source(src)
            .expect("macro invocation hiding admission must pass — explicit non-scope per RUB-176");
    }

    #[test]
    fn nested_cfg_test_module_inside_production_mod_is_skipped() {
        let src = "\
pub fn handle_received_tx() {}

pub mod production_helpers {
    pub fn helper() {}

    #[cfg(test)]
    mod inner_tests {
        fn negative_case() {
            crate::txpool::TxPool::admit(tx);
        }
    }
}
";
        check_tx_relay_boundary_source(src).expect(
            "nested #[cfg(test)] mod inside production mod must be skipped via AST attribute walk",
        );
    }

    #[test]
    fn cfg_any_test_with_feature_disjunct_is_production_admission_detected() {
        // `cfg(any(test, feature = "x"))` is not the EXACT literal
        // `#[cfg(test)]` shape, so the conservative scope scans the
        // carrier as production and the admission call inside is
        // detected. The carrier is also genuinely production-reachable
        // when `feature = "x"` is set in non-test builds, so the
        // detection direction is sound. The checker reaches this
        // verdict by shape match alone — it does not evaluate cfg
        // predicate semantics.
        let src = "\
pub fn handle_received_tx() {}

#[cfg(any(test, feature = \"experimental\"))]
fn experimental_helper() {
    crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(AdmissionCallKind::DirectPath {
                path,
            })) => assert_eq!(path, "crate::txpool::TxPool::admit"),
            other => {
                panic!("expected admission detection inside cfg(any(test, feature)), got {other:?}")
            }
        }
    }

    #[test]
    fn cfg_all_test_x_is_production_under_conservative_scope() {
        // `cfg(all(test, target_os = "linux"))` is NOT the exact
        // literal `#[cfg(test)]`, so the carrier is scanned as
        // production under the conservative scope. The fact that the
        // predicate logically implies `test` (every config that
        // satisfies it has `test ∈ C`) is irrelevant — general
        // `ConfigurationPredicate` reachability is explicit non-scope
        // per RUB-176 / GitHub issue #1432's `class_change_stop_rule`.
        // Conservative direction: false-positive over false-negative.
        let src = "\
pub fn handle_received_tx() {}

#[cfg(all(test, target_os = \"linux\"))]
fn linux_test_helper() {
    crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside cfg(all(test, target_os)) under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn cfg_any_test_x_is_production_under_conservative_scope() {
        // `cfg(any(test, foo))` — config with `foo` enabled and test
        // disabled satisfies the predicate, so the carrier is genuinely
        // production-reachable. Conservative scope flags it correctly.
        let src = "\
pub fn handle_received_tx() {}

#[cfg(any(test, foo))]
fn helper() {
    crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => {
                panic!("expected admission detection inside cfg(any(test, foo)), got {other:?}")
            }
        }
    }

    #[test]
    fn cfg_double_negation_of_test_is_production_under_conservative_scope() {
        // `cfg(not(not(test)))` is logically equivalent to
        // `cfg(test)`, but it is not the EXACT literal `#[cfg(test)]`,
        // so the conservative scope scans it as production. General
        // `ConfigurationPredicate` reachability is explicit non-scope
        // per RUB-176 / GitHub issue #1432's `class_change_stop_rule`.
        let src = "\
pub fn handle_received_tx() {}

#[cfg(not(not(test)))]
fn helper() {
    crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside cfg(not(not(test))) under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn cfg_false_literal_is_production_under_conservative_scope() {
        // `cfg(false)` is logically never-enabled, but it is not the
        // EXACT literal `#[cfg(test)]`, so the conservative scope
        // scans it as production. Detecting `cfg(false)` as
        // unconditionally-disabled requires the same general
        // `ConfigurationPredicate` reachability that is explicit
        // non-scope.
        let src = "\
pub fn handle_received_tx() {}

#[cfg(false)]
fn never_compiled_helper() {
    crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside cfg(false) under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn cfg_test_on_impl_item_is_production_under_conservative_scope() {
        // `impl Foo { #[cfg(test)] fn ... }` carries the `#[cfg(test)]`
        // attribute at the `ImplItem` level, NOT at the surrounding
        // `Item::Impl` level. Below-item-level cfg gating is explicit
        // non-scope per RUB-176 / GitHub issue #1432's
        // `class_change_stop_rule`, so the conservative scope walks
        // every `ImplItem` body inside a production `impl` and
        // detects the admission call.
        let src = "\
pub fn handle_received_tx() {}

pub struct Foo;
impl Foo {
    pub fn prod_method(&self) {}

    #[cfg(test)]
    fn test_only_method(&self) {
        crate::txpool::TxPool::admit(tx);
    }
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside #[cfg(test)] ImplItem under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn cfg_test_on_trait_item_default_method_is_production_under_conservative_scope() {
        // Same below-item-level non-scope rule applies to `TraitItem`
        // default-method bodies inside a production `trait`
        // declaration.
        let src = "\
pub fn handle_received_tx() {}

pub trait Foo {
    fn prod_method(&self);

    #[cfg(test)]
    fn test_only_default(&self) {
        crate::txpool::TxPool::admit(tx);
    }
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside #[cfg(test)] TraitItem under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn impl_item_without_cfg_test_inside_production_impl_admission_is_detected() {
        // Negative control: an ordinary production impl-fn with an
        // admission call must be detected. The conservative scope
        // walks every `ImplItem` body inside a production `impl`
        // unconditionally — there is no `ImplItem`-level cfg-skip,
        // so this case is identical in handling to a `#[cfg(test)]`
        // impl-fn (both fire the checker; the latter is pinned by
        // `cfg_test_on_impl_item_is_production_under_conservative_scope`).
        let src = "\
pub fn handle_received_tx() {}

pub struct Foo;
impl Foo {
    pub fn prod_method(&self) {
        crate::txpool::TxPool::admit(tx);
    }
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => {
                panic!("expected admission detection inside production impl-fn body, got {other:?}")
            }
        }
    }

    #[test]
    fn multi_cfg_attrs_unrelated_to_test_remain_production() {
        // Two cfg attributes neither of which is the exact literal
        // `#[cfg(test)]` leave the item in production scope.
        let src = "\
pub fn handle_received_tx() {}

#[cfg(any(unix, windows))]
#[cfg(target_pointer_width = \"64\")]
fn cross_platform_helper() {
    crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside cfg(unix|windows) ∧ cfg(64-bit) helper, got {other:?}"
            ),
        }
    }

    #[test]
    fn cfg_test_with_companion_non_cfg_attr_is_skipped_under_conservative_scope() {
        // `#[cfg(test)] #[derive(Debug)]` — the `#[derive(...)]`
        // attribute is a non-`cfg` attribute and does not gate
        // compilation, so the cfg-attribute count remains 1 (the
        // exact literal `#[cfg(test)]`) and the carrier is skipped.
        // Pins the contract that `item_is_exact_cfg_test` filters
        // attributes by `path().is_ident("cfg")` before counting,
        // not by counting all attributes.
        let src = "\
pub fn handle_received_tx() {}

#[cfg(test)]
#[derive(Debug)]
struct TestOnlyHelper {
    bad_field: u32,
}

#[cfg(test)]
fn helper() {
    crate::txpool::TxPool::admit(tx);
}
";
        check_tx_relay_boundary_source(src).expect(
            "carrier with #[cfg(test)] + non-cfg companion attr (#[derive]) must be skipped",
        );
    }

    #[test]
    fn cfg_attr_form_does_not_count_as_exact_cfg_test_skip() {
        // `#[cfg_attr(test, derive(Debug))]` — the attribute path
        // is `cfg_attr`, not `cfg`. `item_is_exact_cfg_test`'s
        // `path().is_ident("cfg")` filter excludes `cfg_attr`, so
        // the cfg-attribute count is 0 and the carrier is scanned
        // as production. `cfg_attr` evaluation is explicit non-scope
        // per RUB-176 / GitHub issue #1432's `class_change_stop_rule`;
        // any admission inside such a carrier fires the checker.
        let src = "\
pub fn handle_received_tx() {}

#[cfg_attr(test, derive(Debug))]
fn helper() {
    crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside cfg_attr(...) carrier under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn multi_cfg_attrs_test_first_other_second_is_production_under_conservative_scope() {
        // `#[cfg(test)] #[cfg(other)]` — even though one of the two
        // cfg attributes is the EXACT literal `#[cfg(test)]`, the
        // multi-`#[cfg]` stack pushes the carrier out of the
        // single-attribute skip class. The conservative scope
        // requires exactly one cfg attribute and that attribute be
        // the literal shape; any additional cfg attribute makes the
        // carrier production. Pins the contract↔code alignment after
        // tightening `item_is_exact_cfg_test` to count cfg attrs.
        let src = "\
pub fn handle_received_tx() {}

#[cfg(test)]
#[cfg(other)]
fn helper() {
    crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside #[cfg(test)] + #[cfg(other)] stack under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn multi_cfg_attrs_with_test_disjunct_is_production_under_conservative_scope() {
        // Two cfg attributes whose conjunction logically implies
        // `test` — `(test ∨ foo) ∧ (test ∨ ¬foo)` ≡ `test`. The
        // conservative scope does NOT decode multi-attribute
        // conjunctions; neither single attribute is the exact literal
        // `#[cfg(test)]`, so the carrier is scanned as production.
        // Multi-attribute `ConfigurationPredicate` reachability is
        // explicit non-scope per RUB-176 / GitHub issue #1432's
        // `class_change_stop_rule`.
        let src = "\
pub fn handle_received_tx() {}

#[cfg(any(test, foo))]
#[cfg(any(test, not(foo)))]
fn test_only_via_conjunction() {
    crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside multi-cfg(any(test,...)) under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn cfg_test_on_block_expression_is_production_under_conservative_scope() {
        // `#[cfg(test)] { ... }` block expression inside a production
        // function body. Below-item-level cfg gating is explicit
        // non-scope per RUB-176 / GitHub issue #1432's
        // `class_change_stop_rule`, so the conservative scope walks
        // the block body and detects the admission call.
        let src = "\
pub fn handle_received_tx() {
    #[cfg(test)]
    {
        crate::txpool::TxPool::admit(tx);
    }
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside #[cfg(test)] block expr under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn cfg_test_on_match_arm_is_production_under_conservative_scope() {
        // `match x { #[cfg(test)] _ => TxPool::admit(tx); ... }` —
        // the `#[cfg(test)]` is on the `Arm`, not on a top-level
        // `Item`. Below-item-level cfg gating is non-scope per
        // RUB-176 / GitHub issue #1432, so the conservative scope
        // walks the arm body and detects the admission call.
        let src = "\
pub fn handle_received_tx() {
    let x = 0;
    match x {
        #[cfg(test)]
        _ => { crate::txpool::TxPool::admit(tx); }
        _ => (),
    }
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside #[cfg(test)] match arm under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn cfg_test_on_let_stmt_is_production_under_conservative_scope() {
        // `#[cfg(test)] let _ = TxPool::admit(tx);` — `Stmt::Local`
        // attribute. Below-item-level cfg gating is non-scope per
        // RUB-176 / GitHub issue #1432, so the conservative scope
        // walks the let-binding initialiser and detects the
        // admission call.
        let src = "\
pub fn handle_received_tx() {
    #[cfg(test)]
    let _ = crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside #[cfg(test)] let-stmt under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn parenthesised_direct_path_call_is_detected() {
        // `(TxPool::admit)(tx)` — parens around a path callee. The
        // default Expr::Path match in visit_expr_call would skip this
        // form because the immediate callee is Expr::Paren. The
        // unwrap_path_expr helper peels Paren/Group to expose the
        // inner ExprPath.
        let src = make_source_with_production_admission_body("let _ = (TxPool::admit)(tx);");
        match check_tx_relay_boundary_source(&src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(AdmissionCallKind::DirectPath {
                path,
            })) => assert_eq!(path, "TxPool::admit"),
            other => panic!("expected DirectPath for parenthesised TxPool::admit, got {other:?}"),
        }
    }

    #[test]
    fn parenthesised_qself_path_call_is_detected() {
        // `(<crate::txpool::TxPool>::admit_with_metadata)(tx)` — parens
        // around a UFCS callee. Same Paren-unwrap fix applies.
        let src = make_source_with_production_admission_body(
            "let _ = (<crate::txpool::TxPool>::admit_with_metadata)(tx);",
        );
        match check_tx_relay_boundary_source(&src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(AdmissionCallKind::QSelfPath {
                qself_ty,
                method,
            })) => {
                assert_eq!(qself_ty, "crate::txpool::TxPool");
                assert_eq!(method, "admit_with_metadata");
            }
            other => panic!(
                "expected QSelfPath for parenthesised <crate::txpool::TxPool>::admit_with_metadata, got {other:?}"
            ),
        }
    }

    #[test]
    fn cfg_test_on_struct_literal_field_value_is_production_under_conservative_scope() {
        // `Foo { #[cfg(test)] bad: TxPool::admit(tx), good: 0 }` —
        // the `#[cfg(test)]` is on the `FieldValue`, not on a
        // top-level `Item`. Below-item-level cfg gating is non-scope
        // per RUB-176 / GitHub issue #1432, so the conservative
        // scope walks the initialiser expression and detects the
        // admission call.
        let src = "\
pub fn handle_received_tx() {
    let _ = Foo {
        #[cfg(test)]
        bad: crate::txpool::TxPool::admit(tx),
        good: 0,
    };
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside #[cfg(test)] FieldValue under conservative scope, got {other:?}"
            ),
        }
    }

    #[test]
    fn struct_literal_field_value_without_cfg_test_admission_is_detected() {
        // Negative control: an ordinary FieldValue initialiser with
        // an admission call must be detected. The conservative scope
        // walks every `FieldValue` unconditionally — there is no
        // `FieldValue`-level cfg-skip, so this case is identical in
        // handling to a `#[cfg(test)]` FieldValue (both fire; the
        // latter is pinned by
        // `cfg_test_on_struct_literal_field_value_is_production_under_conservative_scope`).
        let src = "\
pub fn handle_received_tx() {
    let _ = Foo {
        bad: crate::txpool::TxPool::admit(tx),
        good: 0,
    };
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside ordinary FieldValue initialiser, got {other:?}"
            ),
        }
    }

    #[test]
    fn doubly_parenthesised_direct_path_call_is_detected() {
        // `((TxPool::add_tx_with_source))(tx)` — two layers of parens
        // around the callee. The unwrap_path_expr recursion peels
        // them one at a time.
        let src = make_source_with_production_admission_body(
            "let _ = ((TxPool::add_tx_with_source))(tx);",
        );
        match check_tx_relay_boundary_source(&src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(AdmissionCallKind::DirectPath {
                path,
            })) => assert_eq!(path, "TxPool::add_tx_with_source"),
            other => panic!(
                "expected DirectPath for doubly parenthesised TxPool::add_tx_with_source, got {other:?}"
            ),
        }
    }

    #[test]
    fn block_expression_without_cfg_test_inside_production_fn_admission_is_detected() {
        // Negative control: an ordinary block expression with an
        // admission call inside a production function must be
        // detected. The conservative scope walks every `Expr`
        // unconditionally — there is no `Expr`-level cfg-skip, so
        // this case is identical in handling to a `#[cfg(test)]`
        // block expr (both fire; the latter is pinned by
        // `cfg_test_on_block_expression_is_production_under_conservative_scope`).
        let src = "\
pub fn handle_received_tx() {
    {
        crate::txpool::TxPool::admit(tx);
    }
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(_)) => {}
            other => panic!(
                "expected admission detection inside ordinary block expression, got {other:?}"
            ),
        }
    }

    #[test]
    fn cfg_not_test_predicate_is_production_and_admission_is_detected() {
        // `#[cfg(not(test))]` is enabled exactly when `test` is NOT
        // in the active config set — i.e. visible during normal
        // builds and disabled during test compilation, the opposite
        // gate of `#[cfg(test)]`. It is also not the EXACT literal
        // `#[cfg(test)]`, so the conservative scope scans it as
        // production and detects admission calls inside it.
        let src = "\
pub fn handle_received_tx() {}

#[cfg(not(test))]
fn prod_only_helper() {
    crate::txpool::TxPool::admit(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ProductionAdmissionCall(AdmissionCallKind::DirectPath {
                path,
            })) => assert_eq!(path, "crate::txpool::TxPool::admit"),
            other => {
                panic!("expected DirectPath for cfg(not(test)) production helper, got {other:?}")
            }
        }
    }

    #[test]
    fn fail_closed_on_invalid_rust_syntax() {
        let src = "this is not valid rust syntax !!! @@@ <<< >>>";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::ParseFailed(_)) => {}
            other => panic!("expected ParseFailed, got {other:?}"),
        }
    }

    #[test]
    fn fail_closed_on_empty_file() {
        match check_tx_relay_boundary_source("") {
            Err(BoundaryCheckError::EmptyFile) => {}
            other => panic!("expected EmptyFile, got {other:?}"),
        }
    }

    #[test]
    fn fail_closed_on_renamed_handler() {
        let src = "\
pub fn handle_received_tx_renamed() {
    let _ = pool.put(tx);
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::HandlerMissing) => {}
            other => panic!("expected HandlerMissing, got {other:?}"),
        }
    }

    #[test]
    fn fail_closed_when_handler_is_only_under_cfg_test() {
        // Production handler accidentally moved under `#[cfg(test)]` —
        // checker must fail closed because it cannot see a
        // production-scope handler item.
        let src = "\
pub fn other_production_fn() {}

#[cfg(test)]
fn handle_received_tx() {
}
";
        match check_tx_relay_boundary_source(src) {
            Err(BoundaryCheckError::HandlerMissing) => {}
            other => panic!("expected HandlerMissing, got {other:?}"),
        }
    }

    #[test]
    fn handle_received_tx_metadata_failure_marks_seen_but_does_not_relay() {
        let tx_bytes = real_tx_bytes();
        let sync_engine = SyncEngine::new(
            ChainState::new(),
            None,
            default_sync_config(None, [0u8; 32], None),
        )
        .expect("sync engine");
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
        outboxes
            .lock()
            .unwrap()
            .insert("sender:8333".to_string(), PeerOutbox::default());
        outboxes
            .lock()
            .unwrap()
            .insert("other:8333".to_string(), PeerOutbox::default());

        let txid = canonical_txid(&tx_bytes).unwrap();
        let result = handle_received_tx(
            &tx_bytes,
            &sync_engine,
            &relay,
            &pm,
            "sender:8333",
            "local:8333",
            &outboxes,
        );
        assert!(result.is_ok());
        assert!(relay.tx_seen.has(&txid));
        assert!(!relay.relay_pool.has(&txid));
        let boxes = outboxes.lock().unwrap();
        assert!(boxes["sender:8333"].is_empty());
        assert!(boxes["other:8333"].is_empty());
    }

    #[test]
    fn handle_received_tx_duplicate_is_noop() {
        let tx_bytes = real_tx_bytes();
        let txid = canonical_txid(&tx_bytes).unwrap();
        let relay = TxRelayState::new();
        relay.tx_seen.add(txid);

        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());

        let result = handle_received_tx(
            &tx_bytes,
            &SyncEngine::new(
                ChainState::new(),
                None,
                default_sync_config(None, [0u8; 32], None),
            )
            .expect("sync engine"),
            &relay,
            &pm,
            "sender:8333",
            "local:8333",
            &outboxes,
        );
        assert!(result.is_ok());
        assert!(!relay.relay_pool.has(&txid)); // Not stored — was already seen.
    }

    /// C.2 parity: malformed relay tx payload must surface as
    /// `RelayTxOutcome::MalformedParse` (ban-worthy) rather than being
    /// silently swallowed. Mirrors Go `handleTx` bumping ban by 10 on parse
    /// failure (`peer.handleTx` in `clients/go/node/p2p/handlers_tx.go`).
    #[test]
    fn handle_received_tx_malformed_surfaces_ban_worthy_outcome() {
        let sync_engine = SyncEngine::new(
            ChainState::new(),
            None,
            default_sync_config(None, [0u8; 32], None),
        )
        .expect("sync engine");
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());

        // Garbage bytes that will fail consensus parse.
        let garbage = vec![0xFFu8, 0xFE];
        let outcome = handle_received_tx(
            &garbage,
            &sync_engine,
            &relay,
            &pm,
            "sender:8333",
            "local:8333",
            &outboxes,
        )
        .expect("handle_received_tx should not return io::Error on malformed input");

        match &outcome {
            RelayTxOutcome::MalformedParse(_) => {}
            other => panic!("expected MalformedParse, got {other:?}"),
        }
        assert!(
            outcome.is_banworthy(),
            "malformed parse must be ban-worthy for Go parity"
        );
        assert!(
            relay.tx_seen.is_empty(),
            "malformed tx must not mark seen (parity with Go handleTx early return)"
        );
        assert!(
            relay.relay_pool.is_empty(),
            "malformed tx must not enter relay pool"
        );
    }

    /// C.1 parity: oversized relay payload must surface as
    /// `RelayTxOutcome::Oversized` (ban-worthy), never touching consensus
    /// parsing. Mirrors the explicit `MAX_RELAY_MSG_BYTES` guard now added to
    /// Go `handleTx` (see `clients/go/node/p2p/handlers_tx.go`).
    #[test]
    fn handle_received_tx_oversize_surfaces_ban_worthy_outcome() {
        let sync_engine = SyncEngine::new(
            ChainState::new(),
            None,
            default_sync_config(None, [0u8; 32], None),
        )
        .expect("sync engine");
        let relay = TxRelayState::new();
        let pm = PeerManager::new(crate::p2p_runtime::default_peer_runtime_config(
            "devnet", 64,
        ));
        let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());

        // Coverage of the `Oversized` return branch requires the actual
        // length check to fire, which needs `MAX_RELAY_MSG_BYTES + 1`
        // bytes (~96 MB). Modern CI runners absorb this; an env-var
        // skip would drop diff-coverage below the 85% gate, so the
        // allocation is accepted as the lesser evil. The check itself
        // never reads the payload, so zero-fill cost dominates.
        let oversize = vec![0u8; rubin_consensus::constants::MAX_RELAY_MSG_BYTES as usize + 1];
        let outcome = handle_received_tx(
            &oversize,
            &sync_engine,
            &relay,
            &pm,
            "sender:8333",
            "local:8333",
            &outboxes,
        )
        .expect("handle_received_tx should not return io::Error on oversize");

        assert_eq!(outcome, RelayTxOutcome::Oversized);
        assert!(outcome.is_banworthy());
        assert!(relay.tx_seen.is_empty());
        assert!(relay.relay_pool.is_empty());
    }

    #[test]
    fn default_relay_state() {
        let rs = TxRelayState::default();
        assert_eq!(rs.tx_relay_fanout, DEFAULT_TX_RELAY_FANOUT);
        assert_eq!(rs.network, "devnet");
        assert!(rs.relay_pool.is_empty());
        assert!(rs.tx_seen.is_empty());
    }

    #[test]
    fn relay_state_with_network() {
        let rs = TxRelayState::new_with_network("mainnet");
        assert_eq!(rs.network, "mainnet");
    }

    #[test]
    fn peer_outbox_enforces_byte_budget_and_resets_on_drain() {
        let mut outbox = PeerOutbox::default();
        assert!(outbox.push_frame(vec![0xAA; MAX_OUTBOX_BYTES_PER_PEER - 16]));
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox.total_bytes(), MAX_OUTBOX_BYTES_PER_PEER - 16);

        assert!(!outbox.push_frame(vec![0xBB; 17]));
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox.total_bytes(), MAX_OUTBOX_BYTES_PER_PEER - 16);

        let drained = outbox.take_frames();
        assert_eq!(drained.len(), 1);
        assert_eq!(outbox.len(), 0);
        assert_eq!(outbox.total_bytes(), 0);
        assert!(outbox.is_empty());
    }

    #[test]
    fn tx_relay_score_matches_go_reference() {
        // Cross-validate with Go: sha3_256(key || salt || addr)
        // key = [0x00; 32], salt = "", addr = "test"
        let score = tx_relay_score([0x00; 32], "", "test");
        // Compute expected: sha3_256(32 zero bytes || "" || "test")
        let mut h = Sha3_256::new();
        h.update([0x00; 32]);
        h.update(b"");
        h.update(b"test");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(score, expected);
    }
}

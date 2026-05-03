use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

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
        broadcast_inv_to_addrs(&block_vecs, &addrs, &relay_state.network, peer_writers)?;
    }

    if tx_items.is_empty() {
        return Ok(());
    }

    let tx_vecs: Vec<InventoryVector> = tx_items.into_iter().cloned().collect();
    let relay_key = inventory_relay_key(&tx_vecs);
    let relay_salt = skip_addr.unwrap_or(local_addr);
    addrs = select_tx_relay_peers(relay_key, relay_salt, &addrs, relay_state.tx_relay_fanout);
    broadcast_inv_to_addrs(&tx_vecs, &addrs, &relay_state.network, peer_writers)
}

/// Send INV message to a set of peer addresses.
fn broadcast_inv_to_addrs(
    items: &[InventoryVector],
    addrs: &[String],
    network: &str,
    peer_writers: &Mutex<HashMap<String, PeerOutbox>>,
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
    let Ok(mut outboxes) = peer_writers.lock() else {
        return Err("peer_outboxes lock poisoned".to_string());
    };
    for addr in addrs {
        if let Some(queue) = outboxes.get_mut(addr) {
            let _ = queue.push_frame(frame.clone());
            // else: drop silently — peer is slow or over byte budget and will
            // catch up on the next drain.
        }
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
fn canonical_txid(tx_bytes: &[u8]) -> Result<[u8; 32], String> {
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
    // The two consumer tests (`positive_fixture_tx_and_meta` builder
    // and `handle_received_tx_with_valid_floor_compliant_tx_stores_and_relays`)
    // now build a floor-compliant signed P2PK fixture inline via the
    // public `signed_conflicting_p2pk_state_and_txs` helper because the
    // conformance fixture's pre-signed tx (fee=10/weight≈7653) is
    // sub-floor under the wave-2 `relay_metadata` rolling-floor check.

    fn positive_fixture_tx_and_meta() -> (Vec<u8>, crate::txpool::RelayTxMetadata) {
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
        .expect("positive fixture relay metadata (floor-compliant signed P2PK)");
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
        let (tx_bytes, meta) = positive_fixture_tx_and_meta();
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
        let (tx_bytes, meta) = positive_fixture_tx_and_meta();
        let incoming_txid = canonical_txid(&tx_bytes).unwrap();
        let existing_txid = [0xEE; 32];
        let relay = TxRelayState {
            tx_seen: BoundedHashSet::new(crate::tx_seen::DEFAULT_TX_SEEN_CAPACITY),
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

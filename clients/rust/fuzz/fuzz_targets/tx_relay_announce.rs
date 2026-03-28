#![no_main]

use std::collections::HashMap;
use std::sync::Mutex;

use libfuzzer_sys::fuzz_target;
use rubin_node::p2p_runtime::{default_peer_runtime_config, PeerManager, PeerState};
use rubin_node::tx_relay::{announce_tx, PeerOutbox, TxRelayState};
use rubin_node::txpool::RelayTxMetadata;
use rubin_node::build_coinbase_tx;

const MAX_PEERS: usize = 8;
const MAX_RAW_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
struct AnnounceSnapshot {
    result: Result<(), String>,
    tx_seen_len: usize,
    relay_pool_len: usize,
    outboxes: HashMap<String, PeerOutbox>,
}

fn sample_tx_bytes(mode: u8, data: &[u8]) -> Vec<u8> {
    let base = build_coinbase_tx(0, 0, &[], [0x11; 32]).expect("coinbase fixture");
    match mode % 3 {
        0 => base,
        1 => {
            let mut mutated = base;
            if mutated.is_empty() {
                return mutated;
            }
            let flips = data.len().clamp(1, 4);
            for i in 0..flips {
                let idx = usize::from(data.get(i).copied().unwrap_or(0)) % mutated.len();
                mutated[idx] ^= data.get(i + 4).copied().unwrap_or(0x5a);
            }
            mutated
        }
        _ => data[..data.len().min(MAX_RAW_BYTES)].to_vec(),
    }
}

fn selected_network(tag: u8) -> &'static str {
    match tag % 3 {
        0 => "devnet",
        1 => "testnet",
        2 => "opsnet",
        _ => "opsnet",
    }
}

fn build_peer_state(addr: String) -> PeerState {
    PeerState {
        addr,
        ..PeerState::default()
    }
}

fn run_once(
    network: &str,
    peer_count: usize,
    fanout: usize,
    tx_bytes: &[u8],
    meta: RelayTxMetadata,
) -> AnnounceSnapshot {
    let relay = {
        let mut relay = TxRelayState::new_with_network(network);
        relay.tx_relay_fanout = fanout;
        relay
    };
    let peer_manager = PeerManager::new(default_peer_runtime_config(network, peer_count.max(1)));
    let outboxes: Mutex<HashMap<String, PeerOutbox>> = Mutex::new(HashMap::new());
    for idx in 0..peer_count {
        let addr = format!("peer-{idx}:8333");
        let _ = peer_manager.add_peer(build_peer_state(addr.clone()));
        outboxes
            .lock()
            .expect("peer outboxes")
            .insert(addr, PeerOutbox::default());
    }

    let result = announce_tx(tx_bytes, meta, &relay, &peer_manager, "local:8333", &outboxes);
    let outboxes_snapshot = outboxes.lock().expect("peer outboxes").clone();
    AnnounceSnapshot {
        result,
        tx_seen_len: relay.tx_seen.len(),
        relay_pool_len: relay.relay_pool.len(),
        outboxes: outboxes_snapshot,
    }
}

fn assert_outbox_invariants(snapshot: &AnnounceSnapshot) {
    let nonempty = snapshot
        .outboxes
        .values()
        .filter(|queue| !queue.is_empty())
        .count();
    for queue in snapshot.outboxes.values() {
        let frame_bytes: usize = queue.frames().iter().map(Vec::len).sum();
        assert_eq!(queue.total_bytes(), frame_bytes);
        assert!(queue.len() <= 1, "announce_tx should enqueue at most one INV frame");
        assert!(queue.total_bytes() <= (1 << 20));
    }

    if snapshot.result.is_ok() && !snapshot.outboxes.is_empty() {
        let configured_fanout = snapshot.outboxes.len();
        assert!(nonempty <= configured_fanout);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    let peer_count = usize::from(data[0] % (MAX_PEERS as u8 + 1));
    let fanout = usize::from(data[1]) % (MAX_PEERS + 2);
    let tx_bytes = sample_tx_bytes(data[2], &data[8..]);
    let fee = u64::from_le_bytes(data[3..11].try_into().unwrap_or([0u8; 8]));
    let size = usize::from(u16::from_le_bytes([data[11], data[12]]));
    let network = selected_network(data[13]);
    let meta = RelayTxMetadata { fee, size };

    let first = run_once(network, peer_count, fanout, &tx_bytes, meta);
    let second = run_once(network, peer_count, fanout, &tx_bytes, meta);

    assert_eq!(first, second, "announce_tx runtime path must be deterministic");
    assert_outbox_invariants(&first);

    if first.result.is_ok() {
        assert_eq!(first.tx_seen_len, first.relay_pool_len);
        if peer_count == 0 {
            assert!(first.outboxes.values().all(PeerOutbox::is_empty));
        } else if first.relay_pool_len == 1 {
            let nonempty = first
                .outboxes
                .values()
                .filter(|queue| !queue.is_empty())
                .count();
            let expected = if fanout == 0 || fanout >= peer_count {
                peer_count
            } else {
                fanout
            };
            assert_eq!(nonempty, expected);
        }
    } else {
        assert_eq!(first.tx_seen_len, 0);
        assert_eq!(first.relay_pool_len, 0);
        assert!(first.outboxes.values().all(PeerOutbox::is_empty));
    }
});

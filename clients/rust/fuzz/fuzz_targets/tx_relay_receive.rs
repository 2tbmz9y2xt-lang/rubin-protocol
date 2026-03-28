#![no_main]

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use libfuzzer_sys::fuzz_target;
use rubin_node::p2p_runtime::{default_peer_runtime_config, PeerManager, PeerState};
use rubin_node::tx_relay::{handle_received_tx, PeerOutbox, TxRelayState};
use rubin_node::{build_coinbase_tx, default_sync_config, ChainState, SyncEngine};

const MAX_PEERS: usize = 6;
const MAX_RAW_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiveSnapshot {
    result: String,
    tx_seen_len: usize,
    relay_pool_len: usize,
    outboxes: BTreeMap<String, PeerOutbox>,
}

fn sample_tx_bytes(mode: u8, data: &[u8]) -> Vec<u8> {
    let base = build_coinbase_tx(1, 0, &rubin_node::default_mine_address(), [0x22; 32])
        .expect("coinbase fixture");
    match mode % 4 {
        0 => base,
        1 => {
            let mut mutated = base;
            if mutated.is_empty() {
                return mutated;
            }
            let flips = data.len().clamp(1, 4);
            for i in 0..flips {
                let idx = usize::from(data.get(i).copied().unwrap_or(0)) % mutated.len();
                mutated[idx] ^= data.get(i + 4).copied().unwrap_or(0xa5);
            }
            mutated
        }
        2 => base[..base.len().saturating_sub(1)].to_vec(),
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

fn sync_engine_for(network: &str) -> SyncEngine {
    let mut cfg = default_sync_config(None, [0u8; 32], None);
    cfg.network = network.to_string();
    SyncEngine::new(ChainState::new(), None, cfg).expect("sync engine")
}

fn run_once(network: &str, peer_count: usize, tx_bytes: &[u8]) -> ReceiveSnapshot {
    let relay = TxRelayState::new_with_network(network);
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

    let sync_engine = sync_engine_for(network);
    let result = handle_received_tx(
        tx_bytes,
        &sync_engine,
        &relay,
        &peer_manager,
        "peer-0:8333",
        "local:8333",
        &outboxes,
    );
    let outboxes_snapshot = outboxes
        .lock()
        .expect("peer outboxes")
        .iter()
        .map(|(addr, queue)| (addr.clone(), queue.clone()))
        .collect();
    ReceiveSnapshot {
        result: match result {
            Ok(()) => "ok".to_string(),
            Err(err) => format!("{:?}:{}", err.kind(), err),
        },
        tx_seen_len: relay.tx_seen.len(),
        relay_pool_len: relay.relay_pool.len(),
        outboxes: outboxes_snapshot,
    }
}

fn run_twice_same_state(network: &str, peer_count: usize, tx_bytes: &[u8]) -> (ReceiveSnapshot, ReceiveSnapshot) {
    let relay = TxRelayState::new_with_network(network);
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
    let sync_engine = sync_engine_for(network);

    let first_result = handle_received_tx(
        tx_bytes,
        &sync_engine,
        &relay,
        &peer_manager,
        "peer-0:8333",
        "local:8333",
        &outboxes,
    );
    let first_outboxes = outboxes
        .lock()
        .expect("peer outboxes")
        .iter()
        .map(|(addr, queue)| (addr.clone(), queue.clone()))
        .collect();
    let first = ReceiveSnapshot {
        result: match first_result {
            Ok(()) => "ok".to_string(),
            Err(err) => format!("{:?}:{}", err.kind(), err),
        },
        tx_seen_len: relay.tx_seen.len(),
        relay_pool_len: relay.relay_pool.len(),
        outboxes: first_outboxes,
    };

    let second_result = handle_received_tx(
        tx_bytes,
        &sync_engine,
        &relay,
        &peer_manager,
        "peer-0:8333",
        "local:8333",
        &outboxes,
    );
    let second_outboxes = outboxes
        .lock()
        .expect("peer outboxes")
        .iter()
        .map(|(addr, queue)| (addr.clone(), queue.clone()))
        .collect();
    let second = ReceiveSnapshot {
        result: match second_result {
            Ok(()) => "ok".to_string(),
            Err(err) => format!("{:?}:{}", err.kind(), err),
        },
        tx_seen_len: relay.tx_seen.len(),
        relay_pool_len: relay.relay_pool.len(),
        outboxes: second_outboxes,
    };
    (first, second)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let peer_count = usize::from(data[0] % (MAX_PEERS as u8 + 1));
    let network = selected_network(data[1]);
    let mode = data[2];
    let tx_bytes = sample_tx_bytes(mode, &data[3..]);

    let first = run_once(network, peer_count, &tx_bytes);
    let second = run_once(network, peer_count, &tx_bytes);
    assert_eq!(first, second, "handle_received_tx must be deterministic on fresh state");

    if mode % 4 == 2 {
        assert_ne!(first.result, "ok");
        assert_eq!(first.tx_seen_len, 0);
        assert_eq!(first.relay_pool_len, 0);
        assert!(first.outboxes.values().all(PeerOutbox::is_empty));
    }

    let (before, after) = run_twice_same_state(network, peer_count, &tx_bytes);
    assert_eq!(after.tx_seen_len, before.tx_seen_len);
    assert_eq!(after.relay_pool_len, before.relay_pool_len);
    assert_eq!(after.outboxes, before.outboxes);

    for queue in after.outboxes.values() {
        let frame_bytes: usize = queue.frames().iter().map(Vec::len).sum();
        assert_eq!(queue.total_bytes(), frame_bytes);
        assert!(queue.len() <= 1);
        assert!(queue.total_bytes() <= (1 << 20));
    }
});

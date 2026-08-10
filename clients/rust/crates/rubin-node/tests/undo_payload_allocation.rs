use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};

use rubin_consensus::{block_hash, Outpoint, UtxoEntry, BLOCK_HEADER_BYTES};
use rubin_node::undo::{BlockUndo, SpentUndo, TxUndo};
use rubin_node::{devnet_genesis_block_bytes, BlockStore};
use sha3::{Digest, Sha3_256};

const ROWS: usize = 1 << 17;
const MARGIN: isize = 1 << 20;
const TREE_BYTES: usize = std::mem::size_of::<TxUndo>() + std::mem::size_of::<SpentUndo>();
const INVALID_SUPPLY: [&str; 2] = [
    "decode undo: envelope v1 previous_already_generated must be a nonnegative JSON integer through u64",
    "decode undo: envelope v2 previous_already_generated must be a canonical unsigned decimal string within u128",
];
struct CountingAllocator;
static ARMED: AtomicBool = AtomicBool::new(false);
static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);
fn signed(size: usize) -> isize {
    isize::try_from(size).unwrap_or(isize::MAX)
}

fn adjust(delta: isize) {
    if !ARMED.load(Ordering::Relaxed) {
        return;
    }
    let old = LIVE.fetch_add(delta, Ordering::Relaxed);
    let live = old.saturating_add(delta);
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every pointer/layout is passed to System unchanged; bookkeeping is atomic only.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        adjust(signed(l.size()));
        System.alloc(l)
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        adjust(signed(l.size()));
        System.alloc_zeroed(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        adjust(-signed(l.size()));
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        adjust(signed(n).saturating_sub(signed(l.size())));
        System.realloc(p, l, n)
    }
}

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

fn measure<T>(run: impl FnOnce() -> T) -> (T, isize) {
    LIVE.store(0, Ordering::Relaxed);
    PEAK.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let value = run();
    ARMED.store(false, Ordering::Relaxed);
    (value, PEAK.load(Ordering::Relaxed))
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let word = u32::from(c[0]) << 16
            | u32::from(*c.get(1).unwrap_or(&0)) << 8
            | u32::from(*c.get(2).unwrap_or(&0));
        for (shift, needed) in [(18, 0), (12, 0), (6, 1), (0, 2)] {
            out.push(if c.len() > needed {
                TABLE[((word >> shift) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn envelope(version: u32, hash: [u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut digest = Sha3_256::new();
    let domain: &[u8] = if version == 1 {
        b"RUBIN_BLOCK_UNDO_V1"
    } else {
        b"RUBIN_BLOCK_UNDO_V2"
    };
    digest.update(domain);
    digest.update(hash);
    digest.update((payload.len() as u64).to_be_bytes());
    digest.update(payload);
    (format!(
        r#"{{"version":{version},"block_hash":"{}","payload_b64":"{}","checksum":"{}"}}"#,
        hex::encode(hash),
        base64(payload),
        hex::encode(digest.finalize())
    ) + "\n")
        .into_bytes()
}

fn payload(supply: &str, data: &[u8]) -> Vec<u8> {
    let spent = format!(
        r#"{{"txid":"{}","vout":2,"value":3,"covenant_type":4,"covenant_data":"{}","creation_height":5,"created_by_coinbase":true}}"#,
        hex::encode([1u8; 32]),
        hex::encode(data)
    );
    format!(
        r#"{{"block_height":0,"previous_already_generated":{supply},"txs":[{{"spent":[{spent}]}}]}}"#
    )
    .into_bytes()
}

fn invalid_payload(supply: &str) -> Vec<u8> {
    let rows = "{\"spent\":[]}".to_owned() + &",{\"spent\":[]}".repeat(ROWS - 1);
    format!(r#"{{"block_height":0,"previous_already_generated":{supply},"txs":[{rows}]}}"#)
        .into_bytes()
}

fn get_peak_limit(raw: &[u8], payload: &[u8], data: &[u8]) -> isize {
    let disk = signed(payload.len()).saturating_add(signed(TREE_BYTES));
    let runtime = signed(data.len()).saturating_add(signed(TREE_BYTES));
    signed(raw.len())
        .saturating_add(
            signed(payload.len())
                .saturating_add(disk)
                .max(disk.saturating_add(runtime)),
        )
        .saturating_add(MARGIN)
}

fn existing_peak_limit(raw: &[u8], payload: &[u8]) -> isize {
    // <=2P payload Vec, <=R base64 and <=2R envelope Vec fit 4R+P because R >= P.
    let candidate_encode = signed(raw.len())
        .saturating_mul(4)
        .saturating_add(signed(payload.len()));
    let existing_decode = signed(raw.len())
        .saturating_mul(2)
        .saturating_add(signed(payload.len()).saturating_mul(2))
        .saturating_add(signed(TREE_BYTES));
    candidate_encode.max(existing_decode).saturating_add(MARGIN)
}

#[test]
fn undo_payload_public_paths_have_bounded_allocation() {
    let genesis = devnet_genesis_block_bytes();
    let header = &genesis[..BLOCK_HEADER_BYTES];
    let hash = block_hash(header).expect("genesis hash");
    let name = format!("{}.json", hex::encode(hash));
    let pid = std::process::id();
    let mut corpus = Vec::with_capacity(4);
    for (version, supply) in [(1, "7"), (2, "\"7\"")] {
        for size in [8 << 20, 12 << 20] {
            let undo = BlockUndo {
                block_height: 0,
                previous_already_generated: 7,
                txs: vec![TxUndo {
                    spent: vec![SpentUndo {
                        outpoint: Outpoint {
                            txid: [1; 32],
                            vout: 2,
                        },
                        entry: UtxoEntry {
                            value: 3,
                            covenant_type: 4,
                            covenant_data: vec![0xab; size],
                            creation_height: 5,
                            created_by_coinbase: true,
                        },
                    }],
                }],
            };
            let data = &undo.txs[0].spent[0].entry.covenant_data;
            let payload = payload(supply, data);
            let raw = envelope(version, hash, &payload);
            corpus.push((version, undo, payload, raw));
        }
    }
    let invalid_payloads = [invalid_payload("\"0\""), invalid_payload("0")];
    let invalid_raws = [
        envelope(1, hash, &invalid_payloads[0]),
        envelope(2, hash, &invalid_payloads[1]),
    ]; // All corpus bytes exist before arming.
    let different = BlockUndo {
        block_height: 0,
        previous_already_generated: 8,
        txs: vec![],
    };
    let (_held, control) = measure(|| vec![0u8; MARGIN as usize]);
    assert!(
        control >= MARGIN,
        "counting allocator missed held allocation"
    );
    for (version, undo, payload, raw) in &corpus {
        let size = undo.txs[0].spent[0].entry.covenant_data.len() >> 20;
        let root = std::env::temp_dir().join(format!("rubin-undo-{version}-{size}-{pid}"));
        let _ = std::fs::remove_dir_all(&root);
        let mut store = BlockStore::create(&root).expect("create store");
        let path = root.join("undo").join(&name);
        std::fs::write(&path, raw).expect("seed undo");
        let (got, get_peak) = measure(|| store.get_undo(hash).expect("public get"));
        assert_eq!(&got, undo);
        assert!(
            get_peak <= get_peak_limit(raw, payload, &undo.txs[0].spent[0].entry.covenant_data),
            "v{version} {size} MiB get {get_peak}"
        );
        drop(got);
        let mut commit =
            |candidate| store.commit_canonical_block(0, hash, header, &genesis, candidate);
        let (_, commit_peak) = measure(|| commit(undo).expect("existing-file commit"));
        assert!(
            commit_peak <= existing_peak_limit(raw, payload),
            "v{version} {size} MiB commit {commit_peak}"
        );
        // Small Q makes a restored Ue conversion add the large existing U above this decoder-only ceiling.
        let (_, different_peak) = measure(|| commit(&different).expect_err("different existing"));
        assert!(
            different_peak <= get_peak_limit(raw, payload, &[]),
            "v{version} {size} MiB different {different_peak}"
        );
        assert_eq!(
            std::fs::read(&path).expect("read undo"),
            *raw,
            "v{version} {size} MiB rewrote undo"
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }
    for (index, (payload, raw)) in invalid_payloads.iter().zip(&invalid_raws).enumerate() {
        let version = index + 1;
        let root = std::env::temp_dir().join(format!("rubin-undo-invalid-{version}-{pid}"));
        let _ = std::fs::remove_dir_all(&root);
        let store = BlockStore::create(&root).expect("create invalid store");
        std::fs::write(root.join("undo").join(&name), raw).expect("seed invalid undo");
        let (err, invalid_peak) = measure(|| store.get_undo(hash).expect_err("invalid supply"));
        assert_eq!(err, INVALID_SUPPLY[index], "v{version} invalid supply");
        assert!(
            invalid_peak
                <= signed(raw.len())
                    .saturating_add(signed(payload.len()))
                    .saturating_add(MARGIN),
            "v{version} invalid supply {invalid_peak}"
        );
        std::fs::remove_dir_all(root).expect("cleanup");
    }
}

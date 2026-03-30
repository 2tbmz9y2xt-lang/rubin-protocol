#[path = "bench_support.rs"]
mod bench_support;

use std::env;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use rubin_consensus::constants::{
    COV_TYPE_DA_COMMIT, MAX_DA_CHUNK_COUNT, MAX_DA_MANIFEST_BYTES_PER_TX, MAX_WITNESS_BYTES_PER_TX,
    TX_WIRE_VERSION,
};
use rubin_consensus::{
    encode_compact_size, parse_tx, validate_block_basic_with_context_at_height, Tx, TxInput,
    TxOutput,
};

use bench_support::{
    build_block_bytes, coinbase_with_witness_commitment, filled32, sha3_256, tx_ids,
};

const DEFAULT_UNKNOWN_SUITE_TXS: usize = 8;
const DEFAULT_DA_CHUNKS: usize = 32;
const DEFAULT_CHUNK_BYTES: usize = 65_536;
const DEFAULT_UNKNOWN_SUITE_SIG_BYTES: usize = 49_856;
const UNKNOWN_SUITE_PUBKEY_BYTES: usize = 64;

fn compact_size_len(value: u64) -> usize {
    match value {
        0x00..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn max_unknown_suite_sig_bytes(pubkey_len: usize) -> usize {
    let base_overhead = 1 + 1 + compact_size_len(pubkey_len as u64) + pubkey_len;
    let mut sig_len = MAX_WITNESS_BYTES_PER_TX.saturating_sub(base_overhead);
    while sig_len + compact_size_len(sig_len as u64) + base_overhead > MAX_WITNESS_BYTES_PER_TX {
        sig_len -= 1;
    }
    sig_len
}

fn bench_env_usize(key: &str, default: usize, min: usize, max: usize) -> usize {
    let Ok(raw) = env::var(key) else {
        return default;
    };
    let parsed = raw.parse::<usize>().expect("valid usize env");
    assert!(
        parsed >= min && parsed <= max,
        "{key}={parsed} out of range [{min},{max}]"
    );
    parsed
}

fn bench_unknown_suite_tx(tx_nonce: u64, suite_id: u8, pubkey: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut tx = Tx {
        version: TX_WIRE_VERSION,
        tx_kind: 0x00,
        tx_nonce,
        inputs: vec![TxInput {
            prev_txid: filled32(tx_nonce as u8),
            prev_vout: 0,
            script_sig: Vec::new(),
            sequence: 0,
        }],
        outputs: vec![TxOutput {
            value: 1,
            covenant_type: rubin_consensus::constants::COV_TYPE_P2PK,
            covenant_data: rubin_consensus::p2pk_covenant_data_for_pubkey(&[0x11; 2592]),
        }],
        locktime: 0,
        da_commit_core: None,
        da_chunk_core: None,
        witness: vec![rubin_consensus::WitnessItem {
            suite_id,
            pubkey: pubkey.to_vec(),
            signature: signature.to_vec(),
        }],
        da_payload: Vec::new(),
    };
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    out.push(tx.tx_kind);
    out.extend_from_slice(&tx.tx_nonce.to_le_bytes());
    encode_compact_size(tx.inputs.len() as u64, &mut out);
    for input in tx.inputs.drain(..) {
        out.extend_from_slice(&input.prev_txid);
        out.extend_from_slice(&input.prev_vout.to_le_bytes());
        encode_compact_size(input.script_sig.len() as u64, &mut out);
        out.extend_from_slice(&input.script_sig);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    encode_compact_size(tx.outputs.len() as u64, &mut out);
    for output in tx.outputs.drain(..) {
        out.extend_from_slice(&output.value.to_le_bytes());
        out.extend_from_slice(&output.covenant_type.to_le_bytes());
        encode_compact_size(output.covenant_data.len() as u64, &mut out);
        out.extend_from_slice(&output.covenant_data);
    }
    out.extend_from_slice(&tx.locktime.to_le_bytes());
    encode_compact_size(tx.witness.len() as u64, &mut out);
    for witness in tx.witness.drain(..) {
        out.push(witness.suite_id);
        encode_compact_size(witness.pubkey.len() as u64, &mut out);
        out.extend_from_slice(&witness.pubkey);
        encode_compact_size(witness.signature.len() as u64, &mut out);
        out.extend_from_slice(&witness.signature);
    }
    encode_compact_size(0, &mut out);
    out
}

fn da_commit_tx_bytes(
    tx_nonce: u64,
    da_id: [u8; 32],
    chunk_count: u16,
    payload_commitment: [u8; 32],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TX_WIRE_VERSION.to_le_bytes());
    out.push(0x01);
    out.extend_from_slice(&tx_nonce.to_le_bytes());
    encode_compact_size(1, &mut out);
    out.extend_from_slice(&filled32(tx_nonce as u8));
    out.extend_from_slice(&0u32.to_le_bytes());
    encode_compact_size(0, &mut out);
    out.extend_from_slice(&0u32.to_le_bytes());
    encode_compact_size(1, &mut out);
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&COV_TYPE_DA_COMMIT.to_le_bytes());
    encode_compact_size(32, &mut out);
    out.extend_from_slice(&payload_commitment);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&da_id);
    out.extend_from_slice(&chunk_count.to_le_bytes());
    out.extend_from_slice(&[0x10u8; 32]);
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&[0x11u8; 32]);
    out.extend_from_slice(&[0x12u8; 32]);
    out.extend_from_slice(&[0x13u8; 32]);
    out.push(0x00);
    encode_compact_size(0, &mut out);
    encode_compact_size(0, &mut out);
    encode_compact_size(0, &mut out);
    out
}

fn da_chunk_tx_bytes(
    tx_nonce: u64,
    da_id: [u8; 32],
    chunk_index: u16,
    chunk_hash: [u8; 32],
    da_payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&TX_WIRE_VERSION.to_le_bytes());
    out.push(0x02);
    out.extend_from_slice(&tx_nonce.to_le_bytes());
    encode_compact_size(1, &mut out);
    out.extend_from_slice(&filled32(tx_nonce as u8));
    out.extend_from_slice(&0u32.to_le_bytes());
    encode_compact_size(0, &mut out);
    out.extend_from_slice(&0u32.to_le_bytes());
    encode_compact_size(0, &mut out);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&da_id);
    out.extend_from_slice(&chunk_index.to_le_bytes());
    out.extend_from_slice(&chunk_hash);
    encode_compact_size(0, &mut out);
    encode_compact_size(da_payload.len() as u64, &mut out);
    out.extend_from_slice(da_payload);
    out
}

fn build_combined_load_fixture() -> (Vec<u8>, [u8; 32], [u8; 32], u64) {
    let unknown_suite_txs = bench_env_usize(
        "RUBIN_COMBINED_LOAD_UNKNOWN_SUITE_TXS",
        DEFAULT_UNKNOWN_SUITE_TXS,
        1,
        64,
    );
    let da_chunks = bench_env_usize(
        "RUBIN_COMBINED_LOAD_DA_CHUNKS",
        DEFAULT_DA_CHUNKS,
        1,
        MAX_DA_CHUNK_COUNT as usize,
    );
    let chunk_bytes = bench_env_usize(
        "RUBIN_COMBINED_LOAD_CHUNK_BYTES",
        DEFAULT_CHUNK_BYTES,
        1,
        MAX_DA_MANIFEST_BYTES_PER_TX as usize,
    );
    let unknown_suite_sig_bytes = bench_env_usize(
        "RUBIN_COMBINED_LOAD_UNKNOWN_SUITE_SIG_BYTES",
        DEFAULT_UNKNOWN_SUITE_SIG_BYTES,
        1,
        max_unknown_suite_sig_bytes(UNKNOWN_SUITE_PUBKEY_BYTES),
    );

    let height = 1u64;
    let unknown_suite_pub = vec![0x42; UNKNOWN_SUITE_PUBKEY_BYTES];
    let unknown_suite_sig = vec![0x5a; unknown_suite_sig_bytes];
    let mut nonce = 1u64;

    let mut non_coinbase = Vec::with_capacity(unknown_suite_txs + 1 + da_chunks);
    for _ in 0..unknown_suite_txs {
        non_coinbase.push(bench_unknown_suite_tx(
            nonce,
            0x02,
            &unknown_suite_pub,
            &unknown_suite_sig,
        ));
        nonce += 1;
    }

    let da_id = filled32(0xd7);
    let mut payload_concat = Vec::with_capacity(da_chunks * chunk_bytes);
    let mut chunk_payloads = Vec::with_capacity(da_chunks);
    for idx in 0..da_chunks {
        let fill = ((idx % 251) + 1) as u8;
        let payload = vec![fill; chunk_bytes];
        payload_concat.extend_from_slice(&payload);
        chunk_payloads.push(payload);
    }
    let payload_commitment = sha3_256(&payload_concat);
    non_coinbase.push(da_commit_tx_bytes(
        nonce,
        da_id,
        da_chunks as u16,
        payload_commitment,
    ));
    nonce += 1;

    for (idx, payload) in chunk_payloads.iter().enumerate() {
        non_coinbase.push(da_chunk_tx_bytes(
            nonce,
            da_id,
            idx as u16,
            sha3_256(payload),
            payload,
        ));
        nonce += 1;
    }

    let coinbase = coinbase_with_witness_commitment(height as u32, &[], &non_coinbase);
    let mut txs = Vec::with_capacity(non_coinbase.len() + 1);
    txs.push(coinbase);
    txs.extend(non_coinbase);
    let merkle_root = {
        let txids = txs.iter().map(|tx| tx_ids(tx).0).collect::<Vec<_>>();
        rubin_consensus::merkle_root_txids(&txids).expect("merkle root")
    };
    let prev_hash = filled32(0x91);
    let target = filled32(0xff);
    let block = build_block_bytes(prev_hash, merkle_root, target, 31, &txs);
    let _ = parse_tx(&txs[0]).expect("parse coinbase");
    (block, prev_hash, target, height)
}

fn validate_block_basic_combined_load_bench(c: &mut Criterion) {
    let (block, prev_hash, target, height) = build_combined_load_fixture();
    validate_block_basic_with_context_at_height(
        &block,
        Some(prev_hash),
        Some(target),
        height,
        None,
    )
    .expect("combined-load fixture invalid");

    let mut group = c.benchmark_group("validate_block_basic_combined_load");
    group.throughput(Throughput::Bytes(block.len() as u64));
    group.bench_function("unknown_suite_plus_da", |b| {
        b.iter(|| {
            let summary = validate_block_basic_with_context_at_height(
                black_box(&block),
                Some(prev_hash),
                Some(target),
                height,
                None,
            )
            .expect("validate block");
            black_box(summary.tx_count);
        });
    });
    group.finish();
}

criterion_group!(
    combined_load_benches,
    validate_block_basic_combined_load_bench
);
criterion_main!(combined_load_benches);

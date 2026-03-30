#[path = "bench_support.rs"]
mod bench_support;

use std::collections::HashMap;

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};

use rubin_consensus::constants::COV_TYPE_P2PK;
use rubin_consensus::{
    connect_block_parallel_sig_verify, InMemoryChainState, Mldsa87Keypair, Outpoint, Tx, TxInput,
    TxOutput, UtxoEntry,
};

use bench_support::{
    block_merkle_root, build_block_bytes, coinbase_with_witness_commitment_and_p2pk_value,
    marshal_tx_expect, p2pk_covdata_for_keypair, sign_input_witness, subsidy_with_fees, tx_ids,
    ZERO_CHAIN_ID,
};

fn build_parallel_fixture(
    tx_count: usize,
) -> (Vec<u8>, [u8; 32], [u8; 32], u64, InMemoryChainState) {
    let prev = [0x77; 32];
    let target = [0xff; 32];
    let height = 1u64;

    let kp = Mldsa87Keypair::generate().expect("keypair");
    let cov_data = p2pk_covdata_for_keypair(&kp);
    let prev_out = Outpoint {
        txid: prev,
        vout: 0,
    };
    let start_value = 100u64 * tx_count as u64;
    let mut state = InMemoryChainState {
        utxos: HashMap::from([(
            prev_out,
            UtxoEntry {
                value: start_value,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
                creation_height: 0,
                created_by_coinbase: false,
            },
        )]),
        already_generated: 0,
    };

    let mut non_coinbase = Vec::with_capacity(tx_count);
    let mut prev_txid = prev;
    let mut cur_value = start_value;
    let mut fees = 0u64;

    for idx in 0..tx_count {
        let next_value = cur_value - 10;
        let mut tx = Tx {
            version: 1,
            tx_kind: 0x00,
            tx_nonce: (idx + 1) as u64,
            inputs: vec![TxInput {
                prev_txid,
                prev_vout: 0,
                script_sig: Vec::new(),
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: next_value,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: cov_data.clone(),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        };
        tx.witness = vec![sign_input_witness(&tx, 0, cur_value, &kp)];
        let tx_bytes = marshal_tx_expect(&tx);
        prev_txid = tx_ids(&tx_bytes).0;
        non_coinbase.push(tx_bytes);
        cur_value = next_value;
        fees += 10;
    }

    let coinbase = coinbase_with_witness_commitment_and_p2pk_value(
        height as u32,
        subsidy_with_fees(height, fees),
        &non_coinbase,
        cov_data,
    );
    let mut txs = Vec::with_capacity(non_coinbase.len() + 1);
    txs.push(coinbase);
    txs.extend(non_coinbase);
    let merkle_root = block_merkle_root(&txs);
    let block = build_block_bytes(prev, merkle_root, target, 1, &txs);

    black_box(&mut state);
    (block, prev, target, height, state)
}

fn connect_block_parallel_sig_verify_bench(c: &mut Criterion) {
    let worker_counts = {
        let mut counts = vec![1usize, 8usize, 16usize];
        let gomax = std::thread::available_parallelism()
            .map(|n| usize::max(2, n.get() * 2))
            .unwrap_or(2);
        if !counts.contains(&gomax) {
            counts.push(gomax);
        }
        counts
    };

    let tx_count = 8usize;
    let (block, prev, target, height, state) = build_parallel_fixture(tx_count);
    let mut group = c.benchmark_group("connect_block_parallel_sig_verify");
    group.throughput(Throughput::Bytes(block.len() as u64));

    for workers in worker_counts {
        group.bench_with_input(
            BenchmarkId::from_parameter(workers),
            &workers,
            |b, &workers| {
                b.iter_batched(
                    || state.clone(),
                    |mut state| {
                        let summary = connect_block_parallel_sig_verify(
                            black_box(&block),
                            Some(prev),
                            Some(target),
                            height,
                            Some(&[0]),
                            &mut state,
                            ZERO_CHAIN_ID,
                            workers,
                        )
                        .expect("parallel connect");
                        black_box(summary.sig_task_count);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(parallel_benches, connect_block_parallel_sig_verify_bench);
criterion_main!(parallel_benches);

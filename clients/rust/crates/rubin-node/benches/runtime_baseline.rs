#[path = "bench_support.rs"]
mod bench_support;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rubin_node::{devnet_genesis_chain_id, Miner, MinerConfig};
use std::time::{Duration, Instant};

use bench_support::{
    chain_state_with_spendable_utxos, engine_after_genesis, fresh_pool, fresh_sync_engine,
    fresh_txpool_fixture, large_block_undo_fixture,
};
use rubin_node::undo::build_block_undo;

fn txpool_admit_bench(c: &mut Criterion) {
    let (state, raw) = fresh_txpool_fixture();
    let mut group = c.benchmark_group("rubin_node_txpool");
    group.bench_function("admit", |b| {
        b.iter_batched(
            fresh_pool,
            |mut pool| {
                let _ = pool
                    .admit(&raw, &state, None, devnet_genesis_chain_id())
                    .expect("admit");
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("relay_metadata", |b| {
        b.iter_batched(
            fresh_pool,
            |pool| {
                let _ = pool
                    .relay_metadata_for_bytes(&raw, &state, None, devnet_genesis_chain_id())
                    .expect("relay_metadata");
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn chainstate_clone_bench(c: &mut Criterion) {
    let (state, _outpoints, _signer, _addr) = chain_state_with_spendable_utxos(256);
    let original_utxo_len = state.utxos.len();
    let clone = state.clone();
    assert_eq!(
        clone.utxos.len(),
        original_utxo_len,
        "chainstate clone preserves utxo set size"
    );
    c.bench_function("rubin_node_chainstate_clone", |b| {
        b.iter(|| {
            let _ = state.clone();
        })
    });
}

fn sync_snapshot_bench(c: &mut Criterion) {
    c.bench_function("rubin_node_sync_chain_state_snapshot", |b| {
        let fixture = engine_after_genesis("rubin-node-sync-snapshot");
        b.iter(|| {
            let _ = fixture.engine.chain_state_snapshot();
        });
        fixture.cleanup();
    });
}

fn sync_apply_disconnect_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("rubin_node_sync");
    group.bench_function("apply_genesis", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut fixture = fresh_sync_engine("rubin-node-sync-apply");
                let start = Instant::now();
                let _ = fixture
                    .engine
                    .apply_block(&rubin_node::devnet_genesis_block_bytes(), None)
                    .expect("apply genesis");
                total += start.elapsed();
                fixture.cleanup();
            }
            total
        })
    });
    group.bench_function("disconnect_tip_after_genesis", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut fixture = engine_after_genesis("rubin-node-sync-disconnect");
                let start = Instant::now();
                let _ = fixture.engine.disconnect_tip().expect("disconnect tip");
                total += start.elapsed();
                fixture.cleanup();
            }
            total
        })
    });
    group.finish();
}

fn sync_undo_large_block_bench(c: &mut Criterion) {
    let fixture = large_block_undo_fixture();
    let mut group = c.benchmark_group("rubin_node_undo");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("build_large_block", |b| {
        b.iter(|| {
            let _ = build_block_undo(
                &fixture.prev_state,
                &fixture.block_bytes,
                fixture.block_height,
            )
            .expect("build undo");
        })
    });
    group.bench_function("disconnect_large_block", |b| {
        b.iter_batched(
            || fixture.connected_state.clone(),
            |mut state| {
                let _ = state
                    .disconnect_block(&fixture.block_bytes, &fixture.undo)
                    .expect("disconnect");
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn miner_bench(c: &mut Criterion) {
    c.bench_function("rubin_node_miner_mine_one", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut fixture = fresh_sync_engine("rubin-node-miner-bench");
                let cfg = MinerConfig {
                    timestamp_source: || 1_777_000_000,
                    ..MinerConfig::default()
                };
                let start = Instant::now();
                let mut miner = Miner::new(&mut fixture.engine, None, cfg).expect("miner");
                let _ = miner.mine_one(&[]).expect("mine one");
                total += start.elapsed();
                drop(miner);
                fixture.cleanup();
            }
            total
        })
    });
}

criterion_group!(
    runtime_baseline_benches,
    txpool_admit_bench,
    chainstate_clone_bench,
    sync_snapshot_bench,
    sync_apply_disconnect_bench,
    sync_undo_large_block_bench,
    miner_bench
);
criterion_main!(runtime_baseline_benches);

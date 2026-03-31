#[path = "bench_support.rs"]
mod bench_support;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rubin_node::{devnet_genesis_chain_id, Miner, MinerConfig};

use bench_support::{
    chain_state_with_spendable_utxos, engine_after_genesis, fresh_pool, fresh_sync_engine,
    fresh_txpool_fixture, SyncFixture,
};

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
    c.bench_function("rubin_node_chainstate_clone", |b| {
        b.iter(|| {
            let _ = state.clone();
        })
    });
}

fn sync_snapshot_bench(c: &mut Criterion) {
    let fixture = engine_after_genesis("rubin-node-sync-snapshot");
    c.bench_function("rubin_node_sync_chain_state_snapshot", |b| {
        b.iter(|| {
            let _ = fixture.engine.chain_state_snapshot();
        })
    });
}

fn sync_apply_disconnect_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("rubin_node_sync");
    group.bench_function("apply_genesis", |b| {
        b.iter_batched(
            || fresh_sync_engine("rubin-node-sync-apply"),
            |mut fixture: SyncFixture| {
                let _ = fixture
                    .engine
                    .apply_block(&rubin_node::devnet_genesis_block_bytes(), None)
                    .expect("apply genesis");
                fixture.cleanup();
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("disconnect_tip_after_genesis", |b| {
        b.iter_batched(
            || engine_after_genesis("rubin-node-sync-disconnect"),
            |mut fixture: SyncFixture| {
                let _ = fixture.engine.disconnect_tip().expect("disconnect tip");
                fixture.cleanup();
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn miner_bench(c: &mut Criterion) {
    c.bench_function("rubin_node_miner_mine_one", |b| {
        b.iter_batched(
            || fresh_sync_engine("rubin-node-miner-bench"),
            |mut fixture: SyncFixture| {
                let cfg = MinerConfig {
                    timestamp_source: || 1_777_000_000,
                    ..MinerConfig::default()
                };
                let mut miner = Miner::new(&mut fixture.engine, None, cfg).expect("miner");
                let _ = miner.mine_one(&[]).expect("mine one");
                drop(miner);
                fixture.cleanup();
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    runtime_baseline_benches,
    txpool_admit_bench,
    chainstate_clone_bench,
    sync_snapshot_bench,
    sync_apply_disconnect_bench,
    miner_bench
);
criterion_main!(runtime_baseline_benches);

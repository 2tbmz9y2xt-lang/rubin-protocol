use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use rubin_consensus::constants::SUITE_ID_ML_DSA_87;
use rubin_consensus::{Mldsa87Keypair, SigCache};

fn sig_cache_lookup_hit(c: &mut Criterion) {
    let kp = Mldsa87Keypair::generate().expect("keypair");
    let digest = [0x42; 32];
    let sig = kp.sign_digest32(digest).expect("sign");
    let pubkey = kp.pubkey_bytes();
    let cache = SigCache::new(64);
    cache.insert(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest);

    c.bench_function("sig_cache_lookup_hit", |b| {
        b.iter(|| {
            black_box(cache.lookup(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest));
        });
    });
}

fn sig_cache_insert_lookup_cycle(c: &mut Criterion) {
    let kp = Mldsa87Keypair::generate().expect("keypair");
    let digest = [0x24; 32];
    let sig = kp.sign_digest32(digest).expect("sign");
    let pubkey = kp.pubkey_bytes();

    c.bench_function("sig_cache_insert_lookup_cycle", |b| {
        b.iter_batched(
            || SigCache::new(64),
            |cache| {
                cache.insert(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest);
                black_box(cache.lookup(SUITE_ID_ML_DSA_87, &pubkey, &sig, digest));
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    sig_cache_benches,
    sig_cache_lookup_hit,
    sig_cache_insert_lookup_cycle
);
criterion_main!(sig_cache_benches);

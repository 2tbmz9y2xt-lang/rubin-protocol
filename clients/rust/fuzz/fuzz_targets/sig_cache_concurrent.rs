#![no_main]

use std::thread;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 34 {
        return;
    }

    let suite_id = data[0];
    let pubkey_len = (data[1] as usize).min(64);
    let sig_len = (data[2] as usize).min(64);
    if data.len() < 3 + pubkey_len + sig_len + 32 {
        return;
    }

    let mut pos = 3;
    let pubkey = data[pos..pos + pubkey_len].to_vec();
    pos += pubkey_len;
    let sig = data[pos..pos + sig_len].to_vec();
    pos += sig_len;

    let mut base_digest = [0u8; 32];
    base_digest.copy_from_slice(&data[pos..pos + 32]);
    let cache = rubin_consensus::SigCache::new(16);

    let mut handles = Vec::new();
    for i in 0..4u8 {
        let cache = cache.clone();
        let pubkey = pubkey.clone();
        let sig = sig.clone();
        let mut digest = base_digest;
        digest[0] ^= i;
        handles.push(thread::spawn(move || {
            cache.insert(suite_id, &pubkey, &sig, digest);
            let _ = cache.lookup(suite_id, &pubkey, &sig, digest);
        }));
    }

    for handle in handles {
        handle.join().expect("sig_cache concurrent worker panicked");
    }

    if cache.len() > 16 {
        panic!("cache exceeded configured capacity");
    }

    cache.reset();
    if !cache.is_empty() {
        panic!("cache reset failed");
    }
});

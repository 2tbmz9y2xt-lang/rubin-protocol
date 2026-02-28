#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz fork_work_from_target: chainwork calculation (2^256 / target).
// Tests no-panic, determinism, and BigUint arithmetic on arbitrary targets.
fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let mut target = [0u8; 32];
    target.copy_from_slice(&data[..32]);

    let r1 = rubin_consensus::fork_work_from_target(target);
    let r2 = rubin_consensus::fork_work_from_target(target);

    match (&r1, &r2) {
        (Ok(a), Ok(b)) => {
            if a != b {
                panic!("fork_work_from_target non-deterministic");
            }
        }
        (Err(_), Err(_)) => {}
        _ => panic!("fork_work_from_target non-deterministic error/ok mismatch"),
    }

    // Also test chainwork accumulation if enough data.
    let n_targets = data.len() / 32;
    if n_targets >= 2 {
        let mut targets = Vec::with_capacity(n_targets);
        for i in 0..n_targets {
            let mut t = [0u8; 32];
            t.copy_from_slice(&data[i * 32..(i + 1) * 32]);
            targets.push(t);
        }
        let _ = rubin_consensus::fork_chainwork_from_targets(&targets);
    }
});

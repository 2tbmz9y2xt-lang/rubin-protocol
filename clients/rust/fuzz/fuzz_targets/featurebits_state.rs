#![no_main]

use libfuzzer_sys::fuzz_target;
use rubin_consensus::constants::{SIGNAL_THRESHOLD, SIGNAL_WINDOW};
use rubin_consensus::{featurebit_state_at_height_from_window_counts, FeatureBitDeployment};

fn decode_window_counts(raw: &[u8]) -> Vec<u32> {
    let count = (raw.len() / 4).min(32);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * 4;
        out.push(u32::from_le_bytes(raw[start..start + 4].try_into().unwrap()));
    }
    out
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 26 {
        return;
    }

    let name_len = (data[0] as usize).min(16);
    let mut cursor = 1usize;
    if data.len() < cursor + name_len + 1 + 8 + 8 + 8 {
        return;
    }

    let name = String::from_utf8_lossy(&data[cursor..cursor + name_len]).into_owned();
    cursor += name_len;
    let bit = data[cursor];
    cursor += 1;
    let start_height = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let timeout_height = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let raw_height = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let counts = decode_window_counts(&data[cursor..]);
    let max_height_exclusive = ((counts.len() as u64).saturating_add(1)).saturating_mul(SIGNAL_WINDOW);
    let height = if max_height_exclusive == 0 {
        0
    } else {
        raw_height % max_height_exclusive
    };

    let deployment = FeatureBitDeployment {
        name,
        bit,
        start_height,
        timeout_height,
    };

    let r1 = featurebit_state_at_height_from_window_counts(&deployment, height, &counts);
    let r2 = featurebit_state_at_height_from_window_counts(&deployment, height, &counts);

    match (&r1, &r2) {
        (Ok(a), Ok(b)) => {
            if a != b {
                panic!("featurebits non-deterministic eval");
            }

            let expected_boundary = height - (height % SIGNAL_WINDOW);
            if a.boundary_height != expected_boundary {
                panic!(
                    "featurebits boundary mismatch: got={} want={}",
                    a.boundary_height, expected_boundary
                );
            }
            if expected_boundary < SIGNAL_WINDOW && a.prev_window_signal_count != 0 {
                panic!(
                    "featurebits prev_window_signal_count below first boundary: {}",
                    a.prev_window_signal_count
                );
            }
            if a.signal_window != SIGNAL_WINDOW || a.signal_threshold != SIGNAL_THRESHOLD {
                panic!("featurebits signal constants drift");
            }
        }
        (Err(a), Err(b)) => {
            if a != b {
                panic!("featurebits non-deterministic error text");
            }
        }
        _ => panic!("featurebits non-deterministic error/ok mismatch"),
    }
});

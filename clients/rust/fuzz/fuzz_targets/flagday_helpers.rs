#![no_main]

use libfuzzer_sys::fuzz_target;
use rubin_consensus::flagday::validate_deployment_bit_uniqueness;
use rubin_consensus::{flagday_active_at_height, FlagDayDeployment};

fn decode_deployments(raw: &[u8]) -> Vec<FlagDayDeployment> {
    const STRIDE: usize = 10;
    let count = (raw.len() / STRIDE).min(8);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let chunk = &raw[i * STRIDE..(i + 1) * STRIDE];
        let name = if chunk[0] & 0x01 != 0 {
            String::new()
        } else {
            format!("d{i}")
        };
        let activation_height = u64::from_le_bytes(chunk[2..10].try_into().unwrap());
        let bit = if chunk[0] & 0x02 != 0 {
            Some(chunk[1])
        } else {
            None
        };
        out.push(FlagDayDeployment {
            name,
            activation_height,
            bit,
        });
    }
    out
}

fn warnings_join(items: &[String]) -> String {
    items.join("\n")
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 19 {
        return;
    }

    let name_len = (data[0] as usize).min(16);
    let mut cursor = 1usize;
    if data.len() < cursor + name_len + 8 + 8 + 1 + 1 {
        return;
    }

    let name = String::from_utf8_lossy(&data[cursor..cursor + name_len]).into_owned();
    cursor += name_len;
    let activation_height = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let height = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let has_bit = data[cursor] & 0x01 != 0;
    cursor += 1;
    let bit_value = data[cursor];
    cursor += 1;

    let deployment = FlagDayDeployment {
        name,
        activation_height,
        bit: has_bit.then_some(bit_value),
    };

    let a1 = flagday_active_at_height(&deployment, height);
    let a2 = flagday_active_at_height(&deployment, height);
    match (&a1, &a2) {
        (Ok(x), Ok(y)) => {
            if x != y {
                panic!("flagday non-deterministic active result");
            }
        }
        (Err(x), Err(y)) => {
            if x != y {
                panic!("flagday non-deterministic error text");
            }
        }
        _ => panic!("flagday non-deterministic error/ok mismatch"),
    }

    let deployments = decode_deployments(&data[cursor..]);
    let w1 = validate_deployment_bit_uniqueness(&deployments);
    let w2 = validate_deployment_bit_uniqueness(&deployments);
    if warnings_join(&w1) != warnings_join(&w2) {
        panic!("flagday warnings non-deterministic");
    }
});

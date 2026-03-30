#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use rubin_consensus::constants::{
    ML_DSA_87_PUBKEY_BYTES, ML_DSA_87_SIG_BYTES, SUITE_ID_ML_DSA_87, VERIFY_COST_ML_DSA_87,
};
use rubin_consensus::{DefaultRotationProvider, RotationProvider, SuiteParams, SuiteRegistry};

fn build_registry(data: &[u8]) -> SuiteRegistry {
    if data.first().copied().unwrap_or_default() & 1 == 0 {
        return SuiteRegistry::default_registry();
    }

    let mut suites = BTreeMap::new();
    let custom_id = data.get(1).copied().unwrap_or(0x09);
    let pubkey_len = u64::from(data.get(2).copied().unwrap_or(0)) + 1;
    let sig_len = u64::from(data.get(3).copied().unwrap_or(0)) + 1;
    let verify_cost = u64::from(data.get(4).copied().unwrap_or(0)) + 1;
    suites.insert(
        custom_id,
        SuiteParams {
            suite_id: custom_id,
            pubkey_len,
            sig_len,
            verify_cost,
            openssl_alg: "ML-DSA-87",
        },
    );
    suites.insert(
        SUITE_ID_ML_DSA_87,
        SuiteParams {
            suite_id: SUITE_ID_ML_DSA_87,
            pubkey_len: ML_DSA_87_PUBKEY_BYTES,
            sig_len: ML_DSA_87_SIG_BYTES,
            verify_cost: VERIFY_COST_ML_DSA_87,
            openssl_alg: "ML-DSA-87",
        },
    );
    SuiteRegistry::with_suites(suites)
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let registry = build_registry(data);
    let suite_id = data[0];
    let params = registry.lookup(suite_id);
    let is_registered = registry.is_registered(suite_id);

    if params.is_some() != is_registered {
        panic!("lookup/is_registered mismatch for suite 0x{suite_id:02x}");
    }

    if let Some(params) = registry.lookup(SUITE_ID_ML_DSA_87) {
        if params.pubkey_len != ML_DSA_87_PUBKEY_BYTES {
            panic!("ml-dsa-87 pubkey len drift");
        }
        if params.sig_len != ML_DSA_87_SIG_BYTES {
            panic!("ml-dsa-87 sig len drift");
        }
        if params.verify_cost != VERIFY_COST_ML_DSA_87 {
            panic!("ml-dsa-87 verify_cost drift");
        }
    }

    let min_payload = registry.min_sigcheck_payload_bytes();
    if let Ok(Some(bytes)) = min_payload {
        if bytes == 0 {
            panic!("min_sigcheck_payload_bytes must be positive");
        }
    }

    let provider = DefaultRotationProvider;
    let create = provider.native_create_suites(0);
    let spend = provider.native_spend_suites(u64::from(data.get(1).copied().unwrap_or(0)));
    if !create.contains(SUITE_ID_ML_DSA_87) {
        panic!("default rotation create set lost ml-dsa-87");
    }
    if !spend.contains(SUITE_ID_ML_DSA_87) {
        panic!("default rotation spend set lost ml-dsa-87");
    }

    let ids = create.suite_ids();
    if !ids.windows(2).all(|pair| pair[0] < pair[1]) {
        panic!("suite ids not sorted");
    }
});

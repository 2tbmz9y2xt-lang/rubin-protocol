#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = rubin_consensus::parse_tx(data);
    let second = rubin_consensus::parse_tx(data);

    match (first, second) {
        (Ok((tx_a, txid_a, wtxid_a, consumed_a)), Ok((tx_b, txid_b, wtxid_b, consumed_b))) => {
            assert_eq!(tx_a, tx_b, "parse_tx tx drift");
            assert_eq!(txid_a, txid_b, "parse_tx txid drift");
            assert_eq!(wtxid_a, wtxid_b, "parse_tx wtxid drift");
            assert_eq!(consumed_a, consumed_b, "parse_tx consumed drift");
        }
        (Err(err_a), Err(err_b)) => {
            assert_eq!(err_a.code, err_b.code, "parse_tx error code drift");
            assert_eq!(err_a.msg, err_b.msg, "parse_tx error msg drift");
        }
        _ => panic!("parse_tx non-deterministic error/ok mismatch"),
    }
});

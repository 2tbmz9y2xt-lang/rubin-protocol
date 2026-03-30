#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (tx, _, _, _) = match rubin_consensus::parse_tx(data) {
        Ok(parsed) => parsed,
        Err(_) => return,
    };

    let bytes_a = rubin_consensus::marshal_tx(&tx).expect("marshal parsed tx");
    let (parsed_a, _, _, consumed_a) = rubin_consensus::parse_tx(&bytes_a).expect("reparse");
    assert_eq!(consumed_a, bytes_a.len(), "marshal consumed drift");
    assert_eq!(parsed_a, tx, "marshal roundtrip tx drift");

    let bytes_b = rubin_consensus::marshal_tx(&parsed_a).expect("remarshal");
    assert_eq!(bytes_a, bytes_b, "marshal non-deterministic bytes");
});

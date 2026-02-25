#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((n, nbytes)) = rubin_consensus::read_compact_size_bytes(data) else {
        return;
    };
    let prefix = &data[..nbytes];
    let mut enc = Vec::new();
    rubin_consensus::encode_compact_size(n, &mut enc);
    if enc != prefix {
        panic!("non-minimal or mismatch: got={enc:02x?} want_prefix={prefix:02x?}");
    }
});


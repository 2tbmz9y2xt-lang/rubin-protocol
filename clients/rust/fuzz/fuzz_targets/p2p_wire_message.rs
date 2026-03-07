#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rubin_node::p2p_runtime::fuzz_parse_wire_message("devnet", data);
});

pub fn encode(n: u64) -> Vec<u8> {
    rubin_consensus::compact_size_encode(n)
}

pub fn decode(b: &[u8]) -> Result<(u64, usize), String> {
    rubin_consensus::compact_size_decode(b)
}

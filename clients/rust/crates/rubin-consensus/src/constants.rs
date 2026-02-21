pub const TX_WIRE_VERSION: u32 = 2;

pub const WITNESS_DISCOUNT_DIVISOR: u64 = 4;

pub const MAX_TX_INPUTS: u64 = 1024;
pub const MAX_TX_OUTPUTS: u64 = 1024;
pub const MAX_WITNESS_ITEMS: u64 = 1024;
pub const MAX_WITNESS_BYTES_PER_TX: usize = 100_000;
pub const MAX_SCRIPT_SIG_BYTES: u64 = 32;

pub const SUITE_ID_SENTINEL: u8 = 0x00;
pub const SUITE_ID_ML_DSA_87: u8 = 0x01;
pub const SUITE_ID_SLH_DSA_SHAKE_256F: u8 = 0x02;

pub const ML_DSA_87_PUBKEY_BYTES: u64 = 2592;
pub const ML_DSA_87_SIG_BYTES: u64 = 4627;

pub const SLH_DSA_SHAKE_256F_PUBKEY_BYTES: u64 = 64;
pub const MAX_SLH_DSA_SIG_BYTES: u64 = 49_856;

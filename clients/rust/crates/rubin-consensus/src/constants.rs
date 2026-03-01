pub const WITNESS_DISCOUNT_DIVISOR: u64 = 4;

pub const TARGET_BLOCK_INTERVAL: u64 = 120;
pub const WINDOW_SIZE: u64 = 10_080;

pub const COINBASE_MATURITY: u64 = 100;
pub const MAX_FUTURE_DRIFT: u64 = 7_200;
// Derived consensus constant (CANONICAL §4 / §15).
pub const MAX_TIMESTAMP_STEP_PER_BLOCK: u64 = 10 * TARGET_BLOCK_INTERVAL;

pub const BASE_UNITS_PER_RBN: u64 = 100_000_000;
pub const MAX_SUPPLY: u64 = 5_000_000_000_000_000; // emission anchor; total supply becomes unbounded after tail activation
pub const GENESIS_ALLOCATION: u64 = 100_000_000_000_000;
pub const MINEABLE_CAP: u64 = 4_900_000_000_000_000;
pub const EMISSION_SPEED_FACTOR: u8 = 20;
pub const TAIL_EMISSION_PER_BLOCK: u64 = 19_025_875;

pub const MAX_BLOCK_WEIGHT: u64 = 68_000_000;
pub const MAX_BLOCK_BYTES: u64 = 72_000_000; // operational P2P cap; not a consensus validity bound
pub const MAX_DA_BYTES_PER_BLOCK: u64 = 32_000_000;
pub const MIN_DA_RETENTION_BLOCKS: u64 = 15_120;
pub const MAX_RELAY_MSG_BYTES: u64 = 96_000_000;

pub const MAX_DA_MANIFEST_BYTES_PER_TX: u64 = 65_536;
pub const CHUNK_BYTES: u64 = 524_288;
pub const MAX_DA_BATCHES_PER_BLOCK: u64 = 128;
pub const MAX_DA_CHUNK_COUNT: u64 = MAX_DA_BYTES_PER_BLOCK / CHUNK_BYTES;
pub const MAX_ANCHOR_PAYLOAD_SIZE: u64 = 65_536;
pub const MAX_COVENANT_DATA_PER_OUTPUT: u64 = MAX_ANCHOR_PAYLOAD_SIZE;
pub const MAX_ANCHOR_BYTES_PER_BLOCK: u64 = 131_072;
pub const MAX_P2PK_COVENANT_DATA: u64 = 33;
pub const MAX_HTLC_COVENANT_DATA: u64 = 105;
pub const MIN_HTLC_PREIMAGE_BYTES: u64 = 16; // consensus security floor (Q-A287-03)
pub const MAX_HTLC_PREIMAGE_BYTES: u64 = 256;
pub const MAX_VAULT_KEYS: u8 = 12;
pub const MAX_VAULT_WHITELIST_ENTRIES: u16 = 1024;
pub const MAX_MULTISIG_KEYS: u8 = 12;
pub const COV_TYPE_MULTISIG: u16 = 0x0104;
pub const COV_TYPE_EXT: u16 = 0x0102;
pub const CORE_EXT_WITNESS_SLOTS: u64 = 1;

pub const MAX_TX_INPUTS: u64 = 1024;
pub const MAX_TX_OUTPUTS: u64 = 1024;
pub const MAX_WITNESS_ITEMS: u64 = 1024;
pub const MAX_WITNESS_BYTES_PER_TX: usize = 100_000;
pub const MAX_SLH_WITNESS_BYTES_PER_TX: usize = 50_000;
pub const MAX_SCRIPT_SIG_BYTES: u64 = 32;

pub const SUITE_ID_SENTINEL: u8 = 0x00;
pub const SUITE_ID_ML_DSA_87: u8 = 0x01;
pub const SUITE_ID_SLH_DSA_SHAKE_256F: u8 = 0x02;
pub const SLH_DSA_ACTIVATION_HEIGHT: u64 = 1_000_000;

pub const COV_TYPE_P2PK: u16 = 0x0000;
pub const COV_TYPE_ANCHOR: u16 = 0x0002;
pub const COV_TYPE_RESERVED_FUTURE: u16 = 0x00FF;
pub const COV_TYPE_HTLC: u16 = 0x0100;
pub const COV_TYPE_VAULT: u16 = 0x0101;
pub const COV_TYPE_DA_COMMIT: u16 = 0x0103;

pub const LOCK_MODE_HEIGHT: u8 = 0x00;
pub const LOCK_MODE_TIMESTAMP: u8 = 0x01;

pub const ML_DSA_87_PUBKEY_BYTES: u64 = 2592;
pub const ML_DSA_87_SIG_BYTES: u64 = 4627;

pub const SLH_DSA_SHAKE_256F_PUBKEY_BYTES: u64 = 64;
pub const MAX_SLH_DSA_SIG_BYTES: u64 = 49_856;

pub const VERIFY_COST_ML_DSA_87: u64 = 8;
pub const VERIFY_COST_SLH_DSA_SHAKE_256F: u64 = 64;
pub const VERIFY_COST_UNKNOWN_SUITE: u64 = 64;

pub const SIGNAL_WINDOW: u64 = 2016;
pub const SIGNAL_THRESHOLD: u32 = 1815;

pub const POW_LIMIT: [u8; 32] = [0xff; 32];

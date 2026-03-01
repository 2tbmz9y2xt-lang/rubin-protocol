pub mod block;
pub mod block_basic;
mod compact_relay;
mod compactsize;
pub mod connect_block_inmem;
pub mod constants;
mod covenant_genesis;
pub mod error;
mod ext;
mod fork_choice;
mod hash;
mod htlc;
pub mod merkle;
pub mod pow;
pub mod sighash;
mod spend_verify;
pub mod subsidy;
pub mod tx;
mod utxo_basic;
mod vault;
mod verify_sig_openssl;
mod wire_read;

pub use block::{block_hash, parse_block_header_bytes, BlockHeader, BLOCK_HEADER_BYTES};
pub use block_basic::tx_weight_and_stats_public;
pub use block_basic::{
    parse_block_bytes, validate_block_basic, validate_block_basic_at_height,
    validate_block_basic_with_context_and_fees_at_height,
    validate_block_basic_with_context_at_height, BlockBasicSummary, ParsedBlock,
};
pub use compact_relay::compact_shortid;
pub use compactsize::encode_compact_size;
pub use compactsize::read_compact_size_bytes;
pub use connect_block_inmem::{
    connect_block_basic_in_memory_at_height, ConnectBlockBasicSummary, InMemoryChainState,
};
pub use covenant_genesis::validate_tx_covenants_genesis;
pub use error::{ErrorCode, TxError};
pub use ext::{parse_core_ext_covenant_data, CoreExtProfile};
pub use fork_choice::{fork_chainwork_from_targets, fork_work_from_target};
pub use htlc::{parse_htlc_covenant_data, validate_htlc_spend, HtlcCovenant};
pub use merkle::merkle_root_txids;
pub use pow::{pow_check, retarget_v1, retarget_v1_clamped};
pub use sighash::sighash_v1_digest;
pub use subsidy::block_subsidy;
pub use tx::{parse_tx, DaChunkCore, DaCommitCore, Tx, TxInput, TxOutput, WitnessItem};
pub use utxo_basic::{
    apply_non_coinbase_tx_basic, apply_non_coinbase_tx_basic_update,
    apply_non_coinbase_tx_basic_update_with_mtp,
    apply_non_coinbase_tx_basic_update_with_mtp_and_profiles, apply_non_coinbase_tx_basic_with_mtp,
    apply_non_coinbase_tx_basic_with_mtp_and_profiles, Outpoint, UtxoApplySummary, UtxoEntry,
};
pub use vault::{
    output_descriptor_bytes, parse_multisig_covenant_data, parse_vault_covenant_data,
    witness_slots, MultisigCovenant, VaultCovenant,
};

#[cfg(test)]
mod compact_relay_tests;
#[cfg(test)]
mod ext_tests;
#[cfg(test)]
mod tests;

pub mod block;
pub mod block_basic;
mod compact_relay;
mod compactsize;
pub mod connect_block_inmem;
pub mod constants;
pub mod core_ext;
mod covenant_genesis;
pub mod error;
pub mod featurebits;
pub mod flagday;
mod fork_choice;
mod hash;
mod htlc;
pub mod merkle;
pub mod pow;
pub mod sighash;
mod spend_verify;
mod stealth;
pub mod subsidy;
pub mod suite_registry;
pub mod tx;
mod tx_helpers;
mod utxo_basic;
mod vault;
mod verify_sig_openssl;
mod wire_read;

pub use block::{block_hash, parse_block_header_bytes, BlockHeader, BLOCK_HEADER_BYTES};
pub use block_basic::{tx_weight_and_stats_at_height, tx_weight_and_stats_public};
pub use block_basic::{
    parse_block_bytes, validate_block_basic, validate_block_basic_at_height,
    validate_block_basic_with_context_and_fees_at_height,
    validate_block_basic_with_context_at_height, BlockBasicSummary, ParsedBlock,
};
pub use compact_relay::compact_shortid;
pub use compactsize::encode_compact_size;
pub use compactsize::read_compact_size_bytes;
pub use connect_block_inmem::{
    connect_block_basic_in_memory_at_height,
    connect_block_basic_in_memory_at_height_and_core_ext_deployments, ConnectBlockBasicSummary,
    InMemoryChainState,
};
pub use core_ext::{
    core_ext_verification_binding_from_name, parse_core_ext_covenant_data, validate_core_ext_spend,
    CoreExtActiveProfile, CoreExtDeploymentProfile, CoreExtDeploymentProfiles, CoreExtProfiles,
    CoreExtVerificationBinding,
};
pub use covenant_genesis::validate_tx_covenants_genesis;
pub use error::{ErrorCode, TxError};
pub use featurebits::{
    featurebit_state_at_height_from_window_counts, FeatureBitDeployment, FeatureBitEval,
    FeatureBitState,
};
pub use flagday::{flagday_active_at_height, FlagDayDeployment};
pub use fork_choice::{fork_chainwork_from_targets, fork_work_from_target};
pub use htlc::{parse_htlc_covenant_data, validate_htlc_spend, HtlcCovenant};
pub use merkle::merkle_root_txids;
pub use pow::{pow_check, retarget_v1, retarget_v1_clamped};
pub use sighash::{
    is_valid_sighash_type, sighash_v1_digest, sighash_v1_digest_with_cache,
    sighash_v1_digest_with_type, SighashV1PrehashCache,
};
pub use stealth::{parse_stealth_covenant_data, validate_stealth_spend, StealthCovenant};
pub use subsidy::block_subsidy;
pub use suite_registry::{
    CryptoRotationDescriptor, DefaultRotationProvider, DescriptorRotationProvider, NativeSuiteSet,
    RotationProvider, SuiteParams, SuiteRegistry,
};
pub use tx::{parse_tx, DaChunkCore, DaCommitCore, Tx, TxInput, TxOutput, WitnessItem};
pub use tx_helpers::{marshal_tx, p2pk_covenant_data_for_pubkey, sign_transaction, DigestSigner};
pub use utxo_basic::{
    apply_non_coinbase_tx_basic, apply_non_coinbase_tx_basic_update,
    apply_non_coinbase_tx_basic_update_with_mtp,
    apply_non_coinbase_tx_basic_update_with_mtp_and_core_ext_profiles,
    apply_non_coinbase_tx_basic_with_mtp, Outpoint, UtxoApplySummary, UtxoEntry,
};
pub use vault::{
    output_descriptor_bytes, parse_multisig_covenant_data, parse_vault_covenant_data,
    witness_slots, MultisigCovenant, VaultCovenant,
};
pub use verify_sig_openssl::{verify_sig, verify_sig_with_registry, Mldsa87Keypair};

#[cfg(test)]
mod compact_relay_tests;
#[cfg(test)]
mod coverage_hotspots_tests;
#[cfg(test)]
mod featurebits_tests;
#[cfg(test)]
mod tests;

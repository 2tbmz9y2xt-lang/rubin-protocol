use std::collections::HashMap;

use super::coinbase::{validate_coinbase_structure, validate_coinbase_witness_commitment};
use super::header::{validate_header_commitments, validate_timestamp_rules};
use super::txs::{accumulate_block_resource_stats, validate_block_tx_semantics, BlockTxStats};
use super::{
    validate_block_resource_limits, validate_coinbase_apply_outputs, validate_da_set_integrity,
    BlockBasicSummary, ParsedBlock,
};
use crate::block::block_hash;
use crate::constants::{COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT};
use crate::covenant_genesis::{
    validate_simplicity_output_group_cap, validate_tx_output_covenant_genesis,
};
use crate::error::{ErrorCode, TxError};
use crate::suite_registry::{DefaultRotationProvider, RotationProvider};
use crate::utxo_basic::{Outpoint, UtxoEntry};

/// G.9 / Go parity (`clients/go/consensus/block_basic.go`,
/// `validateParsedBlockBasicWithContextAtHeight`): validation logic against an
/// already-parsed block. Callers that need both the parsed block and the
/// summary parse once via `parse_block_bytes` and then call this helper,
/// instead of re-parsing in both `validate_*` and `connect_*`.
pub(crate) fn validate_parsed_block_basic_with_context_at_height(
    pb: &ParsedBlock,
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    rotation: Option<&dyn RotationProvider>,
) -> Result<BlockBasicSummary, TxError> {
    let stats = validate_parsed_block_basic_checks(
        pb,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
        rotation,
    )?;
    let h = block_hash(&pb.header_bytes)
        .map_err(|_| TxError::new(ErrorCode::BlockErrParse, "failed to hash block header"))?;

    Ok(BlockBasicSummary {
        tx_count: pb.tx_count,
        sum_weight: stats.sum_weight,
        sum_da: stats.sum_da,
        block_hash: h,
    })
}

impl ParsedBlock {
    pub(crate) fn validate_connect_preflight(
        &self,
        expected_prev_hash: Option<[u8; 32]>,
        expected_target: Option<[u8; 32]>,
        block_height: u64,
        prev_timestamps: Option<&[u64]>,
        _rotation: Option<&dyn RotationProvider>,
    ) -> Result<(), TxError> {
        validate_parsed_block_preflight(
            self,
            expected_prev_hash,
            expected_target,
            block_height,
            prev_timestamps,
        )?;
        validate_coinbase_structure(self, block_height)
    }

    fn coinbase_and_txid(&self) -> Result<(&crate::tx::Tx, [u8; 32]), TxError> {
        let coinbase = self
            .txs
            .first()
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrCoinbaseInvalid, "missing coinbase"))?;
        let coinbase_txid = *self
            .txids
            .first()
            .ok_or_else(|| TxError::new(ErrorCode::BlockErrParse, "missing coinbase txid"))?;
        Ok((coinbase, coinbase_txid))
    }
    /// Applies coinbase creation to a caller-owned local UTXO map before
    /// transaction index one. The caller commits that map only after the
    /// complete connect succeeds.
    pub(crate) fn apply_coinbase_outputs(
        &self,
        work_utxos: &mut HashMap<Outpoint, UtxoEntry>,
        block_height: u64,
        rotation: Option<&dyn RotationProvider>,
    ) -> Result<(), TxError> {
        let (coinbase, coinbase_txid) = self.coinbase_and_txid()?;
        let default_rp = DefaultRotationProvider;
        let rp: &dyn RotationProvider = rotation.unwrap_or(&default_rp);
        let mut simplicity_output_cmrs = Vec::with_capacity(coinbase.outputs.len());

        for (index, out) in coinbase.outputs.iter().enumerate() {
            validate_coinbase_apply_outputs(std::slice::from_ref(out))?;
            if let Some(program_cmr) =
                validate_tx_output_covenant_genesis(coinbase.tx_kind, out, block_height, rp)?
            {
                simplicity_output_cmrs.push(program_cmr);
            }
            if matches!(out.covenant_type, COV_TYPE_ANCHOR | COV_TYPE_DA_COMMIT) {
                continue;
            }
            let vout = u32::try_from(index).map_err(|_| {
                TxError::new(
                    ErrorCode::BlockErrParse,
                    "coinbase output index exceeds u32",
                )
            })?;
            work_utxos.insert(
                Outpoint {
                    txid: coinbase_txid,
                    vout,
                },
                UtxoEntry {
                    value: out.value,
                    covenant_type: out.covenant_type,
                    covenant_data: out.covenant_data.clone(),
                    creation_height: block_height,
                    created_by_coinbase: true,
                },
            );
        }

        validate_simplicity_output_group_cap(&simplicity_output_cmrs)
    }
}

fn validate_parsed_block_basic_checks(
    pb: &ParsedBlock,
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
    rotation: Option<&dyn RotationProvider>,
) -> Result<BlockTxStats, TxError> {
    let stats = validate_parsed_block_preflight(
        pb,
        expected_prev_hash,
        expected_target,
        block_height,
        prev_timestamps,
    )?;
    validate_block_tx_semantics(pb, block_height, rotation)?;
    Ok(stats)
}

fn validate_parsed_block_preflight(
    pb: &ParsedBlock,
    expected_prev_hash: Option<[u8; 32]>,
    expected_target: Option<[u8; 32]>,
    block_height: u64,
    prev_timestamps: Option<&[u64]>,
) -> Result<BlockTxStats, TxError> {
    validate_header_commitments(pb, expected_prev_hash, expected_target)
        .and_then(|_| validate_coinbase_witness_commitment(pb))
        .and_then(|_| {
            validate_timestamp_rules(pb.header.timestamp, block_height, prev_timestamps)
        })?;

    let stats = accumulate_block_resource_stats(pb)?;
    validate_block_resource_limits(stats)?;

    validate_da_set_integrity(&pb.txs)?;
    Ok(stats)
}

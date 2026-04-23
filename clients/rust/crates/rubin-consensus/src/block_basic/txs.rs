use super::*;
use crate::covenant_genesis::validate_tx_covenants_genesis;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug)]
pub(super) struct BlockTxStats {
    pub(super) sum_weight: u64,
    pub(super) sum_da: u64,
    pub(super) sum_anchor: u64,
}

pub(super) fn accumulate_block_resource_stats(pb: &ParsedBlock) -> Result<BlockTxStats, TxError> {
    let mut stats = BlockTxStats {
        sum_weight: 0,
        sum_da: 0,
        sum_anchor: 0,
    };
    for tx in &pb.txs {
        let (w, da, anchor_bytes) = tx_weight_and_stats(tx)?;
        stats.sum_weight = add_block_resource_stat(stats.sum_weight, w, "sum_weight overflow")?;
        stats.sum_da = add_block_resource_stat(stats.sum_da, da, "sum_da overflow")?;
        stats.sum_anchor =
            add_block_resource_stat(stats.sum_anchor, anchor_bytes, "sum_anchor overflow")?;
    }
    Ok(stats)
}

fn add_block_resource_stat(current: u64, delta: u64, msg: &'static str) -> Result<u64, TxError> {
    current
        .checked_add(delta)
        .ok_or_else(|| TxError::new(ErrorCode::TxErrParse, msg))
}

pub(super) fn validate_block_tx_semantics(
    pb: &ParsedBlock,
    block_height: u64,
) -> Result<(), TxError> {
    coinbase::validate_coinbase_structure(pb, block_height)?;
    let mut seen_nonces: HashMap<u64, ()> = HashMap::with_capacity(pb.txs.len());
    for (i, tx) in pb.txs.iter().enumerate() {
        if i > 0 {
            if coinbase::is_coinbase_tx(tx) {
                return Err(TxError::new(
                    ErrorCode::BlockErrCoinbaseInvalid,
                    "coinbase-like tx found at index > 0",
                ));
            }
            if tx.inputs.is_empty() {
                return Err(TxError::new(
                    ErrorCode::TxErrParse,
                    "non-coinbase must have at least one input",
                ));
            }
            if seen_nonces.insert(tx.tx_nonce, ()).is_some() {
                return Err(TxError::new(
                    ErrorCode::TxErrNonceReplay,
                    "duplicate tx_nonce in block",
                ));
            }
        }
        validate_tx_covenants_genesis(tx, block_height, None)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use crate::constants::{COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT, COV_TYPE_P2PK, TX_WIRE_VERSION};
    use crate::tx::{DaChunkCore, TxInput, TxOutput, WitnessItem};
    use crate::tx_helpers::p2pk_covenant_data_for_pubkey;

    fn coinbase(block_height: u64) -> Tx {
        Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce: 0,
            inputs: vec![TxInput {
                prev_txid: [0u8; 32],
                prev_vout: u32::MAX,
                script_sig: Vec::new(),
                sequence: u32::MAX,
            }],
            outputs: vec![TxOutput {
                value: 1,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&[0x11; 32]),
            }],
            locktime: block_height as u32,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        }
    }

    fn spend(tx_nonce: u64, value: u64) -> Tx {
        Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce,
            inputs: vec![TxInput {
                prev_txid: [0x22; 32],
                prev_vout: 0,
                script_sig: vec![0x01],
                sequence: 1,
            }],
            outputs: vec![TxOutput {
                value,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: p2pk_covenant_data_for_pubkey(&[0x33; 32]),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: vec![WitnessItem {
                suite_id: SUITE_ID_SENTINEL,
                pubkey: Vec::new(),
                signature: Vec::new(),
            }],
            da_payload: Vec::new(),
        }
    }

    fn parsed_block(txs: Vec<Tx>) -> ParsedBlock {
        ParsedBlock {
            header: BlockHeader {
                version: 1,
                prev_block_hash: [0u8; 32],
                merkle_root: [0u8; 32],
                timestamp: 0,
                target: [1u8; 32],
                nonce: 0,
            },
            header_bytes: [0u8; BLOCK_HEADER_BYTES],
            tx_count: txs.len() as u64,
            txids: Vec::new(),
            wtxids: Vec::new(),
            txs,
        }
    }

    #[test]
    fn accumulate_block_resource_stats_aggregates_da_and_anchor_bytes() {
        let mut da_chunk = spend(7, 2);
        da_chunk.tx_kind = 0x02;
        da_chunk.outputs.push(TxOutput {
            value: 0,
            covenant_type: COV_TYPE_ANCHOR,
            covenant_data: vec![0x44; 32],
        });
        da_chunk.da_chunk_core = Some(DaChunkCore {
            da_id: [0x55; 32],
            chunk_index: 0,
            chunk_hash: sha3_256(&[0xaa, 0xbb, 0xcc]),
        });
        da_chunk.da_payload = vec![0xaa, 0xbb, 0xcc];

        let pb = parsed_block(vec![coinbase(1), da_chunk]);
        let stats = accumulate_block_resource_stats(&pb).expect("stats");

        assert!(stats.sum_weight > 0);
        assert_eq!(stats.sum_da, 3);
        assert_eq!(stats.sum_anchor, 32);
    }

    #[test]
    fn accumulate_block_resource_stats_bubbles_tx_weight_error() {
        let mut bad_da = spend(8, 2);
        bad_da.tx_kind = 0x01;
        bad_da.outputs.push(TxOutput {
            value: 0,
            covenant_type: COV_TYPE_DA_COMMIT,
            covenant_data: vec![0x99; 32],
        });

        let pb = parsed_block(vec![coinbase(1), bad_da]);
        let err = accumulate_block_resource_stats(&pb).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrParse);
    }

    #[test]
    fn add_block_resource_stat_reports_named_overflow() {
        for msg in [
            "sum_weight overflow",
            "sum_da overflow",
            "sum_anchor overflow",
        ] {
            let err = add_block_resource_stat(u64::MAX, 1, msg).unwrap_err();
            assert_eq!(err.code, ErrorCode::TxErrParse);
            assert_eq!(err.msg, msg);
        }
    }

    #[test]
    fn validate_block_tx_semantics_rejects_nonce_replay() {
        let pb = parsed_block(vec![coinbase(1), spend(42, 1), spend(42, 1)]);
        let err = validate_block_tx_semantics(&pb, 1).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrNonceReplay);
    }

    #[test]
    fn validate_block_tx_semantics_bubbles_covenant_error() {
        let mut bad = spend(99, 0);
        bad.outputs[0].value = 0;
        let pb = parsed_block(vec![coinbase(1), bad]);
        let err = validate_block_tx_semantics(&pb, 1).unwrap_err();
        assert_eq!(err.code, ErrorCode::TxErrCovenantTypeInvalid);
    }
}

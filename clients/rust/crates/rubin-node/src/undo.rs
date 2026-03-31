use std::collections::HashSet;

use rubin_consensus::constants::{COV_TYPE_ANCHOR, COV_TYPE_DA_COMMIT};
use rubin_consensus::{block_hash, parse_block_bytes, Outpoint, UtxoEntry};
use serde::{Deserialize, Serialize};

use crate::chainstate::ChainState;
use crate::io_utils::parse_hex32;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentUndo {
    pub outpoint: Outpoint,
    pub entry: UtxoEntry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxUndo {
    pub spent: Vec<SpentUndo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockUndo {
    pub block_height: u64,
    pub previous_already_generated: u64,
    pub txs: Vec<TxUndo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStateDisconnectSummary {
    pub disconnected_height: u64,
    pub block_hash: [u8; 32],
    pub new_height: u64,
    pub new_tip_hash: [u8; 32],
    pub has_tip: bool,
    pub already_generated: u64,
    pub utxo_count: u64,
}

// ---------------------------------------------------------------------------
// Build undo
// ---------------------------------------------------------------------------

fn is_spendable_output(covenant_type: u16) -> bool {
    covenant_type != COV_TYPE_ANCHOR && covenant_type != COV_TYPE_DA_COMMIT
}

/// Build an undo record by replaying UTXO mutations against a copy of the
/// previous chain state. Must be called *before* `connect_block` modifies the
/// live state.
pub fn build_block_undo(
    prev_state: &ChainState,
    block_bytes: &[u8],
    block_height: u64,
) -> Result<BlockUndo, String> {
    let pb = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
    if pb.txs.len() != pb.txids.len() {
        return Err("parsed block txid length mismatch".into());
    }

    let mut spent_prev_outpoints = HashSet::new();
    let mut block_outputs = HashSet::new();
    let mut tx_undos = Vec::with_capacity(pb.txs.len());

    for (i, tx) in pb.txs.iter().enumerate() {
        let mut spent = Vec::with_capacity(tx.inputs.len());
        // Coinbase (index 0) has no real inputs to consume.
        if i > 0 {
            for input in &tx.inputs {
                let op = Outpoint {
                    txid: input.prev_txid,
                    vout: input.prev_vout,
                };
                if block_outputs.remove(&op) {
                    continue;
                }
                let entry = prev_state.utxos.get(&op).ok_or_else(|| {
                    format!("undo missing utxo for {}:{}", hex::encode(op.txid), op.vout)
                })?;
                if !spent_prev_outpoints.insert(op.clone()) {
                    return Err(format!(
                        "undo duplicate prev-state spend for {}:{}",
                        hex::encode(op.txid),
                        op.vout
                    ));
                }
                spent.push(SpentUndo {
                    outpoint: op,
                    entry: entry.clone(),
                });
            }
        }
        // Track new spendable outputs so later txs can consume them without
        // cloning the full previous-state UTXO map.
        for (output_index, out) in tx.outputs.iter().enumerate() {
            if !is_spendable_output(out.covenant_type) {
                continue;
            }
            block_outputs.insert(Outpoint {
                txid: pb.txids[i],
                vout: output_index as u32,
            });
        }
        tx_undos.push(TxUndo { spent });
    }

    Ok(BlockUndo {
        block_height,
        previous_already_generated: prev_state.already_generated,
        txs: tx_undos,
    })
}

// ---------------------------------------------------------------------------
// Disconnect block
// ---------------------------------------------------------------------------

impl ChainState {
    /// Reverse the effects of a single block, restoring the UTXO set and
    /// chain-level accumulators to the state immediately before this block
    /// was connected.
    pub fn disconnect_block(
        &mut self,
        block_bytes: &[u8],
        undo: &BlockUndo,
    ) -> Result<ChainStateDisconnectSummary, String> {
        if !self.has_tip {
            return Err("chainstate has no tip".into());
        }
        // Cheap invariant checks before parsing.
        if self.height != undo.block_height {
            return Err(format!(
                "disconnect height mismatch: chainstate={} undo={}",
                self.height, undo.block_height
            ));
        }

        let pb = parse_block_bytes(block_bytes).map_err(|e| e.to_string())?;
        if pb.txs.len() != pb.txids.len() {
            return Err("parsed block txid length mismatch".into());
        }
        if undo.txs.len() != pb.txs.len() {
            return Err("undo tx count mismatch".into());
        }

        let bh = block_hash(&pb.header_bytes).map_err(|e| e.to_string())?;
        if self.tip_hash != bh {
            return Err("disconnect block is not current tip".into());
        }

        let mut created_outpoints = HashSet::new();
        for (tx_index, tx) in pb.txs.iter().enumerate() {
            for (output_index, out) in tx.outputs.iter().enumerate() {
                if !is_spendable_output(out.covenant_type) {
                    continue;
                }
                created_outpoints.insert(Outpoint {
                    txid: pb.txids[tx_index],
                    vout: output_index as u32,
                });
            }
        }

        let mut restored_outpoints = HashSet::new();
        for tx_undo in &undo.txs {
            for spent in &tx_undo.spent {
                if !restored_outpoints.insert(spent.outpoint.clone()) {
                    return Err(format!(
                        "undo duplicate restore entry for {}:{}",
                        hex::encode(spent.outpoint.txid),
                        spent.outpoint.vout
                    ));
                }
                if created_outpoints.contains(&spent.outpoint) {
                    continue;
                }
                if self.utxos.contains_key(&spent.outpoint) {
                    return Err(format!(
                        "undo restore target already present for {}:{}",
                        hex::encode(spent.outpoint.txid),
                        spent.outpoint.vout
                    ));
                }
            }
        }

        // Process transactions in **reverse** order.
        for tx_index in (0..pb.txs.len()).rev() {
            let tx = &pb.txs[tx_index];
            let txid = pb.txids[tx_index];

            // 1. Remove outputs created by this tx.
            for (output_index, out) in tx.outputs.iter().enumerate() {
                if !is_spendable_output(out.covenant_type) {
                    continue;
                }
                self.utxos.remove(&Outpoint {
                    txid,
                    vout: output_index as u32,
                });
            }

            // 2. Restore spent inputs from the undo record.
            for spent in &undo.txs[tx_index].spent {
                self.utxos
                    .insert(spent.outpoint.clone(), spent.entry.clone());
            }
        }
        self.already_generated = undo.previous_already_generated;

        if self.height == 0 {
            self.has_tip = false;
            self.height = 0;
            self.tip_hash = [0u8; 32];
        } else {
            self.height -= 1;
            self.tip_hash = pb.header.prev_block_hash;
        }

        Ok(ChainStateDisconnectSummary {
            disconnected_height: undo.block_height,
            block_hash: bh,
            new_height: self.height,
            new_tip_hash: self.tip_hash,
            has_tip: self.has_tip,
            already_generated: self.already_generated,
            utxo_count: self.utxos.len() as u64,
        })
    }
}

// ---------------------------------------------------------------------------
// JSON serialization (disk format)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BlockUndoDisk {
    block_height: u64,
    previous_already_generated: u64,
    txs: Vec<TxUndoDisk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxUndoDisk {
    spent: Vec<SpentUndoDisk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpentUndoDisk {
    txid: String,
    vout: u32,
    value: u64,
    covenant_type: u16,
    covenant_data: String,
    creation_height: u64,
    created_by_coinbase: bool,
}

pub fn marshal_block_undo(undo: &BlockUndo) -> Result<Vec<u8>, String> {
    let disk = block_undo_to_disk(undo);
    let mut raw = serde_json::to_vec_pretty(&disk).map_err(|e| format!("encode undo: {e}"))?;
    raw.push(b'\n');
    Ok(raw)
}

pub fn unmarshal_block_undo(raw: &[u8]) -> Result<BlockUndo, String> {
    let disk: BlockUndoDisk =
        serde_json::from_slice(raw).map_err(|e| format!("decode undo: {e}"))?;
    block_undo_from_disk(disk)
}

fn block_undo_to_disk(undo: &BlockUndo) -> BlockUndoDisk {
    let txs = undo
        .txs
        .iter()
        .map(|tx_undo| TxUndoDisk {
            spent: tx_undo
                .spent
                .iter()
                .map(|s| SpentUndoDisk {
                    txid: hex::encode(s.outpoint.txid),
                    vout: s.outpoint.vout,
                    value: s.entry.value,
                    covenant_type: s.entry.covenant_type,
                    covenant_data: hex::encode(&s.entry.covenant_data),
                    creation_height: s.entry.creation_height,
                    created_by_coinbase: s.entry.created_by_coinbase,
                })
                .collect(),
        })
        .collect();
    BlockUndoDisk {
        block_height: undo.block_height,
        previous_already_generated: undo.previous_already_generated,
        txs,
    }
}

fn block_undo_from_disk(disk: BlockUndoDisk) -> Result<BlockUndo, String> {
    let mut txs = Vec::with_capacity(disk.txs.len());
    for (tx_index, tx_undo) in disk.txs.into_iter().enumerate() {
        let mut spent = Vec::with_capacity(tx_undo.spent.len());
        for (spent_index, s) in tx_undo.spent.into_iter().enumerate() {
            let txid = parse_hex32(
                &format!("undo[{tx_index}].spent[{spent_index}].txid"),
                &s.txid,
            )?;
            let covenant_data = hex::decode(&s.covenant_data)
                .map_err(|e| format!("undo[{tx_index}].spent[{spent_index}].covenant_data: {e}"))?;
            spent.push(SpentUndo {
                outpoint: Outpoint { txid, vout: s.vout },
                entry: UtxoEntry {
                    value: s.value,
                    covenant_type: s.covenant_type,
                    covenant_data,
                    creation_height: s.creation_height,
                    created_by_coinbase: s.created_by_coinbase,
                },
            });
        }
        txs.push(TxUndo { spent });
    }
    Ok(BlockUndo {
        block_height: disk.block_height,
        previous_already_generated: disk.previous_already_generated,
        txs,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::devnet_genesis_chain_id;
    use crate::test_helpers::block_with_txs;

    use super::*;
    use rubin_consensus::constants::{COV_TYPE_P2PK, POW_LIMIT, TX_WIRE_VERSION};
    use rubin_consensus::{
        marshal_tx, p2pk_covenant_data_for_pubkey, parse_tx, sign_transaction, Mldsa87Keypair, Tx,
        TxInput, TxOutput,
    };

    fn sample_outpoint(seed: u8) -> Outpoint {
        Outpoint {
            txid: [seed; 32],
            vout: seed as u32,
        }
    }

    fn sample_entry(value: u64) -> UtxoEntry {
        UtxoEntry {
            value,
            covenant_type: COV_TYPE_P2PK,
            covenant_data: vec![0xAB; 33],
            creation_height: 0,
            created_by_coinbase: false,
        }
    }

    fn same_block_spend_fixture() -> (ChainState, Outpoint, Vec<u8>, u64) {
        let funding_key = Mldsa87Keypair::generate().expect("funding key");
        let funding_address = p2pk_covenant_data_for_pubkey(&funding_key.pubkey_bytes());
        let middle_key = Mldsa87Keypair::generate().expect("middle key");
        let middle_address = p2pk_covenant_data_for_pubkey(&middle_key.pubkey_bytes());
        let final_key = Mldsa87Keypair::generate().expect("final key");
        let final_address = p2pk_covenant_data_for_pubkey(&final_key.pubkey_bytes());

        let source_outpoint = Outpoint {
            txid: [0x11; 32],
            vout: 0,
        };
        let mut prev_state = ChainState {
            has_tip: true,
            height: 42,
            tip_hash: [0x22; 32],
            already_generated: 7,
            utxos: HashMap::new(),
        };
        prev_state.utxos.insert(
            source_outpoint.clone(),
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: funding_address,
                creation_height: 1,
                created_by_coinbase: false,
            },
        );

        let mut parent = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![TxInput {
                prev_txid: source_outpoint.txid,
                prev_vout: source_outpoint.vout,
                script_sig: Vec::new(),
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 90,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: middle_address.clone(),
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        };
        sign_transaction(
            &mut parent,
            &prev_state.utxos,
            devnet_genesis_chain_id(),
            &funding_key,
        )
        .expect("sign parent");
        let parent_bytes = marshal_tx(&parent).expect("marshal parent");
        let (_parent_tx, parent_txid, _parent_wtxid, parent_consumed) =
            parse_tx(&parent_bytes).expect("parse parent");
        assert_eq!(parent_consumed, parent_bytes.len());

        let mut middle_view = prev_state.utxos.clone();
        middle_view.remove(&source_outpoint);
        middle_view.insert(
            Outpoint {
                txid: parent_txid,
                vout: 0,
            },
            UtxoEntry {
                value: 90,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: middle_address,
                creation_height: prev_state.height + 1,
                created_by_coinbase: false,
            },
        );

        let mut child = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce: 2,
            inputs: vec![TxInput {
                prev_txid: parent_txid,
                prev_vout: 0,
                script_sig: Vec::new(),
                sequence: 0,
            }],
            outputs: vec![TxOutput {
                value: 80,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: final_address,
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        };
        sign_transaction(
            &mut child,
            &middle_view,
            devnet_genesis_chain_id(),
            &middle_key,
        )
        .expect("sign child");
        let child_bytes = marshal_tx(&child).expect("marshal child");

        let block_height = prev_state.height + 1;
        let block_bytes = block_with_txs(
            block_height,
            prev_state.already_generated,
            prev_state.tip_hash,
            1_777_000_123,
            &[parent_bytes, child_bytes],
        );

        (prev_state, source_outpoint, block_bytes, block_height)
    }

    fn duplicate_prev_state_spend_fixture() -> (ChainState, Vec<u8>, u64) {
        let funding_key = Mldsa87Keypair::generate().expect("funding key");
        let funding_address = p2pk_covenant_data_for_pubkey(&funding_key.pubkey_bytes());
        let recv_key = Mldsa87Keypair::generate().expect("recv key");
        let recv_address = p2pk_covenant_data_for_pubkey(&recv_key.pubkey_bytes());
        let source_outpoint = Outpoint {
            txid: [0x33; 32],
            vout: 0,
        };
        let mut prev_state = ChainState {
            has_tip: true,
            height: 7,
            tip_hash: [0x44; 32],
            already_generated: 3,
            utxos: HashMap::new(),
        };
        prev_state.utxos.insert(
            source_outpoint.clone(),
            UtxoEntry {
                value: 100,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: funding_address.clone(),
                creation_height: 1,
                created_by_coinbase: false,
            },
        );

        let mut tx = Tx {
            version: TX_WIRE_VERSION,
            tx_kind: 0x00,
            tx_nonce: 1,
            inputs: vec![
                TxInput {
                    prev_txid: source_outpoint.txid,
                    prev_vout: source_outpoint.vout,
                    script_sig: Vec::new(),
                    sequence: 0,
                },
                TxInput {
                    prev_txid: source_outpoint.txid,
                    prev_vout: source_outpoint.vout,
                    script_sig: Vec::new(),
                    sequence: 0,
                },
            ],
            outputs: vec![TxOutput {
                value: 90,
                covenant_type: COV_TYPE_P2PK,
                covenant_data: recv_address,
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        };
        sign_transaction(
            &mut tx,
            &prev_state.utxos,
            devnet_genesis_chain_id(),
            &funding_key,
        )
        .expect("sign tx");
        let tx_bytes = marshal_tx(&tx).expect("marshal tx");
        let block_height = prev_state.height + 1;
        let block_bytes = block_with_txs(
            block_height,
            prev_state.already_generated,
            prev_state.tip_hash,
            1_777_000_456,
            &[tx_bytes],
        );
        (prev_state, block_bytes, block_height)
    }

    #[test]
    fn test_undo_roundtrip_serialization() {
        let undo = BlockUndo {
            block_height: 42,
            previous_already_generated: 1000,
            txs: vec![
                TxUndo { spent: vec![] }, // coinbase — no spent
                TxUndo {
                    spent: vec![SpentUndo {
                        outpoint: sample_outpoint(0x01),
                        entry: sample_entry(500),
                    }],
                },
                TxUndo {
                    spent: vec![
                        SpentUndo {
                            outpoint: sample_outpoint(0x02),
                            entry: sample_entry(200),
                        },
                        SpentUndo {
                            outpoint: sample_outpoint(0x03),
                            entry: sample_entry(300),
                        },
                    ],
                },
            ],
        };

        let raw = marshal_block_undo(&undo).expect("marshal");
        let decoded = unmarshal_block_undo(&raw).expect("unmarshal");
        assert_eq!(undo, decoded);
    }

    #[test]
    fn test_undo_empty_block() {
        let undo = BlockUndo {
            block_height: 0,
            previous_already_generated: 0,
            txs: vec![TxUndo { spent: vec![] }],
        };
        let raw = marshal_block_undo(&undo).expect("marshal");
        let decoded = unmarshal_block_undo(&raw).expect("unmarshal");
        assert_eq!(undo, decoded);
    }

    #[test]
    fn test_is_spendable_output() {
        assert!(is_spendable_output(0x0001)); // P2PK
        assert!(is_spendable_output(0x0100)); // HTLC
        assert!(!is_spendable_output(COV_TYPE_ANCHOR));
        assert!(!is_spendable_output(COV_TYPE_DA_COMMIT));
    }

    #[test]
    fn test_disconnect_height_mismatch() {
        let mut cs = ChainState {
            has_tip: true,
            height: 5,
            tip_hash: [0xAA; 32],
            already_generated: 100,
            utxos: HashMap::new(),
        };
        let undo = BlockUndo {
            block_height: 3, // mismatched
            previous_already_generated: 50,
            txs: vec![],
        };
        let err = cs.disconnect_block(&[], &undo).expect_err("should fail");
        assert!(err.contains("disconnect height mismatch"));
    }

    #[test]
    fn test_disconnect_no_tip() {
        let mut cs = ChainState::new();
        let undo = BlockUndo {
            block_height: 0,
            previous_already_generated: 0,
            txs: vec![],
        };
        let err = cs.disconnect_block(&[], &undo).expect_err("should fail");
        assert!(err.contains("has no tip"));
    }

    #[test]
    fn test_unmarshal_invalid_json() {
        let err = unmarshal_block_undo(b"not json").expect_err("should fail");
        assert!(err.contains("decode undo"));
    }

    #[test]
    fn test_unmarshal_invalid_hex_txid() {
        let json = r#"{
            "block_height": 1,
            "previous_already_generated": 0,
            "txs": [{"spent": [{"txid": "ZZZZ", "vout": 0, "value": 0, "covenant_type": 1, "covenant_data": "", "creation_height": 0, "created_by_coinbase": false}]}]
        }"#;
        let err = unmarshal_block_undo(json.as_bytes()).expect_err("should fail");
        assert!(err.contains("txid"));
    }

    #[test]
    fn build_block_undo_ignores_same_block_spends() {
        let (prev_state, source_outpoint, block_bytes, block_height) = same_block_spend_fixture();

        let undo = build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");

        assert_eq!(undo.txs.len(), 3, "coinbase + parent + child");
        assert!(undo.txs[0].spent.is_empty(), "coinbase has no undo inputs");
        assert_eq!(
            undo.txs[1].spent.len(),
            1,
            "parent spends previous-state utxo"
        );
        assert_eq!(undo.txs[1].spent[0].outpoint, source_outpoint);
        assert!(
            undo.txs[2].spent.is_empty(),
            "child spends same-block output and must not require prev-state undo"
        );
    }

    #[test]
    fn build_block_undo_errors_on_missing_prev_state_utxo() {
        let (mut prev_state, source_outpoint, block_bytes, block_height) =
            same_block_spend_fixture();
        prev_state.utxos.remove(&source_outpoint);

        let err =
            build_block_undo(&prev_state, &block_bytes, block_height).expect_err("missing utxo");
        assert!(err.contains("undo missing utxo"));
    }

    #[test]
    fn build_block_undo_errors_on_duplicate_prev_state_spend() {
        let (prev_state, block_bytes, block_height) = duplicate_prev_state_spend_fixture();

        let err =
            build_block_undo(&prev_state, &block_bytes, block_height).expect_err("duplicate spend");
        assert!(err.contains("undo duplicate prev-state spend"));
    }

    #[test]
    fn disconnect_block_restores_prev_state_after_same_block_spend() {
        let (prev_state, _source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let undo = build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");

        let summary = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect("disconnect block");

        assert_eq!(connected_state, prev_state);
        assert_eq!(summary.new_height, prev_state.height);
        assert_eq!(summary.new_tip_hash, prev_state.tip_hash);
        assert_eq!(summary.utxo_count, prev_state.utxos.len() as u64);
    }

    #[test]
    fn disconnect_block_rejects_undo_tx_count_mismatch() {
        let (prev_state, _source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let mut undo =
            build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        undo.txs.pop();
        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("undo tx count mismatch");
        assert!(err.contains("undo tx count mismatch"));
    }

    #[test]
    fn disconnect_block_rejects_tip_mismatch() {
        let (prev_state, _source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let undo = build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");
        connected_state.tip_hash = [0xAA; 32];

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("tip mismatch");
        assert!(err.contains("disconnect block is not current tip"));
    }

    #[test]
    fn disconnect_block_rejects_restore_collision() {
        let (prev_state, source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let undo = build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");
        connected_state
            .utxos
            .insert(source_outpoint, sample_entry(77));

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("restore collision");
        assert!(err.contains("undo restore target already present"));
    }

    #[test]
    fn disconnect_block_rejects_duplicate_restore_entries_in_undo() {
        let (prev_state, source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let mut undo =
            build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let duplicate = undo.txs[1].spent[0].clone();
        undo.txs[1].spent.push(duplicate);

        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");
        connected_state.utxos.remove(&source_outpoint);

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("duplicate restore");
        assert!(err.contains("undo duplicate restore entry"));
    }

    #[test]
    fn disconnect_block_rejects_duplicate_created_restore_entries_in_undo() {
        let (prev_state, _source_outpoint, block_bytes, block_height) = same_block_spend_fixture();
        let mut undo =
            build_block_undo(&prev_state, &block_bytes, block_height).expect("build undo");
        let pb = parse_block_bytes(&block_bytes).expect("parse block");
        let duplicate = SpentUndo {
            outpoint: Outpoint {
                txid: pb.txids[1],
                vout: 0,
            },
            entry: sample_entry(55),
        };
        undo.txs[2].spent.push(duplicate.clone());
        undo.txs[2].spent.push(duplicate);

        let mut connected_state = prev_state.clone();
        let prev_timestamps = [1_777_000_000u64; 11];
        connected_state
            .connect_block(
                &block_bytes,
                Some(POW_LIMIT),
                Some(&prev_timestamps),
                devnet_genesis_chain_id(),
            )
            .expect("connect block");

        let err = connected_state
            .disconnect_block(&block_bytes, &undo)
            .expect_err("duplicate created restore");
        assert!(err.contains("undo duplicate restore entry"));
    }
}

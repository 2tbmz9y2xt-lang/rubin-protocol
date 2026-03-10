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

    let mut work = prev_state.utxos.clone();
    let mut tx_undos = Vec::with_capacity(pb.txs.len());

    for (i, tx) in pb.txs.iter().enumerate() {
        let mut spent = Vec::new();
        // Coinbase (index 0) has no real inputs to consume.
        if i > 0 {
            for input in &tx.inputs {
                let op = Outpoint {
                    txid: input.prev_txid,
                    vout: input.prev_vout,
                };
                let entry = work.remove(&op).ok_or_else(|| {
                    format!("undo missing utxo for {}:{}", hex::encode(op.txid), op.vout)
                })?;
                spent.push(SpentUndo {
                    outpoint: op,
                    entry,
                });
            }
        }
        // Add outputs to the working set so subsequent txs can spend them.
        for (output_index, out) in tx.outputs.iter().enumerate() {
            if !is_spendable_output(out.covenant_type) {
                continue;
            }
            work.insert(
                Outpoint {
                    txid: pb.txids[i],
                    vout: output_index as u32,
                },
                UtxoEntry {
                    value: out.value,
                    covenant_type: out.covenant_type,
                    covenant_data: out.covenant_data.clone(),
                    creation_height: block_height,
                    created_by_coinbase: i == 0,
                },
            );
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

        let mut work = self.utxos.clone();

        // Process transactions in **reverse** order.
        for tx_index in (0..pb.txs.len()).rev() {
            let tx = &pb.txs[tx_index];
            let txid = pb.txids[tx_index];

            // 1. Remove outputs created by this tx.
            for (output_index, out) in tx.outputs.iter().enumerate() {
                if !is_spendable_output(out.covenant_type) {
                    continue;
                }
                work.remove(&Outpoint {
                    txid,
                    vout: output_index as u32,
                });
            }

            // 2. Restore spent inputs from the undo record.
            for spent in &undo.txs[tx_index].spent {
                if work.contains_key(&spent.outpoint) {
                    return Err(format!(
                        "undo restore collision for {}:{}",
                        hex::encode(spent.outpoint.txid),
                        spent.outpoint.vout
                    ));
                }
                work.insert(spent.outpoint.clone(), spent.entry.clone());
            }
        }

        self.utxos = work;
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

    use super::*;

    fn sample_outpoint(seed: u8) -> Outpoint {
        Outpoint {
            txid: [seed; 32],
            vout: seed as u32,
        }
    }

    fn sample_entry(value: u64) -> UtxoEntry {
        UtxoEntry {
            value,
            covenant_type: 0x0001, // COV_TYPE_P2PK
            covenant_data: vec![0xAB; 33],
            creation_height: 0,
            created_by_coinbase: false,
        }
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
}

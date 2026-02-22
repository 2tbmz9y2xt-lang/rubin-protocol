use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;

pub fn merkle_root_txids(txids: &[[u8; 32]]) -> Result<[u8; 32], TxError> {
    merkle_root_tagged(txids, 0x00, 0x01)
}

pub fn witness_merkle_root_wtxids(wtxids: &[[u8; 32]]) -> Result<[u8; 32], TxError> {
    if wtxids.is_empty() {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "merkle: empty wtxid list",
        ));
    }
    let mut ids = wtxids.to_vec();
    // Break self-reference: coinbase witness commitment tree uses a zero id for index 0.
    ids[0] = [0u8; 32];
    merkle_root_tagged(&ids, 0x02, 0x03)
}

pub fn witness_commitment_hash(witness_root: [u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity("RUBIN-WITNESS/".len() + 32);
    preimage.extend_from_slice(b"RUBIN-WITNESS/");
    preimage.extend_from_slice(&witness_root);
    sha3_256(&preimage)
}

fn merkle_root_tagged(ids: &[[u8; 32]], leaf_tag: u8, node_tag: u8) -> Result<[u8; 32], TxError> {
    if ids.is_empty() {
        return Err(TxError::new(ErrorCode::TxErrParse, "merkle: empty id list"));
    }

    let mut level: Vec<[u8; 32]> = Vec::with_capacity(ids.len());
    let mut leaf_preimage = [0u8; 1 + 32];
    leaf_preimage[0] = leaf_tag;
    for id in ids {
        leaf_preimage[1..].copy_from_slice(id);
        level.push(sha3_256(&leaf_preimage));
    }

    let mut node_preimage = [0u8; 1 + 32 + 32];
    node_preimage[0] = node_tag;
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0usize;
        while i < level.len() {
            if i == level.len() - 1 {
                // Odd promotion rule: carry forward unchanged.
                next.push(level[i]);
                i += 1;
                continue;
            }
            node_preimage[1..33].copy_from_slice(&level[i]);
            node_preimage[33..].copy_from_slice(&level[i + 1]);
            next.push(sha3_256(&node_preimage));
            i += 2;
        }
        level = next;
    }

    Ok(level[0])
}

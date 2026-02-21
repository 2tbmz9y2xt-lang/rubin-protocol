use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;

pub fn merkle_root_txids(txids: &[[u8; 32]]) -> Result<[u8; 32], TxError> {
    if txids.is_empty() {
        return Err(TxError::new(ErrorCode::TxErrParse, "merkle: empty tx list"));
    }

    let mut level: Vec<[u8; 32]> = Vec::with_capacity(txids.len());
    let mut leaf_preimage = [0u8; 1 + 32];
    leaf_preimage[0] = 0x00;
    for txid in txids {
        leaf_preimage[1..].copy_from_slice(txid);
        level.push(sha3_256(&leaf_preimage));
    }

    let mut node_preimage = [0u8; 1 + 32 + 32];
    node_preimage[0] = 0x01;
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

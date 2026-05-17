use crate::constants::{COV_TYPE_DA_COMMIT, MAX_DA_BATCHES_PER_BLOCK, MAX_DA_CHUNK_COUNT};
use crate::error::{ErrorCode, TxError};
use crate::hash::sha3_256;
use crate::tx::Tx;
use std::collections::HashMap;

#[derive(Clone, Debug)]
struct DaCommitSet {
    tx: Tx,
    chunk_count: u16,
}

type DaCommitMap = HashMap<[u8; 32], DaCommitSet>;
type DaChunkMap = HashMap<[u8; 32], HashMap<u16, Tx>>;

pub(super) fn validate_da_set_integrity(txs: &[Tx]) -> Result<(), TxError> {
    let (commits, chunks) = collect_da_commits_and_chunks(txs)?;
    validate_da_commit_completeness(&commits, &chunks)?;
    validate_da_payload_commitments(&commits, &chunks)
}

fn collect_da_commits_and_chunks(txs: &[Tx]) -> Result<(DaCommitMap, DaChunkMap), TxError> {
    let mut commits = HashMap::new();
    let mut chunks = HashMap::new();
    for tx in txs {
        match tx.tx_kind {
            0x01 => add_da_commit(&mut commits, tx)?,
            0x02 => add_da_chunk(&mut chunks, tx)?,
            _ => {}
        }
    }
    Ok((commits, chunks))
}

fn add_da_commit(commits: &mut DaCommitMap, tx: &Tx) -> Result<(), TxError> {
    let Some(core) = tx.da_commit_core.as_ref() else {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "missing da_commit_core for tx_kind=0x01",
        ));
    };
    if commits
        .insert(
            core.da_id,
            DaCommitSet {
                tx: tx.clone(),
                chunk_count: core.chunk_count,
            },
        )
        .is_some()
    {
        return Err(TxError::new(
            ErrorCode::BlockErrDaSetInvalid,
            "duplicate DA commit for da_id",
        ));
    }
    Ok(())
}

fn add_da_chunk(chunks: &mut DaChunkMap, tx: &Tx) -> Result<(), TxError> {
    let Some(core) = tx.da_chunk_core.as_ref() else {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "missing da_chunk_core for tx_kind=0x02",
        ));
    };
    if sha3_256(&tx.da_payload) != core.chunk_hash {
        return Err(TxError::new(
            ErrorCode::BlockErrDaChunkHashInvalid,
            "chunk_hash mismatch",
        ));
    }
    let set = chunks.entry(core.da_id).or_default();
    if set.insert(core.chunk_index, tx.clone()).is_some() {
        return Err(TxError::new(
            ErrorCode::BlockErrDaSetInvalid,
            "duplicate DA chunk index",
        ));
    }
    Ok(())
}

fn validate_da_commit_completeness(
    commits: &DaCommitMap,
    chunks: &DaChunkMap,
) -> Result<(), TxError> {
    validate_da_batch_count(commits)?;
    validate_da_chunk_orphans(commits, chunks)?;
    validate_da_chunk_integrity(commits, chunks)
}

fn validate_da_batch_count(commits: &DaCommitMap) -> Result<(), TxError> {
    if commits.len() > MAX_DA_BATCHES_PER_BLOCK as usize {
        return Err(TxError::new(
            ErrorCode::BlockErrDaBatchExceeded,
            "too many DA commits in block",
        ));
    }
    Ok(())
}

fn validate_da_chunk_orphans(commits: &DaCommitMap, chunks: &DaChunkMap) -> Result<(), TxError> {
    for da_id in sorted_da_ids(chunks) {
        if !commits.contains_key(&da_id) {
            return Err(TxError::new(
                ErrorCode::BlockErrDaSetInvalid,
                "DA chunks without DA commit",
            ));
        }
    }
    Ok(())
}

fn validate_da_chunk_integrity(commits: &DaCommitMap, chunks: &DaChunkMap) -> Result<(), TxError> {
    for da_id in sorted_da_ids(commits) {
        let commit = da_commit_for_id(commits, &da_id)?;
        validate_da_chunk_count(commit.chunk_count)?;
        let set = da_chunk_set_for_id(chunks, &da_id)?;
        if set.len() != commit.chunk_count as usize {
            return Err(TxError::new(
                ErrorCode::BlockErrDaIncomplete,
                "DA chunk count mismatch",
            ));
        }
        validate_da_chunk_indexes(set, commit.chunk_count)?;
    }
    Ok(())
}

fn validate_da_chunk_count(chunk_count: u16) -> Result<(), TxError> {
    if chunk_count == 0 || u64::from(chunk_count) > MAX_DA_CHUNK_COUNT {
        return Err(TxError::new(
            ErrorCode::TxErrParse,
            "chunk_count out of range for tx_kind=0x01",
        ));
    }
    Ok(())
}

fn validate_da_chunk_indexes(set: &HashMap<u16, Tx>, chunk_count: u16) -> Result<(), TxError> {
    for i in 0..chunk_count {
        let _ = da_chunk_tx_for_index(set, i)?;
    }
    Ok(())
}

fn validate_da_payload_commitments(
    commits: &DaCommitMap,
    chunks: &DaChunkMap,
) -> Result<(), TxError> {
    for da_id in sorted_da_ids(commits) {
        let commit = da_commit_for_id(commits, &da_id)?;
        let set = da_chunk_set_for_id(chunks, &da_id)?;
        let payload_commitment = da_payload_commitment(commit, set)?;
        let got_commitment = da_commit_output_commitment(&commit.tx)?;
        if payload_commitment != got_commitment {
            return Err(TxError::new(
                ErrorCode::BlockErrDaPayloadCommitInvalid,
                "payload commitment mismatch",
            ));
        }
    }
    Ok(())
}

fn da_payload_commitment(
    commit: &DaCommitSet,
    set: &HashMap<u16, Tx>,
) -> Result<[u8; 32], TxError> {
    let mut concat = Vec::<u8>::new();
    for i in 0..commit.chunk_count {
        let tx = da_chunk_tx_for_index(set, i)?;
        concat.extend_from_slice(&tx.da_payload);
    }
    Ok(sha3_256(&concat))
}

fn da_commit_output_commitment(tx: &Tx) -> Result<[u8; 32], TxError> {
    let mut da_commit_outputs: u32 = 0;
    let mut got_commitment = [0u8; 32];
    for o in &tx.outputs {
        if o.covenant_type != COV_TYPE_DA_COMMIT {
            continue;
        }
        da_commit_outputs += 1;
        if o.covenant_data.len() != 32 {
            return Err(TxError::new(
                ErrorCode::BlockErrDaPayloadCommitInvalid,
                "DA commitment output has invalid length",
            ));
        }
        got_commitment.copy_from_slice(&o.covenant_data);
    }
    if da_commit_outputs != 1 {
        return Err(TxError::new(
            ErrorCode::BlockErrDaPayloadCommitInvalid,
            "DA commitment output missing or duplicated",
        ));
    }
    Ok(got_commitment)
}

fn da_commit_for_id<'a>(
    commits: &'a DaCommitMap,
    da_id: &[u8; 32],
) -> Result<&'a DaCommitSet, TxError> {
    commits.get(da_id).ok_or_else(|| {
        TxError::new(
            ErrorCode::BlockErrDaSetInvalid,
            "missing DA commit for da_id",
        )
    })
}

fn da_chunk_set_for_id<'a>(
    chunks: &'a DaChunkMap,
    da_id: &[u8; 32],
) -> Result<&'a HashMap<u16, Tx>, TxError> {
    chunks
        .get(da_id)
        .ok_or_else(|| TxError::new(ErrorCode::BlockErrDaIncomplete, "DA commit without chunks"))
}

fn da_chunk_tx_for_index(set: &HashMap<u16, Tx>, index: u16) -> Result<&Tx, TxError> {
    set.get(&index)
        .ok_or_else(|| TxError::new(ErrorCode::BlockErrDaIncomplete, "missing DA chunk index"))
}

fn sorted_da_ids<T>(m: &HashMap<[u8; 32], T>) -> Vec<[u8; 32]> {
    let mut ids: Vec<[u8; 32]> = m.keys().copied().collect();
    ids.sort_unstable();
    ids
}

#[cfg(test)]
mod tests {
    use super::{
        da_chunk_set_for_id, da_chunk_tx_for_index, da_commit_for_id,
        validate_da_commit_completeness, validate_da_payload_commitments, DaCommitSet,
    };
    use crate::constants::{COV_TYPE_DA_COMMIT, MAX_DA_BATCHES_PER_BLOCK};
    use crate::error::ErrorCode;
    use crate::tx::{Tx, TxOutput};
    use std::collections::HashMap;

    fn dummy_da_commit_tx(payload_commitment: [u8; 32]) -> Tx {
        dummy_da_commit_tx_with_covenant_data(payload_commitment.to_vec())
    }

    fn dummy_da_commit_tx_with_covenant_data(covenant_data: Vec<u8>) -> Tx {
        Tx {
            version: 1,
            tx_kind: 0x01,
            tx_nonce: 0,
            inputs: Vec::new(),
            outputs: vec![TxOutput {
                value: 0,
                covenant_type: COV_TYPE_DA_COMMIT,
                covenant_data,
            }],
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: Vec::new(),
        }
    }

    fn dummy_da_chunk_tx(payload: &[u8]) -> Tx {
        Tx {
            version: 1,
            tx_kind: 0x02,
            tx_nonce: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
            da_commit_core: None,
            da_chunk_core: None,
            witness: Vec::new(),
            da_payload: payload.to_vec(),
        }
    }

    #[test]
    fn da_commit_for_id_missing_returns_block_err_da_set_invalid() {
        let commits: HashMap<[u8; 32], DaCommitSet> = HashMap::new();
        let err = da_commit_for_id(&commits, &[0x11; 32]).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaSetInvalid);
    }

    #[test]
    fn da_chunk_set_for_id_missing_returns_block_err_da_incomplete() {
        let chunks: HashMap<[u8; 32], HashMap<u16, Tx>> = HashMap::new();
        let err = da_chunk_set_for_id(&chunks, &[0x22; 32]).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaIncomplete);
    }

    #[test]
    fn da_chunk_tx_for_index_missing_returns_block_err_da_incomplete() {
        let set: HashMap<u16, Tx> = HashMap::new();
        let err = da_chunk_tx_for_index(&set, 0).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaIncomplete);
    }

    #[test]
    fn validate_da_commit_completeness_rejects_missing_chunk_index_without_panic() {
        let da_id = [0x33; 32];
        let mut commits = HashMap::new();
        commits.insert(
            da_id,
            DaCommitSet {
                tx: dummy_da_commit_tx([0x44; 32]),
                chunk_count: 2,
            },
        );

        let mut set = HashMap::new();
        set.insert(0, dummy_da_chunk_tx(b"chunk-0"));
        let mut chunks = HashMap::new();
        chunks.insert(da_id, set);

        let err = validate_da_commit_completeness(&commits, &chunks).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaIncomplete);
    }

    #[test]
    fn validate_da_payload_commitments_rejects_non_32_covenant_data_as_invalid_length() {
        let da_id = [0x55; 32];
        let payload = b"payload-short-covenant".to_vec();

        let mut commits = HashMap::new();
        let bad_covenant: Vec<u8> = (0..31).collect();
        commits.insert(
            da_id,
            DaCommitSet {
                tx: dummy_da_commit_tx_with_covenant_data(bad_covenant),
                chunk_count: 1,
            },
        );

        let mut set = HashMap::new();
        set.insert(0, dummy_da_chunk_tx(&payload));
        let mut chunks = HashMap::new();
        chunks.insert(da_id, set);

        let err = validate_da_payload_commitments(&commits, &chunks).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaPayloadCommitInvalid);
        assert_eq!(err.msg, "DA commitment output has invalid length");
    }

    #[test]
    fn validate_da_commit_completeness_batch_exceeded_fires_before_set_invalid() {
        let mut commits = HashMap::new();
        let limit: u32 = MAX_DA_BATCHES_PER_BLOCK as u32;
        for i in 0..=limit {
            let mut da_id = [0u8; 32];
            da_id[0..4].copy_from_slice(&i.to_le_bytes());
            commits.insert(
                da_id,
                DaCommitSet {
                    tx: dummy_da_commit_tx([0xAA; 32]),
                    chunk_count: 1,
                },
            );
        }

        let mut orphan_set = HashMap::new();
        orphan_set.insert(0, dummy_da_chunk_tx(b"orphan"));
        let mut chunks = HashMap::new();
        chunks.insert([0xFF; 32], orphan_set);

        assert_eq!(commits.len(), MAX_DA_BATCHES_PER_BLOCK as usize + 1);

        let err = validate_da_commit_completeness(&commits, &chunks).unwrap_err();
        assert_eq!(err.code, ErrorCode::BlockErrDaBatchExceeded);
        assert_eq!(err.msg, "too many DA commits in block");
    }
}
